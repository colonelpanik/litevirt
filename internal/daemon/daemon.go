package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/billing"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/restapi"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/tenancy"
	"github.com/litevirt/litevirt/internal/ui"
	"github.com/litevirt/litevirt/internal/watchdog"
)

// grpcMaxMsgSize raises the gRPC max message size above the 4 MiB default for
// the internal cluster RPCs (full-state dump fallback, replication batches).
// StreamStateDump chunks well below this; it's a backstop for the non-chunked
// paths that share the connection.
const grpcMaxMsgSize = 64 << 20 // 64 MiB

// Daemon is the main litevirtd process.
type Daemon struct {
	cfg     *Config
	db      *corrosion.Client
	virt    *libvirt.Client
	images  *image.Store
	grpcSrv *grpc.Server
	svc     *grpcapi.Server // gRPC service handler; held so background loops can refresh it
	checker *health.Checker
	metrics *metrics.Server

	// authEngine is wired into the gRPC server below; kept on the daemon
	// struct so the realm-sync / binding-reload loop can refresh it later.
	authEngine *auth.Engine

	// realmRegistry holds Local + every configured OIDC/LDAP realm.
	// Login dispatches by name through this registry.
	realmRegistry *auth.Registry

	// fwReconciler polls security_groups + sg_rules and atomically
	// replaces this host's nftables ruleset. Stop() is called on
	// shutdown so the goroutine exits cleanly.
	fwReconciler *firewall.Reconciler

	// snapScheduler is the leader-gated minute-tick that fires backup
	// schedules. Built before the gRPC server (so daemon Run can wire
	// the Runner once svc exists) and Stop()-ed on shutdown.
	snapScheduler *scheduler.SnapshotScheduler
}

// New creates a new daemon instance.
func New(cfg *Config) (*Daemon, error) {
	// Create HLC clock for this node
	clock := hlc.NewClock(cfg.HostName)

	// Open embedded state store and join gossip cluster
	db, err := corrosion.NewClient(corrosion.Config{
		HostName:  cfg.HostName,
		DataDir:   cfg.DataDir,
		BindPort:  cfg.GossipPort,
		JoinPeers: cfg.JoinPeers,
	}, clock)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}

	// Connect to libvirt
	virt, err := libvirt.NewClient()
	if err != nil {
		return nil, fmt.Errorf("libvirt: %w", err)
	}

	// Image store
	store := image.NewStore(cfg.DataDir)
	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("image store: %w", err)
	}

	return &Daemon{
		cfg:    cfg,
		db:     db,
		virt:   virt,
		images: store,
	}, nil
}

// Run starts all daemon services and blocks until context is cancelled.
// markRestarting flags this host 'upgrading' during a graceful shutdown so
// peers skip fence candidacy for the restart window, then waits briefly so the
// state replicates before the gRPC server stops serving. Best-effort and
// bounded — it must never block shutdown for long. The caller's ctx is already
// cancelled (SIGTERM), so this uses a fresh, short-lived context.
func (d *Daemon) markRestarting() {
	mctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := corrosion.UpdateHostState(mctx, d.db, d.cfg.HostName, "upgrading"); err != nil {
		slog.Warn("shutdown: failed to mark host upgrading", "error", err)
		return
	}
	// Peers fence only after several accumulated health failures (~10s+), so a
	// short grace is enough for the 'upgrading' state to reach them first.
	time.Sleep(2 * time.Second)
}

func (d *Daemon) Run(ctx context.Context) error {
	// Pre-flight: refuse to start under a systemd unit that would kill
	// child QEMU processes on stop. See preflight.go for the rationale.
	if err := preflightUnitCheck(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	// Pre-flight: if watchdog self-fencing is configured, refuse to start with a
	// missing/unusable device so we don't discover it only at fence time.
	if err := preflightWatchdog(d.cfg.WatchdogDev); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}

	// Initialize corrosion schema
	if err := corrosion.InitSchema(ctx, d.db); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	// Migrate legacy unscoped network names to stack-scoped names.
	if err := corrosion.MigrateLegacyNetworkNames(ctx, d.db); err != nil {
		slog.Warn("failed to migrate legacy network names", "error", err)
	}

	// Set up libvirt TLS symlinks so qemu+tls:// migration works
	// using our existing PKI certs. Best-effort — log warning if it fails.
	if err := pki.SetupLibvirtTLS(d.cfg.PKIDir); err != nil {
		slog.Warn("failed to set up libvirt TLS certs", "error", err)
	}

	// Seed admin user on first start (if no users exist).
	if err := d.seedAdminUser(ctx); err != nil {
		slog.Warn("failed to seed admin user", "error", err)
	}

	// seed the built-in RBAC roles (Admin, Operator, Viewer,
	// Auditor, BackupOperator, NetworkAdmin, VMOperator, NoAccess) and
	// initialize the auth engine. The engine reloads on every daemon
	// start; mid-run it picks up new bindings via explicit Reload calls
	//.
	if err := auth.SeedBuiltinRoles(ctx, d.db); err != nil {
		slog.Warn("failed to seed built-in roles", "error", err)
	}
	d.authEngine = auth.NewEngine(d.db)
	if err := d.authEngine.Reload(ctx); err != nil {
		slog.Warn("failed to load role bindings", "error", err)
	}

	// build the realm registry from auth.realms YAML. The
	// "local" realm is always installed by BuildRegistry; OIDC/LDAP
	// realms come from config. A realm that fails to construct (e.g.
	// OIDC issuer unreachable at startup) downgrades to a warning so
	// the daemon can still serve local-only Logins; the operator gets
	// to see the error and fix the config without the daemon refusing
	// to start.
	registry, err := auth.BuildRegistry(ctx, d.db, d.cfg.Auth.Realms)
	if err != nil {
		slog.Warn("auth.realms config failed; falling back to local-only", "error", err)
		registry = auth.NewRegistry()
		registry.Register(auth.NewLocalRealm(d.db))
	}
	d.realmRegistry = registry
	if names := registry.Names(); len(names) > 0 {
		slog.Info("auth realms ready", "realms", names)
	}

	// Register this host in corrosion
	if err := d.registerHost(ctx); err != nil {
		slog.Warn("failed to register host", "error", err)
	}
	// Always mark ourselves active on startup — InsertHost is a no-op if the
	// record already exists, so a host that was marked offline (e.g. during an
	// upgrade) would stay offline without this explicit state transition.
	if err := corrosion.UpdateHostState(ctx, d.db, d.cfg.HostName, "active"); err != nil {
		slog.Warn("failed to set host active on startup", "error", err)
	}
	// Always update version on startup (InsertHost may no-op if host already exists).
	if d.cfg.Version != "" {
		_ = corrosion.UpdateHostVersion(ctx, d.db, d.cfg.HostName, d.cfg.Version)
	}
	// Record version on the corrosion client so it goes into Crescent
	// peer handshakes (used by skew detection).
	d.db.SetLocalVersion(d.cfg.Version)
	// Always refresh host resources (CPU, memory, disk) on startup so existing
	// hosts pick up hardware changes and disk_total is always populated.
	// disk_total is the sum of all configured storage pool capacities.
	if cpus, memMiB, err := d.virt.NodeInfo(); err == nil {
		diskGiB := d.sumPoolDiskTotalGiB()
		_ = corrosion.UpdateHostResources(ctx, d.db, d.cfg.HostName, cpus, memMiB, diskGiB)
	}

	// Register storage pools in the cluster DB and start periodic refresh.
	d.registerStoragePools(ctx)
	d.refreshDBPoolCapacity(ctx)
	go d.refreshStoragePools(ctx)

	// Start WAL-based replicator with Crescent relay protocol.
	repl := corrosion.NewReplicator(d.db, d.cfg.PKIDir, corrosion.RelayConfig{
		BaseRelays:      3,
		NodesPerRelay:   50,
		FallbackTimeout: 15 * time.Second,
	})
	repl.Start(ctx)

	// Start anti-entropy (periodic digest comparison + full sync as safety net).
	// Interval is operator-configurable (anti_entropy_interval_sec); 0 → 60s
	// default inside NewAntiEntropy. (P2-2)
	ae := corrosion.NewAntiEntropy(d.db, d.cfg.PKIDir, time.Duration(d.cfg.AntiEntropyIntervalSec)*time.Second)
	go ae.Start(ctx)

	// Start metrics server
	d.metrics = metrics.NewServer(d.cfg.MetricsPort, d.cfg.MetricsBind, d.db, d.virt, d.cfg.HostName)
	go d.metrics.Start()

	// Start host health checker
	d.checker = health.NewChecker(d.cfg.HostName, d.cfg.PKIDir, d.db)
	go d.checker.Start(ctx)

	// Create the failover coordinator; started after the gRPC server is built
	// so its replica-promoter (auto_promote recovery) can be wired first.
	fc := failover.NewCoordinator(d.cfg.HostName, d.db)

	// Start rebalance coordinator. Leader-gated; safe to start on
	// every host. Defaults to dry-run on every VM unless compose says otherwise.
	rc := scheduler.NewRebalancer(d.cfg.HostName, d.db)
	go rc.Start(ctx)

	// Start snapshot scheduler. Leader-gated like the
	// rebalancer; the runner is wired below once the gRPC Server is
	// constructed (it reuses lockVM + pickDisk).
	d.snapScheduler = scheduler.NewSnapshotScheduler(d.db, d.cfg.HostName, nil /* runner set after server build */)

	// Start VM health checker (event bus wired after gRPC server is created below).
	vmChecker := health.NewVMChecker(d.cfg.HostName, d.db, d.virt)
	go vmChecker.Start(ctx)

	// Start libvirt reconnect loop — auto-reconnects if libvirtd restarts (#42).
	go d.virt.StartReconnectLoop(ctx)

	// Register domain event callback for immediate VM death detection (#44).
	d.virt.RegisterDomainEventCallback(func(domName string, event libvirt.DomainEventType, detail int) {
		switch event {
		case libvirt.DomainEventCrashed, libvirt.DomainEventStopped:
			vm, err := corrosion.GetVM(ctx, d.db, domName)
			if err != nil || vm == nil || vm.HostName != d.cfg.HostName {
				return
			}
			if vm.StateDetail == "operator-stop" {
				return // don't act on intentional stops
			}
			slog.Warn("domain event: VM stopped/crashed", "vm", domName, "event", event, "detail", detail)
			corrosion.UpdateVMState(ctx, d.db, domName, "error",
				fmt.Sprintf("domain event: stopped (detail=%d). Check host dmesg for OOM.", detail))
		}
	})

	// Start VM reconciler (picks up "pending" VMs from failover and starts them)
	reconciler := health.NewReconciler(d.cfg.HostName, d.cfg.DataDir, d.db, d.virt)
	go reconciler.Start(ctx)
	// Autostart onboot VMs once, in startup_order (#10). Runs only for VMs not
	// already running in libvirt, so a daemon restart (qemu kept alive by
	// KillMode=process) is a no-op while a host reboot brings them up in order.
	go reconciler.StartOnbootVMs(ctx)

	// Daily prune of this host's vm_events rows so the operational event store
	// stays bounded (see config vm_event_*).
	go d.runVMEventPrune(ctx)

	// Start embedded DNS server
	dnsSrv := dns.NewServer(d.cfg.DNSDomain, d.cfg.DNSPort, d.db)
	go dnsSrv.Start(ctx)

	// Start hardware watchdog heartbeat (optional)
	go watchdog.Heartbeat(ctx, d.cfg.WatchdogDev, 0)

	// PCI device startup scan
	d.runPCIScan(ctx)

	// Start periodic PCI rescan timer (if configured).
	if interval := d.parsePCIRescanInterval(); interval > 0 {
		go d.runPeriodicPCIScan(ctx, interval)
	}

	// Ensure libvirt storage pools exist.
	d.ensureStoragePools()

	// Re-provision networks (DHCP, NAT, VXLAN) for active stacks.
	// dnsmasq is a child process that dies when the daemon restarts;
	// this brings it back for any network with a subnet.
	d.reconcileNetworks(ctx)

	// Start gRPC server with mTLS
	tlsCfg, err := pki.ServerTLSConfig(d.cfg.PKIDir)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	svc := grpcapi.NewServer(d.cfg.HostName, d.cfg.DataDir, d.cfg.PKIDir, d.db, d.virt, d.images)
	d.svc = svc
	svc.SetVersion(d.cfg.Version)
	svc.SetDNSDomain(d.cfg.DNSDomain)
	svc.SetSessionTimeouts(parseDurationOr(d.cfg.Auth.SessionIdleTimeout, 0), parseDurationOr(d.cfg.Auth.SessionHardExpiry, 0))
	svc.SetMigrationMetrics(metrics.NewMigrationMetrics())
	svc.SetStoragePoolsByName(d.storagePoolRefs())
	svc.SetReplicator(repl)
	svc.SetAuthEngine(d.authEngine)
	svc.SetRealmRegistry(d.realmRegistry)
	vmChecker.SetEventBus(svc.EventBus())
	vmChecker.SetMigrateFunc(svc.MigrateVMForHealthCheck)

	// Wire reconciler callbacks now that gRPC server exists.
	reconciler.SetOnVMStarted(svc.RefreshLBForStack)
	reconciler.SetAutoPullImage(svc.AutoPullImage)
	reconciler.SetBackupInProgress(svc.BackupInProgress)

	// Start stack deletion reconciler — retries cleanup for stacks stuck in "deleting" state.
	stackReconciler := health.NewStackReconciler(d.cfg.HostName, d.db)
	stackReconciler.SetCleaner(svc)
	go stackReconciler.Start(ctx)

	// Re-apply LB configs (haproxy + keepalived) that should run on this host.
	// These are child processes that die when the daemon restarts.
	svc.ReconcileLBs(ctx)

	// Start periodic IP scanner — discovers VM IPs via ARP/DHCP and broadcasts FDB entries.
	ipScanner := grpcapi.NewIPScanner(svc)
	go ipScanner.Start(ctx)

	// distributed firewall: poll cluster security_groups +
	// sg_rules every 30s and atomically replace this host's nftables
	// table. The applier short-circuits when the rendered ruleset
	// hasn't changed, so idle clusters cost ~one corrosion query/tick.
	fwApplier := firewall.NewApplier(firewall.NftBinary{})
	fwLoader := firewall.CorrosionPlanLoader(d.db, d.cfg.HostName, firewall.Plan{})
	d.fwReconciler = firewall.NewReconciler(fwLoader, fwApplier, 30*time.Second)
	svc.SetFirewallReconciler(d.fwReconciler)
	d.fwReconciler.Start(ctx)

	// tenancy + billing engine. The webhook URL is empty
	// for most clusters; the emitter resolves to a no-op in that
	// case so production-without-billing is the zero-config default.
	tenancyEngine := tenancy.NewEngine(d.db, billing.NewWebhookEmitter(d.cfg.BillingWebhookURL))
	svc.SetTenancyEngine(tenancyEngine)

	// Seed the default notification webhook from config (#5), if any.
	d.seedNotificationDefaults(ctx)

	// wire the LXC runtime so the Containers RPCs work.
	// We always wire it — when lxc-* binaries aren't installed, the
	// individual RPCs surface the error from the binary lookup, which
	// is more useful than a blanket "container runtime not wired".
	lxcRunner := lxc.NewLxcRunner()
	svc.SetContainerRuntime(grpcapi.NewLXCRuntimeAdapter(lxcRunner))

	// Container reconciler + restart engine: every cycle, sync each locally-owned
	// container's cluster row to the LXC runtime's reality and auto-restart one
	// that stopped unexpectedly per its restart policy. Shares the runtime wired
	// above; operator-stopped containers are left alone (state_detail).
	ctChecker := health.NewContainerChecker(d.cfg.HostName, d.db, lxcRunner)
	ctChecker.SetEventBus(svc.EventBus())
	go ctChecker.Start(ctx)

	// wire the libvirt blockdev-mirror driver so MoveVolume
	// supports running VMs without stopping them.
	svc.SetLiveMover(grpcapi.NewLibvirtLiveMover(d.virt))

	// (content rewrite): wire the guest-content backup engine.
	// Reads the guest disk over qemu's NBD pull-backup export (not the
	// qcow2 container), so full + incremental + the dirty bitmap all share
	// the guest-virtual address space — the correct, consistent model.
	// nil-safe: if BeginBackup fails, BackupSnapshot falls back to a full
	// container backup.
	svc.SetBackupSource(grpcapi.NewLibvirtBackupSource(d.virt))

	// wire the WebAuthn second-factor engine. Empty
	// rp_id disables — the gRPC handlers then return Unimplemented
	// instead of a confusing "missing config" surface.
	if d.cfg.WebAuthn.RPID != "" {
		wa, err := auth.NewWebAuthnService(d.db, auth.WebAuthnConfig{
			RPDisplayName: d.cfg.WebAuthn.RPDisplayName,
			RPID:          d.cfg.WebAuthn.RPID,
			RPOrigins:     d.cfg.WebAuthn.RPOrigins,
		})
		if err != nil {
			return fmt.Errorf("webauthn init: %w", err)
		}
		svc.SetWebAuthnService(wa)
	}

	// snapshot scheduler runner — built after `svc` exists so it
	// can reuse lockVM + pickDisk. Backup repo names resolve through
	// `backup_repos:` in config; an empty map disables the scheduler
	// effectively (every schedule errors with ErrNoRepoConfigured until
	// the operator adds a repo).
	d.snapScheduler.Runner = grpcapi.BackupRunnerForScheduler(svc, d.cfg.BackupRepos)
	d.snapScheduler.ReplRunner = svc // *grpcapi.Server implements RunReplication
	go d.snapScheduler.Run(ctx)

	// Sweep staging temp files leaked by a prior hard crash (SIGKILL skips the
	// deferred cleanup of replicate/upload/import/restore temps — they'd
	// otherwise accumulate and fill the pool/image dirs).
	svc.SweepStaleStaging(ctx)

	// Now that the gRPC server exists, wire it as the failover coordinator's
	// replica promoter (auto_promote recovery) and start the coordinator.
	fc.Promoter = svc                 // *grpcapi.Server implements failover.ReplicaPromoter
	fc.OnFence = svc.NotifyHostFenced // operator notification on fence (#5)
	go fc.Start(ctx)

	// Peer self-upgrade: a daemon that comes back on an old binary (e.g. it was
	// down during a cluster upgrade) pulls the newer binary from a healthy peer
	// and re-execs. Default on; disable with auto_upgrade.from_peer: false.
	if d.cfg.AutoUpgrade.FromPeerEnabled() {
		go svc.RunSelfUpgradeWatcher(ctx, d.cfg.AutoUpgrade.Interval())
	} else {
		slog.Info("peer self-upgrade disabled (auto_upgrade.from_peer: false)")
	}

	// Reap orphaned auto DNS records (VMs deleted without their A-record being
	// removed). Runs an initial sweep shortly after start (clears pre-existing
	// orphans on upgrade) then periodically. Idempotent + grace-windowed, so
	// safe to run on every node.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(90 * time.Second):
		}
		svc.ReapOrphanDNSRecords(ctx)
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				svc.ReapOrphanDNSRecords(ctx)
			}
		}
	}()

	// refresh group caches from external realms (LDAP /
	// OIDC) every 5 min. Errors are per-realm and logged but not fatal
	// — one IdP being down doesn't take the cluster offline.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if errs := d.realmRegistry.SyncAll(ctx); len(errs) > 0 {
					for name, err := range errs {
						slog.Warn("realm sync failed", "realm", name, "error", err)
					}
				}
			}
		}
	}()

	rpcMetrics := metrics.NewRPCMetrics()
	d.grpcSrv = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(rpcMetrics.UnaryInterceptor(), svc.UnaryAuthInterceptor),
		grpc.ChainStreamInterceptor(rpcMetrics.StreamInterceptor(), svc.StreamAuthInterceptor),
		// Defense-in-depth for the legacy unary state-dump/replication paths: the
		// 4 MiB gRPC default silently failed a large full-state dump (the bug
		// StreamStateDump fixes), and a big PushMutations batch could trip it too.
		// StreamStateDump itself stays well under this; this only backstops the
		// non-chunked paths during/after a mixed-version rollout.
		grpc.MaxRecvMsgSize(grpcMaxMsgSize),
		grpc.MaxSendMsgSize(grpcMaxMsgSize),
	)

	pb.RegisterLiteVirtServer(d.grpcSrv, svc)

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", d.cfg.GRPCPort))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	slog.Info("litevirtd starting",
		"host", d.cfg.HostName,
		"grpc", fmt.Sprintf("0.0.0.0:%d", d.cfg.GRPCPort),
		"metrics", fmt.Sprintf("0.0.0.0:%d", d.cfg.MetricsPort),
		"ui", fmt.Sprintf("%s:%d", d.cfg.UIBind, d.cfg.UIPort),
	)

	// Start web UI (connects back to local gRPC as a client).
	go func() {
		clientTLS, err := pki.ClientTLSConfig(d.cfg.PKIDir)
		if err != nil {
			slog.Warn("UI client TLS config failed", "error", err)
			return
		}
		localConn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", d.cfg.GRPCPort),
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		)
		if err != nil {
			slog.Warn("UI gRPC dial failed", "error", err)
			return
		}
		uiClient := pb.NewLiteVirtClient(localConn)
		uiSrv, err := ui.NewServer(uiClient, d.cfg.HostName)
		if err != nil {
			slog.Warn("UI server init failed", "error", err)
			return
		}
		// hand the UI a corrosion DB handle so read-only
		// pages (security-groups, etc.) can query cluster state without
		// adding a dedicated gRPC RPC for every list view.
		uiSrv.SetCorrosionDB(d.db)
		uiSrv.SetBackupRepos(d.cfg.BackupRepos)
		uiSrv.SetWSOriginPatterns(d.cfg.UIAllowedOrigins)
		// ACME (#13): when enabled, terminate UI TLS via autocert (step-ca / LE)
		// with an internal-PKI fallback, and serve the HTTP-01 challenge on :80.
		if tlsCfg, challenge := d.buildUITLSConfig(); tlsCfg != nil {
			uiSrv.SetTLSConfig(tlsCfg)
			startACMEChallengeServer(ctx, challenge)
		}
		uiSrv.StartCollector(ctx)
		if err := uiSrv.ListenAndServe(fmt.Sprintf("%s:%d", d.cfg.UIBind, d.cfg.UIPort)); err != nil {
			slog.Warn("UI server stopped", "error", err)
		}
	}()

	// Start REST API gateway.
	if d.cfg.RESTPort > 0 {
		go func() {
			restTLS, err := pki.ClientTLSConfig(d.cfg.PKIDir)
			if err != nil {
				slog.Warn("REST client TLS config failed", "error", err)
				return
			}
			restConn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", d.cfg.GRPCPort),
				grpc.WithTransportCredentials(credentials.NewTLS(restTLS)),
			)
			if err != nil {
				slog.Warn("REST gRPC dial failed", "error", err)
				return
			}
			restClient := pb.NewLiteVirtClient(restConn)
			restSrv := restapi.NewServer(restClient, "")
			restAddr := fmt.Sprintf("127.0.0.1:%d", d.cfg.RESTPort)
			if err := restSrv.ListenAndServe(restAddr); err != nil {
				slog.Warn("REST API server stopped", "error", err)
			}
		}()
	}

	// Handle shutdown, re-exec, and uninstall signals.
	shutdownDone := make(chan struct{})
	reexecRequested := false
	go func() {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			// A graceful stop (SIGTERM from `systemctl restart/stop`) must not
			// look like a host failure: flag ourselves 'upgrading' so peers skip
			// fence candidacy during the brief downtime. We set 'active' again on
			// healthy startup; the failover coordinator still fences a host stuck
			// 'upgrading' past its timeout, so a host that never returns fails
			// over. (Re-exec already runs under 'upgrading'; uninstall is removing
			// the host, so neither needs this.)
			d.markRestarting()
		case <-svc.ReExecCh:
			slog.Info("re-exec requested after upgrade")
			reexecRequested = true
		case <-svc.ShutdownCh:
			slog.Info("shutdown requested by uninstall")
		}
		done := make(chan struct{})
		go func() {
			d.grpcSrv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			slog.Warn("graceful shutdown timed out, forcing stop")
			d.grpcSrv.Stop()
		}
		if d.fwReconciler != nil {
			d.fwReconciler.Stop()
		}
		if d.snapScheduler != nil {
			d.snapScheduler.Stop()
		}
		repl.Stop()
		d.virt.Close()
		d.db.Close()
		close(shutdownDone)
	}()

	serveErr := d.grpcSrv.Serve(lis)

	// Wait for cleanup to finish (replicator, libvirt, DB) before returning,
	// but cap at 15s so we don't hang longer than systemd's stop timeout.
	select {
	case <-shutdownDone:
	case <-time.After(15 * time.Second):
		slog.Warn("shutdown cleanup timed out after 15s, exiting anyway")
	}

	if reexecRequested {
		return ErrReExec
	}

	// Serve returns ErrServerStopped on graceful shutdown — not a real error.
	if serveErr != nil && serveErr != grpc.ErrServerStopped {
		return fmt.Errorf("gRPC serve: %w", serveErr)
	}
	return nil
}

// ErrReExec is returned by Run when the daemon should re-exec itself
// after a binary upgrade.
var ErrReExec = fmt.Errorf("re-exec requested")

func (d *Daemon) registerHost(ctx context.Context) error {
	// Get system resources from libvirt
	cpus, memMiB, err := d.virt.NodeInfo()
	if err != nil {
		return err
	}

	// Get disk total summed across all configured storage pools.
	diskTotalGiB := d.sumPoolDiskTotalGiB()

	// Get cert serial
	serial, err := pki.CertSerial(d.cfg.PKIDir + "/host.crt")
	if err != nil {
		serial = "unknown"
	}

	// Get host address
	addr := getOutboundIP()

	return corrosion.InsertHost(ctx, d.db, corrosion.HostRecord{
		Name:          d.cfg.HostName,
		Address:       addr,
		SSHUser:       "root",
		SSHPort:       22,
		GRPCPort:      d.cfg.GRPCPort,
		State:         "active",
		CertSerial:    serial,
		CPUTotal:      cpus,
		MemTotal:      memMiB,
		DiskTotal:     diskTotalGiB,
		FenceStrategy: "best-effort",
		Version:       d.cfg.Version,
	})
}

// localDiskTotalGiB returns the total disk capacity in GiB for the filesystem
// containing the given path (typically the litevirt data directory).
func localDiskTotalGiB(path string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return int(st.Blocks * uint64(st.Bsize) / (1024 * 1024 * 1024))
}

// sumPoolDiskTotalGiB returns the total disk capacity in GiB summed across all
// configured storage pool targets. Falls back to localDiskTotalGiB if no pools.
func (d *Daemon) sumPoolDiskTotalGiB() int {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		return localDiskTotalGiB(d.cfg.DataDir)
	}
	seen := make(map[string]bool)
	total := 0
	for _, p := range pools {
		if p.Target == "" || seen[p.Target] {
			continue
		}
		seen[p.Target] = true
		total += localDiskTotalGiB(p.Target)
	}
	return total
}

// registerStoragePools upserts all configured storage pools into the cluster DB
// with current capacity from syscall.Statfs.
func (d *Daemon) registerStoragePools(ctx context.Context) {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "default",
			Driver: "local",
			Target: filepath.Join(d.cfg.DataDir, "disks"),
		}}
	}
	for _, p := range pools {
		rec := corrosion.StoragePoolRecord{
			HostName: d.cfg.HostName,
			Name:     p.Name,
			Driver:   p.Driver,
			Source:   p.Source,
			Target:   p.Target,
			State:    "active",
		}
		if p.Target != "" {
			var st syscall.Statfs_t
			if err := syscall.Statfs(p.Target, &st); err == nil {
				rec.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
				rec.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
			} else {
				rec.State = "error"
				slog.Warn("storage pool statfs failed", "pool", p.Name, "target", p.Target, "error", err)
			}
		}
		if err := corrosion.UpsertStoragePool(ctx, d.db, rec); err != nil {
			slog.Warn("failed to register storage pool", "pool", p.Name, "error", err)
		}
	}
}

// refreshStoragePools periodically updates storage pool capacity in the DB.
func (d *Daemon) refreshStoragePools(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.registerStoragePools(ctx)
			d.refreshDBPoolCapacity(ctx)
		}
	}
}

// refreshDBPoolCapacity updates total/used bytes for every file-based storage
// pool registered for THIS host in the DB — including pools created at runtime
// via `lv pool create`. registerStoragePools only scans cfg.StoragePools, so
// runtime-created pools (not in config) were never statfs'd and showed 0B/0B.
func (d *Daemon) refreshDBPoolCapacity(ctx context.Context) {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("refresh pool capacity: list pools", "error", err)
		return
	}
	for _, p := range pools {
		if !fileBasedPoolDriver(p.Driver) || p.Target == "" {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(p.Target, &st); err != nil {
			slog.Warn("refresh pool capacity: statfs", "pool", p.Name, "target", p.Target, "error", err)
			p.State = "error"
			_ = corrosion.UpsertStoragePool(ctx, d.db, p)
			continue
		}
		p.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
		p.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
		p.State = "active"
		if err := corrosion.UpsertStoragePool(ctx, d.db, p); err != nil {
			slog.Warn("refresh pool capacity: upsert", "pool", p.Name, "error", err)
		}
	}

	// Refresh the gRPC server's in-memory pool map from config + the
	// storage_pools table so pools created at runtime via `lv pool create`
	// (table-only, never in config.yaml) become resolvable by move/replicate
	// and compose volume lookups. Previously the map was loaded once at
	// startup from config alone, so runtime pools were invisible to those
	// paths even though `lv pool ls`/the UI showed them active.
	if d.svc != nil {
		refs := d.storagePoolRefs() // config pools first — they carry driver Options
		for _, p := range pools {
			if _, ok := refs[p.Name]; ok {
				continue // config definition wins
			}
			refs[p.Name] = grpcapi.StoragePoolRef{
				Driver:  p.Driver,
				Source:  p.Source,
				Target:  p.Target,
				Options: p.Options,
			}
		}
		d.svc.SetStoragePoolsByName(refs)
	}
}

// fileBasedPoolDriver reports whether a driver's Target is a local filesystem
// path that syscall.Statfs can measure.
func fileBasedPoolDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "dir", "nfs", "btrfs":
		return true
	}
	return false
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// runPCIScan performs the initial PCI device scan and stores results in the DB.
func (d *Daemon) runPCIScan(ctx context.Context) {
	devices, err := pci.Scan()
	if err != nil {
		slog.Warn("PCI scan failed", "error", err)
		return
	}

	interesting := pci.FilterInteresting(devices)
	for _, dev := range interesting {
		if err := corrosion.UpsertPCIDevice(ctx, d.db, corrosion.PCIDeviceRecord{
			HostName:      d.cfg.HostName,
			Address:       dev.Address,
			VendorID:      dev.VendorID,
			DeviceID:      dev.DeviceID,
			VendorName:    dev.VendorName,
			DeviceName:    dev.DeviceName,
			Type:          dev.Type,
			IOMMUGroup:    dev.IOMMUGroup,
			SRIOVCapable:  dev.SRIOVCapable,
			SRIOVVFsTotal: dev.SRIOVVFsTotal,
			SRIOVVFsFree:  dev.SRIOVVFsFree,
			Driver:        dev.Driver,
			NUMANode:      dev.NUMANode,
			PCIeRootPort:  dev.PCIeRootPort,
			PCIeBridge:    dev.PCIeBridge,
			LinkClique:    dev.LinkClique,
			LinkPeers:     strings.Join(dev.LinkPeers, ","),
		}); err != nil {
			slog.Warn("failed to store PCI device", "address", dev.Address, "error", err)
		}
	}
	slog.Info("PCI startup scan complete", "interesting_devices", len(interesting), "total_scanned", len(devices))

	// NVMe namespace discovery (informational log for now).
	namespaces, err := pci.ScanNVMeNamespaces()
	if err != nil {
		slog.Warn("NVMe namespace scan failed", "error", err)
	} else if len(namespaces) > 0 {
		slog.Info("NVMe namespaces discovered", "count", len(namespaces))
	}
}

// parsePCIRescanInterval parses the pci.rescan_interval config value.
// Returns 0 if disabled (empty or "0").
func (d *Daemon) parsePCIRescanInterval() time.Duration {
	s := d.cfg.PCI.RescanInterval
	if s == "" || s == "0" {
		return 0
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid pci.rescan_interval", "value", s, "error", err)
		return 0
	}
	return dur
}

// parseDurationOr parses a Go duration string, returning fallback when empty
// or unparseable (logging a warning in the latter case).
func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid session-timeout duration in config; using default", "value", s, "error", err)
		return fallback
	}
	return d
}

const adminPasswordFile = "/etc/litevirt/admin-password"

// seedAdminUser creates a default admin user with a random password if no users exist.
// The password is written to /etc/litevirt/admin-password (mode 0600).
func (d *Daemon) seedAdminUser(ctx context.Context) error {
	users, err := corrosion.ListUsers(ctx, d.db)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	if len(users) > 0 {
		return nil
	}

	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := corrosion.InsertUser(ctx, d.db, "admin", "admin", string(hash)); err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}

	if err := os.WriteFile(adminPasswordFile, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("write password file: %w", err)
	}

	slog.Info("seeded admin user", "password_file", adminPasswordFile)
	return nil
}

// generatePassword returns a random 32-character hex string.
func generatePassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// storagePoolRefs converts config pools into grpcapi-friendly references keyed by name.
func (d *Daemon) storagePoolRefs() map[string]grpcapi.StoragePoolRef {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "litevirt",
			Driver: "local",
			Target: filepath.Join(d.cfg.DataDir, "disks"),
		}}
	}
	refs := make(map[string]grpcapi.StoragePoolRef, len(pools))
	for _, p := range pools {
		refs[p.Name] = grpcapi.StoragePoolRef{
			Driver:  p.Driver,
			Source:  p.Source,
			Target:  p.Target,
			Options: p.Options,
		}
	}
	return refs
}

// reconcileNetworks re-provisions DHCP and NAT for active networks on daemon
// startup. dnsmasq is a child process that dies when the daemon restarts, so
// we need to bring it back for any network with a subnet.
func (d *Daemon) reconcileNetworks(ctx context.Context) {
	nets, err := corrosion.ListNetworks(ctx, d.db)
	if err != nil {
		slog.Warn("reconcileNetworks: list networks", "error", err)
		return
	}
	localIP := network.LocalIP()
	for _, n := range nets {
		if n.Config == "" {
			continue
		}
		var def compose.NetworkDef
		if err := json.Unmarshal([]byte(n.Config), &def); err != nil {
			slog.Warn("reconcileNetworks: parse config", "network", n.Name, "error", err)
			continue
		}
		def.Type = n.Type
		if def.Interface == "" {
			def.Interface = n.Name
		}
		if _, err := network.SafeProvision(ctx, d.db, n.Name, def, localIP, d.cfg.HostName); err != nil {
			slog.Warn("reconcileNetworks: provision failed", "network", n.Name, "error", err)
		} else {
			slog.Info("network reconciled", "network", n.Name, "type", n.Type)
		}
	}
}

// ensureStoragePools creates libvirt storage pools from config, or a default
// local pool if none are configured.
func (d *Daemon) ensureStoragePools() {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "litevirt",
			Driver: "local",
			Target: filepath.Join(d.cfg.DataDir, "disks"),
		}}
	}
	for _, p := range pools {
		if err := d.virt.EnsureStoragePool(p.Name, p.Driver, p.Source, p.Target, p.Options); err != nil {
			slog.Warn("failed to ensure storage pool", "pool", p.Name, "error", err)
		} else {
			slog.Info("storage pool ready", "pool", p.Name, "driver", p.Driver)
		}
	}
}

// runPeriodicPCIScan runs the PCI scan on a recurring timer until ctx is cancelled.
func (d *Daemon) runPeriodicPCIScan(ctx context.Context, interval time.Duration) {
	slog.Info("PCI periodic rescan enabled", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Debug("running periodic PCI rescan")
			d.runPCIScan(ctx)
		}
	}
}

// runVMEventPrune periodically trims this host's vm_events rows to the
// configured retention. Each host prunes only its own rows (host_name = self),
// so it's idempotent and needs no cluster lease; the DELETEs replicate. An
// initial run shortly after startup clears anything stale from a prior crash.
func (d *Daemon) runVMEventPrune(ctx context.Context) {
	interval := time.Duration(d.cfg.VMEventPruneHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	prune := func() {
		if err := corrosion.PruneVMEvents(ctx, d.db, d.cfg.HostName,
			d.cfg.VMEventRetentionDays, d.cfg.VMEventErrorRetentionDays, d.cfg.VMEventMaxPerVM); err != nil {
			slog.Warn("vm_events prune", "error", err)
		} else {
			slog.Debug("vm_events prune complete")
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
		prune()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}
