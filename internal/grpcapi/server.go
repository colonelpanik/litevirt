package grpcapi

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Server implements the LiteVirt gRPC service.
type Server struct {
	pb.UnimplementedLiteVirtServer

	hostName   string
	dataDir    string
	pkiDir     string
	db         *corrosion.Client
	virt       LibvirtBackend
	images     *image.Store
	events     *events.Bus
	webhookURL string // optional; fired on every publish() call

	version   string // build version, reported via Ping and ListHosts
	dnsDomain string // DNS domain for VM record names (e.g. "litevirt.local")

	// Session lifetimes. Zero means "use the package default" (see
	// idleTimeout/hardExpiry); set from daemon config via SetSessionTimeouts.
	// Per-node — sessions store an absolute ExpiresAt at login, so a mixed
	// cluster stays coherent (only the idle window can differ by node).
	sessionIdleTimeout time.Duration
	sessionHardExpiry  time.Duration

	// lbApplyOverride is a test seam for LB provisioning: when non-nil it
	// replaces the real haproxy/keepalived Apply (unit tests have no root / no
	// haproxy). Production leaves it nil so apply failures surface + roll back.
	lbApplyOverride func(context.Context, lb.Config) error

	// lbHealthOverride is a test seam for InspectLoadBalancer's HAProxy health
	// overlay (unit tests have no running haproxy): when non-nil it returns the
	// server-name→raw-status map instead of querying the stats socket.
	lbHealthOverride func(context.Context, string) (map[string]string, error)

	// lbKeepalivedOverride is a test seam for the VIP-health (degraded) check:
	// when non-nil it reports whether this host's keepalived for an LB is running.
	lbKeepalivedOverride func(name string) bool

	// migrateRestoreOverride is a test seam for container cold migration: when
	// non-nil it replaces the real "dial the target peer + drive RestoreContainer"
	// step (unit tests have no second daemon). Production leaves it nil.
	migrateRestoreOverride func(ctx context.Context, target, repoPath, name, timestamp string, start bool) error

	// loginThrottle rate-limits failed Login attempts per (username, IP) to
	// blunt password / second-factor brute force. In-memory + per-node; nil
	// in bare test servers (no throttling) and set by NewServer in production.
	loginThrottle *loginThrottle

	migrationMetrics *metrics.MigrationMetrics
	lbMetrics        *metrics.LBMetrics

	// storagePools holds host-level pool refs (name → ref) used to resolve
	// move/replicate/compose volume targets. Seeded from daemon config at
	// startup and refreshed from the storage_pools corrosion table by the
	// daemon so pools created at runtime via `lv pool create` are usable.
	// Guarded by storagePoolsMu because the daemon rewrites it while RPCs read.
	storagePoolsMu sync.RWMutex
	storagePools   map[string]StoragePoolRef

	// vmLocks provides per-VM mutual exclusion for operations that must not
	// run concurrently (e.g. snapshot + migration, backup + delete).
	vmLocksMu sync.Mutex
	vmLocks   map[string]*sync.Mutex

	// activeBackups tracks VMs this daemon is *currently* backing up. It's
	// in-memory, so it's empty after a restart — which is exactly what lets
	// the reconciler tell a genuinely-in-flight backup apart from a
	// "backing-up" state row left stuck by a crashed or interrupted backup
	// (consulted via BackupInProgress). Value is unused; presence is the signal.
	activeBackups sync.Map // vmName -> struct{}

	// replicator handles WAL-based state replication to peers.
	replicator *corrosion.Replicator

	// authEngine is the path-based RBAC engine. transitional:
	// when nil OR when no role-bindings exist for the caller, RequirePerm
	// falls back to the legacy admin/operator/viewer roleLevel comparison.
	authEngine *auth.Engine

	// realmRegistry is consulted by Login to dispatch authentication
	// to the right realm by name. Always contains "local"; OIDC/LDAP
	// realms are added from daemon config at startup. nil = legacy path
	// (LocalRealm only) — kept for tests that don't wire a registry.
	realmRegistry *auth.Registry

	// fwReconciler is the firewall reconciler the daemon started.
	// ReloadFirewall calls Reconcile(ctx) on it synchronously to give
	// `lv firewall reload` push semantics rather than a 30s wait.
	fwReconciler FirewallReconciler

	// tenancy gates CreateVM/stack admission against project quotas
	// and emits metered billing events. Optional — nil means
	// unbounded admission + no billing.
	tenancy *tenancy.Engine

	// containerRuntime executes LXC ops on this host.
	// nil = container RPCs return Unavailable. Tests inject a fake.
	containerRuntime ContainerRuntime

	// liveMover drives libvirt blockdev-mirror for running-VM
	// MoveVolume calls. nil = MoveVolume on a running
	// VM returns Unimplemented (the legacy 1.2.E behaviour).
	liveMover LiveMover

	// webauthn is the second-factor engine. Daemon
	// constructs it once the UI domain is known; tests leave it
	// nil and the WebAuthn RPCs return Unimplemented.
	webauthn *auth.WebAuthnService

	// backupSource opens guest-content backup sessions (pull-mode NBD).
	// nil = legacy qcow2-container full backup. Set by daemon when libvirt
	// is reachable. content-based rewrite.
	backupSource BackupSource

	// ReExecCh is signalled after a successful self-upgrade to trigger
	// a re-exec of the daemon binary. The daemon's main loop should
	// listen on this channel and call syscall.Exec.
	ReExecCh chan struct{}

	// ShutdownCh is signalled after a self-uninstall to trigger daemon shutdown.
	ShutdownCh chan struct{}

	// binaryPath is the path to the daemon binary. Defaults to /usr/local/bin/litevirt.
	binaryPath string
	// logDir is the directory for VM log files. Defaults to /var/log/libvirt/qemu.
	logDir string
}

// FirewallReconciler is the subset of *firewall.Reconciler the gRPC
// layer calls — kept narrow so tests can swap a fake without
// importing internal/firewall at the test level.
type FirewallReconciler interface {
	Reconcile(ctx context.Context) error
	LastError() error
	LastTick() time.Time
}

// ContainerRuntime is the subset of internal/lxc.Runtime the gRPC
// layer calls. Defined here (not imported) so server.go doesn't pull
// internal/lxc into every test that constructs a Server.
type ContainerRuntime interface {
	CreateContainer(ctx context.Context, opts CreateContainerOpts) (*ContainerInfo, error)
	StartContainer(ctx context.Context, name string) error
	StopContainer(ctx context.Context, name string, timeoutSec int) error
	DeleteContainer(ctx context.Context, name string) error
	ExecContainer(ctx context.Context, name string, argv []string) (ContainerExecResult, error)
	StateContainer(ctx context.Context, name string) (string, error)
	IPContainer(ctx context.Context, name string) (string, error)
	ListContainers(ctx context.Context) ([]string, error)
	// FreezeContainer/UnfreezeContainer quiesce a container for a consistent
	// rootfs read (backup/snapshot); ContainerRootFSPath returns the host path of
	// its root tree. Added in B0 (container day-2 primitives).
	FreezeContainer(ctx context.Context, name string) error
	UnfreezeContainer(ctx context.Context, name string) error
	ContainerRootFSPath(name string) (string, error)
	// ExportContainer/ImportContainer stream a container's on-disk directory
	// (config + rootfs) as a tar for backup/restore (B1). Quiesce with
	// FreezeContainer before exporting.
	ExportContainer(ctx context.Context, name string, w io.Writer) error
	ImportContainer(ctx context.Context, name string, r io.Reader) error
	// RevertContainer replaces a stopped container's on-disk dir from a snapshot
	// tar in place (B2 snapshot revert — clobbers).
	RevertContainer(ctx context.Context, name string, r io.Reader) error
	// CloneContainer full-copies src's on-disk dir as dst with a fresh identity
	// (B4 templates/clones).
	CloneContainer(ctx context.Context, src, dst string) error
	PullOCIImage(ctx context.Context, image, dest, tag, username, password string) error
}

// CreateContainerOpts mirrors lxc.CreateOpts at the gRPC boundary so
// internal/grpcapi doesn't need to import internal/lxc.
type CreateContainerOpts struct {
	Name      string
	Template  string
	Distro    string
	Release   string
	Arch      string
	CPULimit  int
	MemoryMiB int
	Networks  []ContainerNICOpt
	Labels    map[string]string
}

// ContainerNICOpt mirrors lxc.NetworkAttach.
type ContainerNICOpt struct {
	Name   string
	Bridge string
	IP     string
	MAC    string
}

// ContainerInfo is the minimal post-create record handed back.
type ContainerInfo struct {
	Name  string
	State string
	Image string
}

// ContainerExecResult mirrors lxc.ExecResult.
type ContainerExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// StoragePoolRef is a lightweight reference to a host-level storage pool.
type StoragePoolRef struct {
	Driver  string
	Source  string
	Target  string
	Options map[string]string
}

// NewServer creates a new gRPC service handler.
func NewServer(hostName, dataDir, pkiDir string, db *corrosion.Client, virt LibvirtBackend, images *image.Store) *Server {
	return &Server{
		hostName:      hostName,
		dataDir:       dataDir,
		pkiDir:        pkiDir,
		db:            db,
		virt:          virt,
		images:        images,
		events:        events.NewBus(),
		vmLocks:       make(map[string]*sync.Mutex),
		loginThrottle: newLoginThrottle(),
		ReExecCh:      make(chan struct{}, 1),
		ShutdownCh:    make(chan struct{}, 1),
	}
}

// SetAuthEngine wires the path-based RBAC engine. Called by the daemon
// after SeedBuiltinRoles + Reload so the bridge knows when to consult it.
func (s *Server) SetAuthEngine(e *auth.Engine) {
	s.authEngine = e
}

// SetRealmRegistry wires the multi-realm authentication registry. The
// daemon constructs it from the auth.realms YAML block and calls this
// before serving begins. When nil, Login falls back to a hard-coded
// LocalRealm.
func (s *Server) SetRealmRegistry(r *auth.Registry) {
	s.realmRegistry = r
}

// RealmRegistry returns the configured registry (or nil). Used by the
// UI to populate the login realm dropdown via availableRealms().
func (s *Server) RealmRegistry() *auth.Registry { return s.realmRegistry }

// SetFirewallReconciler wires the daemon's firewall reconciler so the
// ReloadFirewall RPC can drive a synchronous Reconcile.
func (s *Server) SetFirewallReconciler(r FirewallReconciler) { s.fwReconciler = r }

// SetTenancyEngine wires the admission + billing engine.
// nil = unbounded admission, no billing. Daemon constructs the
// engine with a webhook URL from config.yaml.billing_webhook_url.
func (s *Server) SetTenancyEngine(t *tenancy.Engine) { s.tenancy = t }

// SetContainerRuntime wires the LXC/OCI runtime so the Containers
// RPCs can act on this host. nil = container RPCs return Unavailable.
func (s *Server) SetContainerRuntime(r ContainerRuntime) { s.containerRuntime = r }

// SetLiveMover wires the libvirt blockdev-mirror driver. Daemon
// constructs a real one from internal/libvirt; tests inject a fake.
// nil = MoveVolume on a running VM returns Unimplemented.
func (s *Server) SetLiveMover(m LiveMover) { s.liveMover = m }

// SetWebAuthnService wires the WebAuthn second-factor engine. nil
// causes the WebAuthn RPCs to return Unimplemented — config error /
// not configured in this build / fips-only build all share that path.
func (s *Server) SetWebAuthnService(w *auth.WebAuthnService) { s.webauthn = w }

// lockVM acquires a per-VM mutex. Returns an unlock function. Lazily
// initialises the map so test servers built without NewServer don't
// panic on first lock.
func (s *Server) lockVM(vmName string) func() {
	s.vmLocksMu.Lock()
	if s.vmLocks == nil {
		s.vmLocks = map[string]*sync.Mutex{}
	}
	mu, ok := s.vmLocks[vmName]
	if !ok {
		mu = &sync.Mutex{}
		s.vmLocks[vmName] = mu
	}
	s.vmLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// markBackupActive / clearBackupActive bracket a backup operation so the
// reconciler (via BackupInProgress) can distinguish a live backup from a stuck
// "backing-up" state row.
func (s *Server) markBackupActive(vmName string)  { s.activeBackups.Store(vmName, struct{}{}) }
func (s *Server) clearBackupActive(vmName string) { s.activeBackups.Delete(vmName) }

// BackupInProgress reports whether this daemon is actively backing up the VM.
// Wired into the health reconciler so a "backing-up" row with no live backup
// here (e.g. after a crash/restart or an interrupted stream) is self-healed.
func (s *Server) BackupInProgress(vmName string) bool {
	_, ok := s.activeBackups.Load(vmName)
	return ok
}

// EventBus returns the server's event bus so other components can publish events.
func (s *Server) EventBus() *events.Bus {
	return s.events
}

// SetWebhookURL configures the outbound webhook URL for cluster events.
func (s *Server) SetWebhookURL(url string) {
	s.webhookURL = url
}

// SetVersion sets the daemon build version reported via Ping and host listings.
func (s *Server) SetVersion(v string) {
	s.version = v
}

// SetMigrationMetrics attaches Prometheus migration histograms.
func (s *Server) SetMigrationMetrics(m *metrics.MigrationMetrics) {
	s.migrationMetrics = m
}

// SetLBMetrics attaches Prometheus load-balancer gauges.
func (s *Server) SetLBMetrics(m *metrics.LBMetrics) {
	s.lbMetrics = m
}

// recordLBKeepalived publishes whether this host's keepalived for lbName is
// running (VIP assignable). No-op when metrics aren't wired (tests). Call after
// a local LB apply; pair with clearLBKeepalived on teardown.
func (s *Server) recordLBKeepalived(lbName string) {
	if s.lbMetrics == nil {
		return
	}
	up := 0.0
	if s.lbKeepalivedRunning(lbName) {
		up = 1.0
	}
	s.lbMetrics.KeepalivedUp.WithLabelValues(lbName).Set(up)
}

// clearLBKeepalived drops the gauge for a torn-down LB so it stops reporting.
func (s *Server) clearLBKeepalived(lbName string) {
	if s.lbMetrics == nil {
		return
	}
	s.lbMetrics.KeepalivedUp.DeleteLabelValues(lbName)
}

// SetDNSDomain sets the base DNS domain for VM record names.
func (s *Server) SetDNSDomain(domain string) {
	s.dnsDomain = domain
}

// SetReplicator attaches the WAL-based replicator to the server.
func (s *Server) SetReplicator(r *corrosion.Replicator) {
	s.replicator = r
}

// SetStoragePools configures host-level storage pool references for volume resolution.
func (s *Server) SetStoragePools(pools []StoragePoolRef) {
	m := make(map[string]StoragePoolRef, len(pools))
	for _, p := range pools {
		m[p.Driver+":"+p.Source] = p // keyed for lookup
	}
	s.storagePoolsMu.Lock()
	s.storagePools = m
	s.storagePoolsMu.Unlock()
}

// SetStoragePoolsByName configures host-level storage pool references keyed by
// name. The daemon calls this both at startup (config pools) and periodically
// with config + runtime (corrosion-table) pools merged.
func (s *Server) SetStoragePoolsByName(pools map[string]StoragePoolRef) {
	s.storagePoolsMu.Lock()
	s.storagePools = pools
	s.storagePoolsMu.Unlock()
}

// lookupStoragePool resolves a pool ref by name under the read lock.
func (s *Server) lookupStoragePool(name string) (StoragePoolRef, bool) {
	s.storagePoolsMu.RLock()
	defer s.storagePoolsMu.RUnlock()
	p, ok := s.storagePools[name]
	return p, ok
}

// resolvePool resolves a pool ref for THIS host, falling back to the
// authoritative corrosion storage_pools row when the in-memory cache misses.
//
// The cache (s.storagePools) is seeded from daemon config at startup and only
// merged with corrosion-table pools (e.g. `lv pool create`) on a periodic
// refresh tick. So right after a daemon restart a CLI-created pool is briefly
// invisible to lookupStoragePool — which silently broke replicate/promote in
// that window (e.g. failover auto-promotion firing on a fence right after a
// cluster-wide upgrade resolved "" for the pool dir → "replica not found").
// corrosion is always current, so consult it on a miss and warm the cache.
func (s *Server) resolvePool(ctx context.Context, name string) (StoragePoolRef, bool) {
	if ref, ok := s.lookupStoragePool(name); ok {
		return ref, true
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, name)
	if err != nil || !ok {
		return StoragePoolRef{}, false
	}
	ref := StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}
	s.addStoragePoolRef(name, ref)
	return ref, true
}

// addStoragePoolRef inserts/updates one pool ref under the write lock, so a
// pool just created on this host (CreateStoragePool) is resolvable by
// move/replicate/compose immediately rather than after the daemon's next
// pool-refresh tick.
func (s *Server) addStoragePoolRef(name string, ref StoragePoolRef) {
	s.storagePoolsMu.Lock()
	defer s.storagePoolsMu.Unlock()
	if s.storagePools == nil {
		s.storagePools = map[string]StoragePoolRef{}
	}
	s.storagePools[name] = ref
}

// removeStoragePoolRef drops a pool ref under the write lock (DeleteStoragePool).
// A config-defined pool would be re-added by the daemon's next refresh; a
// runtime pool stays gone.
func (s *Server) removeStoragePoolRef(name string) {
	s.storagePoolsMu.Lock()
	defer s.storagePoolsMu.Unlock()
	delete(s.storagePools, name)
}

// daemonBinary returns the path to the daemon binary.
func (s *Server) daemonBinary() string {
	if s.binaryPath != "" {
		return s.binaryPath
	}
	return "/usr/local/bin/litevirt"
}

// vmLogDir returns the directory containing VM log files.
func (s *Server) vmLogDir() string {
	if s.logDir != "" {
		return s.logDir
	}
	return "/var/log/libvirt/qemu"
}

// peerClient creates a gRPC client connection to a remote host's daemon.
// The caller must close the returned connection when done.
func (s *Server) peerClient(ctx context.Context, hostName string) (pb.LiteVirtClient, *grpc.ClientConn, error) {
	host, err := corrosion.GetHost(ctx, s.db, hostName)
	if err != nil {
		return nil, nil, fmt.Errorf("look up host %q: %w", hostName, err)
	}
	if host == nil {
		return nil, nil, fmt.Errorf("host %q not found in cluster state", hostName)
	}
	if host.Address == "" {
		// grpc.NewClient won't reject this until first RPC; fail fast with a
		// clear reason so console/VNC forwarders can report it to the user.
		return nil, nil, fmt.Errorf("host %q has no address in cluster state", hostName)
	}
	tlsCfg, err := pki.PeerTLSConfig(s.pkiDir)
	if err != nil {
		return nil, nil, fmt.Errorf("peer TLS config: %w", err)
	}
	port := host.GRPCPort
	if port == 0 {
		port = 7443
	}
	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", host.Address, port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial host %s: %w", hostName, err)
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}
