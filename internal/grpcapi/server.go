package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/lb"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

	// backupRepos maps a logical repo name to its on-disk path (daemon config
	// `backup_repos:`), set via SetBackupRepos. Used to resolve a request's
	// repo_path: a registered name is allowed for any operator; an absolute or
	// unregistered path is admin-only (resolveBackupRepoPath).
	backupRepos map[string]string

	// imageMaxBytes / imagePullTimeout bound image pull+import (disk-fill /
	// SSRF guards), set from daemon config via SetImageLimits. Zero → the image
	// package defaults apply. imageBlockedCIDRs is the opt-in URL-pull network
	// deny policy (nil → no guard); applies to image.Pull only.
	imageMaxBytes     int64
	imagePullTimeout  time.Duration
	imageBlockedCIDRs []netip.Prefix

	// Session lifetimes. Zero means "use the package default" (see
	// idleTimeout/hardExpiry); set from daemon config via SetSessionTimeouts.
	// Per-node — sessions store an absolute ExpiresAt at login, so a mixed
	// cluster stays coherent (only the idle window can differ by node).
	sessionIdleTimeout time.Duration
	sessionHardExpiry  time.Duration

	// strictMTLSIdentity, when true, is this node's enforcement switch for the
	// strict mTLS-identity model (a bearerless "client" cert is denied; must
	// `lv login`). Enforcement is this flag AND the StrictMTLSIdentityV1 gate
	// being active cluster-wide; the flag is also the kill switch. Default false.
	strictMTLSIdentity bool

	// forwardedIdentity, when true, is this node's enforcement switch for owner-
	// side promotion of a forwarded user identity (x-litevirt-fwd-bearer). Gated
	// by this flag AND the ForwardedIdentityV1 capability active cluster-wide.
	// Default false; the flag is the kill switch.
	forwardedIdentity bool

	// enfSafeFence / enfLWWSkew / enfVIPSelfDemote / enfVIPProofReclaim mirror the
	// split-brain-family enforcement kill-switches (config.Enforcement) so the HA
	// monitor can drive the right tokens' latches (mandatory ∪ configured-on) and
	// gate the degraded/paging contributions on config intent, not mere
	// advertisement. The actual enforcement predicates live on the consumers
	// (Coordinator, daemon closures, vipGateActive); the daemon wires both from one
	// config source. See SetEnforcementConfig / tokenEnabled. All default false.
	enfSafeFence       bool
	enfLWWSkew         bool
	enfVIPSelfDemote   bool
	enfVIPProofReclaim bool

	// capHealthLast records the most recent bounded freshness-check result per
	// configured-on token (checkOneCapabilityHealth, round-robin one/cycle) so the HA
	// monitor detects a POST-latch capability regression (a peer that later stops
	// advertising) that the one-way durable latch can't reflect. Guarded by capHealthMu.
	capHealthMu     sync.Mutex
	capHealthLast   map[string]bool
	capHealthCursor int

	// firmware holds the host's resolved OVMF paths (Secure Boot + vTPM, G1), set
	// at daemon startup so CreateVM/restore render the same files the capability
	// label was derived from.
	firmware lv.FirmwarePaths

	// lbApplyOverride is a test seam for LB provisioning: when non-nil it
	// replaces the real haproxy/keepalived Apply (unit tests have no root / no
	// haproxy). Production leaves it nil so apply failures surface + roll back.
	lbApplyOverride func(context.Context, lb.Config) error

	// probeHolder is a test seam for the Phase-2 VIP takeover check: when non-nil it
	// replaces the real fresh-probe of a peer holder's (reachable, supports, assigned)
	// state. Production leaves it nil.
	probeHolder func(ctx context.Context, host, vip string) holderStatus

	// vipGateFlipped is a test seam for the CAPABILITY side of vipGateActive only: when
	// non-nil it overrides the VIPReleaseProbeV1 latch check. It is still AND-ed with the
	// enforcement.vip_proof_reclaim config flag (see vipGateActive), so a test can't use
	// it to bypass the kill-switch. Production nil.
	vipGateFlipped func() bool

	// removeLBFromHost is a test seam for the Phase-2 synchronous stand-down of a removed
	// VIP holder (a peer RemoveLB RPC). Production leaves it nil (the real RemoveLB call).
	removeLBFromHost func(ctx context.Context, lbName, host string) error

	// lbParticipantsOverride is a test seam for resolving the ACTUAL participants of an LB
	// by name (Phase-2 High-2: ground-truth membership — incl. VRRP backups — for
	// implicit/legacy hosts=[] LBs). Production nil.
	lbParticipantsOverride func(ctx context.Context, lbName string) ([]string, bool)

	// vipHoldersOverride is a test seam for resolving which hosts currently hold a VIP by
	// ADDRESS (Phase-2 create kernel-absence proof). Production nil.
	vipHoldersOverride func(ctx context.Context, vip string) ([]string, bool)

	// lbHealthOverride is a test seam for InspectLoadBalancer's HAProxy health
	// overlay (unit tests have no running haproxy): when non-nil it returns the
	// server-name→raw-status map instead of querying the stats socket.
	lbHealthOverride func(context.Context, string) (map[string]string, error)

	// lbKeepalivedOverride is a test seam for the VIP-health (degraded) check:
	// when non-nil it reports whether this host's keepalived for an LB is running.
	lbKeepalivedOverride func(name string) bool

	// migrateRestoreOverride is a test seam for container cold migration + failover
	// relocation: when non-nil it replaces the real "dial the target peer + drive
	// RestoreContainer" step (unit tests have no second daemon) and returns the
	// classified restore outcome directly, so a test can model a landed restore, a
	// pre-row failure, or an indeterminate stream break. Production leaves it nil.
	migrateRestoreOverride func(ctx context.Context, target, repoPath, name, timestamp string, start bool) (corrosion.RestoreOutcome, error)

	// peerClientOverride is a test seam for the PR-4 peer backup/restore streaming
	// helpers (dialPeer): when non-nil it returns a fake LiteVirtClient + closer
	// instead of dialing a real peer over mTLS, so the owner→sink push path is
	// unit-testable in-process. Production leaves it nil → real peerClient.
	peerClientOverride func(ctx context.Context, host string) (pb.LiteVirtClient, func(), error)

	// stopVMOverride is a test seam for ShutdownHostWorkloads: when non-nil it
	// replaces the in-process StopVM call (unit tests have no libvirt/peer), so
	// the test can observe the reverse-startup-order sequence and stop_delay
	// pacing. Production leaves it nil → real StopVM forwards to the owning host.
	stopVMOverride func(ctx context.Context, req *pb.StopVMRequest) (*pb.VM, error)

	// loginThrottle rate-limits failed Login attempts per (username, IP) to
	// blunt password / second-factor brute force. In-memory + per-node; nil
	// in bare test servers (no throttling) and set by NewServer in production.
	loginThrottle *loginThrottle

	migrationMetrics *metrics.MigrationMetrics
	lbMetrics        *metrics.LBMetrics
	haMetrics        *metrics.HAHealthMetrics

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

	// fetchBinarySem bounds concurrent FetchBinary streams this node serves, so a
	// fleet-wide version flip can't make one source a thundering-herd target.
	// nil → unbounded (defensive; constructors initialize it).
	fetchBinarySem chan struct{}

	// pushBackupSem bounds concurrent PushBackup streams this node serves as a
	// sink, so a burst of remote backups/migrations can't exhaust disk/CPU.
	// nil → unbounded (defensive; constructors initialize it).
	pushBackupSem chan struct{}

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

	// gate is the split-brain safety gate (Phase 1), implemented by *health.Checker.
	// When set + enforced, ApplyLB (VIP takeover) requires local quorum. nil /
	// pre-activation → unchanged. onGateRefused feeds the refusal metric (nil-safe).
	gate          serverGate
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state/image write that failed
	// (nil-safe); the daemon wires it to litevirt_state_write_failures_total.
	onStateWriteFail func(op, class string)

	// demotionUnfenced is set by the VIPDemoter (SetDemotionUnfenced) when a minority VIP
	// self-demote FAILED and this node has no verified self-fence — a durable HA-degraded
	// condition (the majority won't reclaim without proof, so the VIP stays down). It does
	// NOT gate advertisement: vip_demote_v1 is a software capability advertised regardless
	// of watchdog (the decouple), so a watchdog-less node still self-demotes.
	demotionUnfenced atomic.Bool

	// watchdogFenced reports whether this node has SELF-FENCED (tripped the watchdog) and
	// is only waiting for the hardware timeout to reboot. During that live-but-doomed
	// window it must stop being trusted as a healthy member — advertisedCapabilities drops
	// ALL split-brain tokens so peers stop counting it. Set by the daemon from the watchdog
	// controller. Stored atomically: the HA-health monitor goroutine can self-Ping into
	// advertisedCapabilities before the daemon wires this in, so the read must not race the
	// write. Unset (nil) → never fenced.
	watchdogFenced atomic.Pointer[func() bool]
}

// SetDemotionUnfenced records whether a minority VIP demote failed with no verified
// self-fence (from the VIPDemoter) — read by evaluateHADegraded to surface the durable
// haDemotionUnfenced condition.
func (s *Server) SetDemotionUnfenced(on bool) { s.demotionUnfenced.Store(on) }

// SetWatchdogFenced injects the self-fenced predicate (Phase 2 defense-in-depth).
func (s *Server) SetWatchdogFenced(fn func() bool) { s.watchdogFenced.Store(&fn) }

// advertisedCapabilities is Supported() as-is — vip_demote_v1 is a SOFTWARE capability
// advertised by every new-binary node regardless of any hardware watchdog (the decouple:
// self-demotion runs without one; the watchdog is only an optional self-fence backstop).
//
// ADVERTISED MEANS "THIS BINARY SUPPORTS THE FEATURE", NOT "THIS NODE IS ENFORCING IT".
// With the kill-switch flags, a node advertises a token (so the cluster can latch it)
// while `enforcement.*` / `auth.*` is false and it does NOT act on it — e.g. it
// advertises vip_demote_v1 but will not self-demote. Future code MUST NOT read a peer's
// advertisement (PeerSupportsFresh(VIPDemoteV1), CapabilityActive, …) as proof the peer
// will self-demote or otherwise enforce; the majority proof path keys on
// vip_release_probe_v1 + the ground-truth VIPAssigned probe, never on vip_demote_v1.
//
// Once this node has SELF-FENCED it advertises NOTHING split-brain-related: it is
// committed to going down, so it de-advertises immediately rather than presenting as a
// healthy participant for the fence-timeout window. This is safe (doesn't wrongly free a
// VIP): the majority's reclaim gates on the ground-truth VIPAssigned probe / a Phase-5
// fence proof, never on the token, and peers already latched keep enforcing regardless.
func (s *Server) advertisedCapabilities() []string {
	if s.selfFenced() {
		return []string{}
	}
	return capabilities.Supported()
}

// serverGate is the subset of *health.Checker the gRPC server consults.
type serverGate interface {
	ExecutionGate(ctx context.Context) health.GateResult
	// DecisionGate is the coordinator/decide-site gate (quorum + coordinator-eligible).
	// Leader-gated decide loops (rebalance executor) require it ON TOP of their CRDT
	// lease, since a lease can be "held" on both sides of a partition.
	DecisionGate(ctx context.Context) health.GateResult
	CapabilityActive(ctx context.Context, token string) (bool, string)
	// CapabilityActiveForHealth is the positive-cached variant for the periodic HA-degraded
	// monitor ONLY — never the activation path (see health.Checker).
	CapabilityActiveForHealth(ctx context.Context, token string) (bool, string)
	// Enforced is the LATCHED enforcement decision — once activated cluster-wide it
	// stays true even when a fresh Ping can't confirm (partition → fail closed).
	Enforced(ctx context.Context, token string) bool
	// Latched is a cheap in-memory read of whether token has already latched (no
	// Ping). The HA monitor's bounded latch-driver uses it to skip already-latched
	// tokens so it drives at most one unlatched token per cycle.
	Latched(token string) bool
	// PeerSupportsFresh fresh-Pings peer (UNcached) and reports whether it advertises
	// token — used before stamping/forwarding a proof-bearing action, so a
	// regressed/replaced target that can't honor the proof is never sent one.
	// Uncached so a target that regressed within the cache TTL is caught immediately.
	PeerSupportsFresh(ctx context.Context, peer, token string) bool
	// HealthyPeers returns the peers this node currently counts toward quorum (probed
	// healthy this run AND voting-eligible by host state). Used to pick a quorum-visible
	// relay for the VIP absence proof when the target isn't directly reachable.
	HealthyPeers(ctx context.Context) []string
}

// SetGate injects the split-brain safety gate.
func (s *Server) SetGate(g serverGate) { s.gate = g }

// SetEnforcementConfig records the split-brain-family kill-switch flags so the HA
// monitor drives/gates the right tokens. Wired once from config.Enforcement.
func (s *Server) SetEnforcementConfig(safeFence, lwwSkew, vipSelfDemote, vipProofReclaim bool) {
	s.enfSafeFence = safeFence
	s.enfLWWSkew = lwwSkew
	s.enfVIPSelfDemote = vipSelfDemote
	s.enfVIPProofReclaim = vipProofReclaim
}

// tokenEnabled reports whether this node is configured to ENFORCE token — the
// single source of "configured-to-enforce" the HA monitor uses to decide which
// tokens to latch-drive and which may contribute to HA-degraded. split_brain_gate_v1
// is mandatory (no flag); every other token is gated by its config kill-switch.
// NOTE: enabled ≠ latched ≠ advertised — advertisement is build-static, latch is
// cluster confirmation, this is local config intent.
func (s *Server) tokenEnabled(token string) bool {
	switch token {
	case capabilities.SplitBrainGateV1:
		return true
	case capabilities.SafeFenceDefaultV1:
		return s.enfSafeFence
	case capabilities.LWWSkewGuardV1:
		return s.enfLWWSkew
	case capabilities.VIPDemoteV1:
		return s.enfVIPSelfDemote
	case capabilities.VIPReleaseProbeV1:
		return s.enfVIPProofReclaim
	case capabilities.StrictMTLSIdentityV1:
		return s.strictMTLSIdentity
	case capabilities.ForwardedIdentityV1:
		return s.forwardedIdentity
	default:
		return false
	}
}

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (s *Server) SetGateRefusedObserver(fn func(action, reason string)) { s.onGateRefused = fn }

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (s *Server) SetStateWriteFailObserver(fn func(op, class string)) { s.onStateWriteFail = fn }

func (s *Server) noteStateWriteFail(op string, err error) {
	if s.onStateWriteFail != nil {
		s.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

// persistVMState records an authoritative VM state via the strict helper,
// retrying briefly to absorb a transient Corrosion/DB error (the realistic
// failure after a runtime action already succeeded). A zero-row result
// (ErrNoRowsAffected — the row vanished) returns immediately; retrying it is
// pointless. On a persistent failure it counts the drop (state-write metric) and
// returns the error, letting the caller decide whether losing THIS write is fatal
// (operator-stop, whose loss lets HA restart a stopped VM) or merely observed (a
// "running" state the reconciler heals from libvirt).
func (s *Server) persistVMState(ctx context.Context, name, state, detail, op string) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if err = corrosion.UpdateVMStateStrict(ctx, s.db, name, state, detail); err == nil {
			return nil
		}
		if errors.Is(err, corrosion.ErrNoRowsAffected) {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	s.noteStateWriteFail(op, err)
	return err
}

func (s *Server) noteGateRefused(action, reason string) {
	if s.onGateRefused != nil {
		s.onGateRefused(action, reason)
	}
}

// gateActive reports whether the split-brain gate is enforced cluster-wide
// (split_brain_gate_v1 present on every enforcement-relevant member). Fail-open
// (false) until then. Recomputed per call.
func (s *Server) gateActive(ctx context.Context) bool {
	if s.gate == nil {
		return false
	}
	return s.gate.Enforced(ctx, capabilities.SplitBrainGateV1)
}

// selfFenced reports whether THIS node has self-fenced (tripped the watchdog) and is
// only waiting for the hardware timeout to reboot. During that live-but-doomed window it
// must refuse every runtime-ownership decide/execute — even if quorum transiently returns
// before the reboot — since it has already committed to going down. nil predicate → false.
func (s *Server) selfFenced() bool {
	if fn := s.watchdogFenced.Load(); fn != nil {
		return (*fn)()
	}
	return false
}

// execGateForAction reports whether the split-brain gate blocks a runtime-ownership
// action on THIS host. It runs the local ExecutionGate (must be an active worker
// with quorum) when EITHER a proof marker is carried OR enforcement is latched
// cluster-wide. The marker forcing the gate is essential: in an asymmetric
// partition a target can receive a valid carried proof while itself lacking quorum,
// and must NOT execute. Legacy (ungated) is allowed ONLY when there is no marker
// AND enforcement never activated. Fail-open ("" ok) in that legacy case.
func (s *Server) execGateForAction(ctx context.Context, markerPresent bool) (reason string, refused bool) {
	// Self-fence is a HARD, unconditional local gate (independent of markers, quorum, or
	// enforcement): a doomed node must not execute already-stamped or self-minted actions
	// during the fence-timeout window.
	if s.selfFenced() {
		return health.ReasonSelfFenced, true
	}
	if s.gate == nil {
		// A carried proof MARKER with no gate to verify quorum fails CLOSED — we
		// cannot confirm this host has quorum, and a proof implies enforcement was
		// active somewhere. Only a truly markerless legacy action proceeds ungated.
		if markerPresent {
			return health.ReasonNoQuorum, true
		}
		return "", false
	}
	if !markerPresent && !s.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		return "", false
	}
	if g := s.gate.ExecutionGate(ctx); !g.OK {
		return g.Reason, true
	}
	return "", false
}

// execGateRefused is the markerless form (enforcement-gated only). Direct-RPC
// executors that may carry a proof must use execGateForAction(ctx, proof != nil).
func (s *Server) execGateRefused(ctx context.Context) (reason string, refused bool) {
	return s.execGateForAction(ctx, false)
}

// decideGateRefused reports whether the split-brain DECIDE gate blocks a
// coordinator-driven runtime-ownership decision on THIS host: enforced cluster-wide
// AND DecisionGate not OK (no quorum / not coordinator-eligible). Fail-open until
// split_brain_gate_v1 is cluster-wide. Used by leader-gated decide loops (the
// rebalance executor) ON TOP of their CRDT lease — a lease can be "held" on both
// sides of a partition, so it is never sufficient alone for an automated move.
func (s *Server) decideGateRefused(ctx context.Context) (reason string, refused bool) {
	// A self-fenced node must not DECIDE either (same hard gate as execute).
	if s.selfFenced() {
		return health.ReasonSelfFenced, true
	}
	if s.gate == nil {
		return "", false
	}
	if !s.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		return "", false
	}
	if g := s.gate.DecisionGate(ctx); !g.OK {
		return g.Reason, true
	}
	return "", false
}

// destSupportsGate fresh-Pings dest to confirm it advertises split_brain_gate_v1
// BEFORE this (latched-enforcement) node stamps/forwards a proof-bearing action
// there. A regressed/replaced dest that no longer advertises can't honor the proof
// — proceeding would strand the action or silently drop it to the legacy path on
// the dest, both defeating the gate. Fail closed: unconfirmed support → false.
func (s *Server) destSupportsGate(ctx context.Context, dest string) bool {
	if s.gate == nil {
		return false
	}
	if dest == s.hostName {
		// Our own capability is known locally — no self-Ping needed. Read the SAME
		// dynamic advertised view Ping returns (advertisedCapabilities), so a self-fenced
		// node reports itself as NOT gate-capable and won't stamp/forward a self-targeted
		// proof, matching what peers see.
		return capabilities.Has(s.advertisedCapabilities(), capabilities.SplitBrainGateV1)
	}
	return s.gate.PeerSupportsFresh(ctx, dest, capabilities.SplitBrainGateV1)
}

// lbGateRefused is the markerless execute-gate at the LB-apply chokepoint.
func (s *Server) lbGateRefused(ctx context.Context) (string, bool) { return s.execGateRefused(ctx) }

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
	// ContainerExists reports whether the on-disk container artifact (dir) exists —
	// independent of any DB row. Used by the crash-idempotent restore resume path to
	// tell an untracked leftover (import done, row not yet written) from a clean slate.
	ContainerExists(ctx context.Context, name string) (bool, error)
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
	Veth   string // deterministic host-side veth name (managed NICs); "" = legacy/unmanaged
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
		hostName:       hostName,
		dataDir:        dataDir,
		pkiDir:         pkiDir,
		db:             db,
		virt:           virt,
		images:         images,
		events:         events.NewBus(),
		vmLocks:        make(map[string]*sync.Mutex),
		loginThrottle:  newLoginThrottle(),
		ReExecCh:       make(chan struct{}, 1),
		ShutdownCh:     make(chan struct{}, 1),
		fetchBinarySem: make(chan struct{}, fetchBinaryMaxConcurrent),
		pushBackupSem:  make(chan struct{}, pushBackupMaxConcurrent),
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

// reconcileFirewall applies the firewall ruleset now, best-effort. Callers use it
// after writing/deleting host_fw_intent (NAT/SNAT/isolation) so the change takes
// effect immediately instead of on the next 30s reconciler tick — host isolation
// must not be fail-open, and NAT/VIP exceptions must not be missing, for a whole
// tick after a create. A failure is only a latency regression (the tick still
// applies it), so it is logged, not surfaced.
func (s *Server) reconcileFirewall(ctx context.Context) {
	if s.fwReconciler == nil {
		return
	}
	if err := s.fwReconciler.Reconcile(ctx); err != nil {
		slog.Debug("firewall reconcile after intent change failed (next tick will apply)", "error", err)
	}
}

// reconcileFirewallRequired is the fail-CLOSED variant: it returns the apply
// error so a caller that just recorded host-isolation / NAT intent can fail
// rather than report success while nft hasn't applied the rules. Use it on the
// provisioning paths (network create/provision, NIC hotplug, VM-local network
// setup) — a swallowed failure there is a fail-open regression from the old
// direct EnsureHostIsolation/EnsureNAT calls, which returned the error. Teardown
// and LB paths use the best-effort reconcileFirewall instead.
func (s *Server) reconcileFirewallRequired(ctx context.Context) error {
	if s.fwReconciler == nil {
		return nil
	}
	return s.fwReconciler.Reconcile(ctx)
}

// SetFirmwarePaths injects the host's resolved OVMF firmware paths (G1).
func (s *Server) SetFirmwarePaths(fp lv.FirmwarePaths) { s.firmware = fp }

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

// SetHAHealthMetrics attaches the persistent HA-degraded gauge (Phase 2 H1).
func (s *Server) SetHAHealthMetrics(m *metrics.HAHealthMetrics) {
	s.haMetrics = m
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

// SetBinaryPath sets the path the upgrade swap targets. The daemon sets this to
// its own os.Executable() at startup so `lv host upgrade` replaces the binary
// this process is ACTUALLY running (which is what the re-exec then runs) —
// rather than a hardcoded path. For a systemd install that's /usr/local/bin/
// litevirt (no change); for any other install path (or an ephemeral test
// daemon) it self-locates correctly instead of swapping the wrong file.
func (s *Server) SetBinaryPath(p string) { s.binaryPath = p }

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

// peerTarget builds a dialable "host:port" target, defaulting the port to 7443
// and bracketing IPv6 addresses via net.JoinHostPort.
func peerTarget(addr string, port int) string {
	if port == 0 {
		port = 7443
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

// dialPeerAddr opens an mTLS gRPC connection to a peer daemon at an already-known
// "host:port" target (skipping the corrosion host lookup that dialPeer does).
// pki.PeerDial itself attaches tracing dial options (via the hook the daemon
// wires with pki.SetTraceDialOptions at boot) so W3C traceparent propagates on
// the outbound call — a no-op when tracing is off — for every PeerDial caller,
// not just this one; a new call site can no longer silently drop trace
// propagation by forgetting to pass obs.ClientDialOptions() explicitly.
func (s *Server) dialPeerAddr(target string) (*grpc.ClientConn, error) {
	return pki.PeerDial(s.pkiDir, target)
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
	// dialPeer always attaches obs trace-context options (injects W3C trace context
	// on the outbound peer RPC when tracing is active; nil otherwise).
	conn, err := s.dialPeerAddr(peerTarget(host.Address, host.GRPCPort))
	if err != nil {
		return nil, nil, fmt.Errorf("dial host %s: %w", hostName, err)
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}
