// Package failover implements the fast failover coordinator for litevirt.
// When a host is detected as offline (consecutive health failures ≥ threshold),
// the coordinator fences it and reschedules its VMs onto healthy hosts.
package failover

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/randid"
)

const (
	// pollInterval is how often the coordinator checks for offline hosts.
	pollInterval = 5 * time.Second
	// offlineThreshold is the number of consecutive failures before a host
	// is considered offline by the coordinator.
	offlineThreshold = 5
	// leaseDuration is the TTL for the failover-leader lease. Must be
	// comfortably larger than pollInterval so a slow tick doesn't lose the
	// lease, and comfortably larger than the worst-case fence latency
	// (IPMI verify ≤ 15 s + SSH 10 s + jitter) plus a renewal margin.
	leaseDuration = 30 * time.Second
	// leaseRenewBefore is how much head-room the leader has to renew before
	// the lease expires. Failover renews when remaining time drops below this.
	leaseRenewBefore = 10 * time.Second
	// minFenceLease is the lease head-room required before a fence may START.
	// leaseRenewBefore (10 s) is NOT enough: an IPMI fence spends up to
	// fence.PowerOffVerifyTimeout (15 s) on verification alone, so a fence begun
	// with only the renewal margin left outlives the lease that authorised it —
	// the row expires mid-call, a second coordinator takes it, and two nodes
	// fence and reschedule the same host concurrently. This is a floor, not a
	// budget: the actual deadline comes from the lease time this node really
	// holds, which is usually the full leaseDuration.
	minFenceLease = 20 * time.Second
	// leaseFenceMargin is withheld from the fence deadline so the call returns
	// while this node is still demonstrably the leader, leaving room for the
	// post-fence re-check to read the lease row before it expires.
	leaseFenceMargin = 5 * time.Second
	// failoverLeaseKey is this coordinator's row in leader_election. Named once
	// so the acquire and the three read sites cannot drift apart; it used to be
	// a bare 'failover' literal repeated in each of them.
	//
	// It aliases corrosion.LeaseKeyFailover rather than re-spelling the string,
	// so an enforcement path outside this package and this coordinator can never
	// disagree about which ledger the failover lease lives in.
	failoverLeaseKey = corrosion.LeaseKeyFailover
	// healthFreshness is the maximum age of a host_health row that may count
	// toward fencing quorum. Stale rows from dead observers must not fence
	// hosts they last saw failing days ago.
	healthFreshness = 30 * time.Second
	// recentFenceWindow gates re-fencing of a host for which the fencing_log
	// already shows a successful fence in the recent past.
	recentFenceWindow = 5 * time.Minute
	// upgradingTimeout bounds how long a host may sit in the 'upgrading' state
	// (set by `lv host upgrade` or by a daemon on graceful SIGTERM restart)
	// before the coordinator treats it as a genuine failure. Long enough for a
	// binary stream + restart, short enough that a host that died mid-upgrade
	// still fails over instead of stranding its VMs forever.
	upgradingTimeout = 2 * time.Minute
	// defaultRelocateRestoreTimeout is the fallback for Coordinator.RelocateRestoreTimeout
	// (config container_restore_timeout_sec): how long a relocate-restore marker is
	// treated as in-flight before the coordinator gives up and image-recreates.
	defaultRelocateRestoreTimeout = 10 * time.Minute
)

// Fencer abstracts fence.Execute so tests can inject a stub. Production code
// uses fence.Execute directly via the default value.
type Fencer func(ctx context.Context, h fence.HostConfig) fence.Result

// ReplicaPromoter promotes a VM's freshest replica onto a healthy host. The
// grpcapi server implements it; the coordinator calls it during failover for
// VMs whose replication schedule opted into auto_promote, so a VM on the fenced
// host's local storage can resume from its replica instead of failing to start
// for want of a disk. Optional — nil disables auto-promotion.
type ReplicaPromoter interface {
	// fenceEpoch binds the promote proof to the specific proof-grade fence of the
	// old owner that authorizes this cross-host transfer (see proofGradeFenceRef);
	// "" when no proof-grade fence exists (a best-effort/SSH fence), which the
	// executor treats as fail-closed for a shared-disk VM.
	AutoPromoteReplica(ctx context.Context, vmName, fenceEpoch string) error
}

// ContainerRestorer restores a container onto a survivor host from its latest
// valid backup. The grpcapi server implements it; the coordinator calls it
// during host-loss relocation to prefer a faithful restore-from-backup
// (networking + non-image state) over a bare image-recreate. Optional — nil
// disables tier-2 and the coordinator always image-recreates.
type ContainerRestorer interface {
	// RestoreContainerFromBackup drives the restore on targetHost and classifies
	// the result (corrosion.RestoreOutcome): the signal is the TARGET's, so the
	// coordinator needn't read its own (replication-lagged) replica. Landed ⇒
	// complete; NotAttempted/FailedBeforeRow ⇒ fall back; Unknown ⇒ defer (the row
	// may have landed but the confirmation was lost).
	RestoreContainerFromBackup(ctx context.Context, ctName, targetHost, token string) (corrosion.RestoreOutcome, error)
}

// Coordinator watches for host failures and triggers failover.
type Coordinator struct {
	hostName string
	db       *corrosion.Client
	fencer   Fencer
	// capacity is the cluster-wide capacity policy; see placement.Request.Capacity.
	capacity corrosion.CapacityPolicy
	// leaseTerm is the fencing term of the lease incarnation this coordinator
	// currently holds, 0 when it holds none. Recorded here in Phase 1 and read by
	// the Phase-2 enforcement path; nothing enforces on it yet.
	//
	// Atomic because Phase 2 adds readers outside the poll loop. Today every
	// access is on the single poll goroutine (acquireLease is reached only from
	// the poll cycle and from holdLease within it), so the atomic is
	// future-proofing rather than a fix for a live race — unlike the
	// rebalancer's, which has two concurrent callers.
	leaseTerm atomic.Int64
	// Promoter, when set, lets failover promote replicas for auto_promote VMs.
	Promoter ReplicaPromoter
	// Restorer, when set, lets host-loss relocation restore a container from its
	// latest backup before falling back to image-recreate. nil → image-recreate only.
	Restorer ContainerRestorer
	// RelocateRestoreTimeout bounds how long a relocate-restore marker is treated
	// as in-flight before the coordinator gives up on the restore and falls back
	// to image-recreate. 0 → defaultRelocateRestoreTimeout.
	RelocateRestoreTimeout time.Duration
	// fencing tracks hosts that have already been fenced in this session
	// to avoid double-fencing on repeated poll cycles.
	fenced map[string]bool
	// fenceRelocated records, for hosts THIS coordinator fenced, whether the
	// fence actually relocated any VMs. Presence of a key means "fenced by me
	// this session"; the value is "did VMs move". A spuriously-fenced host that
	// relocated nothing (value=false) can auto-recover to active once healthy;
	// one that moved VMs (value=true) must wait for a manual `undrain` to avoid
	// split-brain. Absent key ⇒ we can't prove it's safe ⇒ stays manual.
	fenceRelocated map[string]bool
	// Now is the time source for lease TTL / fencing-log timestamps.
	// Defaults to time.Now; the fleet harness overrides it with a
	// virtual clock so scenarios can advance time deterministically
	// past the recentFenceWindow / lease expiry without sleeping.
	Now func() time.Time
	// OnFence, when set, is invoked after a fence is recorded so the daemon can
	// emit an operator notification (#5). Best-effort; must not block.
	OnFence func(host, method, result, detail string)
	// Metrics, when set, counts failover decisions/outcomes/errors by
	// phase+result+error_class (U9). Optional + nil-safe (see metrics.go).
	Metrics Metrics
	// Gate is the split-brain safety gate (Phase 1), implemented by *health.Checker.
	// When set AND split_brain_gate_v1 is cluster-wide, the reschedule decide site
	// requires DecisionGate and writes a durable, single-use runtime_action_proofs
	// row linked to the VM's pending transition. nil / pre-activation → legacy path.
	Gate FailoverGate
	// SafeFenceEnforce is the per-node kill-switch for the safe-fence-default policy
	// (config.Enforcement.SafeFenceDefault). Enforcement is this flag AND the
	// SafeFenceDefaultV1 capability latch; the zero value (false) preserves the
	// legacy proceed-anyway behavior, so a hand-built Coordinator / test is unaffected
	// until explicitly enabled. Wired by the daemon.
	SafeFenceEnforce bool
	// SharedStorageFenceEnforce is the per-node kill-switch for the shared-disk
	// ownership-transfer fence gate (config.Enforcement.SharedStorageFence).
	// Enforcement is this flag AND the SharedStorageFenceV1 capability latch. When
	// enforced, the coordinator refuses to CREATE a cross-host transfer of a VM with
	// a writable shared disk unless it has a proof-grade fence of the old owner
	// (a non-empty fence_epoch) — failing closed at the SOURCE so a config-skewed or
	// regressed target can never receive an unfenced shared-disk transfer. Wired by
	// the daemon.
	SharedStorageFenceEnforce bool
	// LeaseTermEnforce is the per-node kill-switch for leader-lease term
	// enforcement (config.Enforcement.LeaseTerm). Enforcement is this flag AND the
	// LeaseTermV1 capability latch, matching the executor's own predicate
	// (grpcapi's leaseTermEnforced) — the two halves of one decision, and they
	// must agree. When enforced, the coordinator refuses to stamp a proof whose
	// term has been superseded. It is a precheck, not the guarantee: the
	// executor's quorum barrier is, because a stale coordinator can skip this and
	// nothing can skip that. Wired by the daemon.
	//
	// It does NOT run "before any destructive work", and must not be described
	// that way. Every stamp site is reached AFTER the host has been fenced —
	// c.fenced is set and the fencer has run long before, and the host row is
	// already persisted offline — so a refusal here abandons a workload whose host
	// is already powered off. A fenced host is processed only once (see the
	// auto-promote fallback comment in failover), so nothing revisits it: that is
	// why the threshold read below fails OPEN, and why a refusal on this path is a
	// last resort rather than a cheap safety net.
	LeaseTermEnforce bool
	// onGateRefused observes gate refusals at decide sites (nil-safe; daemon wires
	// it to litevirt_runtime_action_refused_total).
	onGateRefused func(action, reason string)
	// SelfFenced reports whether THIS node has self-fenced (tripped the watchdog) and is
	// waiting to reboot. A doomed node must not drive ANY failover decision during that
	// window, even if quorum transiently returns first. Wired by the daemon from the
	// watchdog controller; nil → never fenced.
	SelfFenced func() bool
}

// FailoverGate is the subset of *health.Checker the coordinator consults at
// decide sites. Kept as an interface so the coordinator stays testable and the
// gate is optional.
type FailoverGate interface {
	DecisionGate(ctx context.Context) health.GateResult
	QuorumProof(ctx context.Context) (health.QuorumState, int, int)
	// Enforced is the LATCHED enforcement decision (partition → fail closed).
	Enforced(ctx context.Context, token string) bool
	// PeerSupportsFresh fresh-Pings peer (UNcached) and reports whether it advertises
	// token — used to confirm a destination can honor a proof BEFORE stamping one.
	// Uncached so a target that regressed within the cache TTL is caught immediately.
	PeerSupportsFresh(ctx context.Context, peer, token string) bool
}

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (c *Coordinator) SetGateRefusedObserver(fn func(action, reason string)) { c.onGateRefused = fn }

func (c *Coordinator) noteGateRefused(action, reason string) {
	if c.onGateRefused != nil {
		c.onGateRefused(action, reason)
	}
}

// gateEnforced reports whether the split-brain gate is active cluster-wide, so
// the coordinator must write proof-linked pending transitions. Fail-open
// (returns false) until every enforcement-relevant member advertises the token —
// so a mid-roll cluster keeps failing over via the legacy path.
func (c *Coordinator) gateEnforced(ctx context.Context) bool {
	if c.Gate == nil {
		return false
	}
	return c.Gate.Enforced(ctx, capabilities.SplitBrainGateV1)
}

// destAdvertisesGate fresh-Pings dest to confirm it advertises split_brain_gate_v1
// BEFORE the coordinator stamps a proof-bearing action there. A latched-enforcement
// coordinator must never stamp a proof a REGRESSED/replaced target (no longer
// advertising, e.g. downgraded) can't honor — the target would be required to
// validate a proof it doesn't understand, or silently take the legacy path. Fail
// closed: unconfirmed support → false → the mint site refuses.
func (c *Coordinator) destAdvertisesGate(ctx context.Context, dest string) bool {
	if c.Gate == nil {
		return false
	}
	if dest == c.hostName {
		// A self-fenced node advertises nothing split-brain-related (it de-advertises to
		// peers via advertisedCapabilities); mirror that locally so it never stamps a
		// self-targeted proof. run() already hard-gates a fenced coordinator, so this is
		// defense-in-depth against any self-dest mint path.
		return !c.selfFenced() && capabilities.Has(capabilities.Supported(), capabilities.SplitBrainGateV1)
	}
	return c.Gate.PeerSupportsFresh(ctx, dest, capabilities.SplitBrainGateV1)
}

// selfFenced reports whether THIS node has self-fenced (nil predicate → false).
func (c *Coordinator) selfFenced() bool { return c.SelfFenced != nil && c.SelfFenced() }

// NewCoordinator creates a new failover coordinator with the real fencer.
func NewCoordinator(hostName string, db *corrosion.Client) *Coordinator {
	return &Coordinator{
		hostName:       hostName,
		db:             db,
		fencer:         fence.Execute,
		fenced:         make(map[string]bool),
		fenceRelocated: make(map[string]bool),
		Now:            func() time.Time { return time.Now() },
	}
}

// SetFencer replaces the fence implementation. Test-only; production code
// should not use this.
func (c *Coordinator) SetFencer(f Fencer) { c.fencer = f }

// SetCapacityPolicy wires the cluster-wide capacity policy.
func (c *Coordinator) SetCapacityPolicy(p corrosion.CapacityPolicy) { c.capacity = p }

// buildFailoverPlacementRequest constructs a placement request for a VM being
// rescheduled off failedHost, honoring the constraints in its stored spec.
// A spec pin to the failed host itself is dropped — the whole point is to leave.
func buildFailoverPlacementRequest(vm corrosion.VMRecord, failedHost string, capacity corrosion.CapacityPolicy) placement.Request {
	req := placement.Request{
		VMName:       vm.Name,
		CPUNeeded:    vm.CPUActual,
		MemMiBNeeded: vm.MemActual,
		Capacity:     capacity,
	}
	if vm.Spec == "" {
		return req
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(vm.Spec), spec) != nil || spec.Placement == nil {
		return req
	}
	p := spec.Placement
	if p.Host != "" && p.Host != failedHost {
		req.PinHost = p.Host
	}
	req.AntiAffinity = p.AntiAffinity
	req.Affinity = p.Affinity
	req.RequireLabels = p.Require
	req.PreferLabels = p.Prefer
	req.Spread = p.Spread
	if p.MaxPerNode > 0 {
		req.MaxPerNode = int(p.MaxPerNode)
	}
	return req
}

// now is the coordinator's clock — defaults to time.Now, overridable
// for virtual-time scenarios via the exported Now field.
func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func ownerEpochString(epoch int64) string {
	return strconv.FormatInt(epoch, 10)
}

// Start runs the coordinator loop. Blocks until ctx is cancelled.
func (c *Coordinator) Start(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.run(ctx)
		}
	}
}

// RunOnce executes a single coordinator cycle and returns. Exposed for
// cross-package integration tests in tests/cluster/. Production code uses
// Start which loops on the poll ticker.
func (c *Coordinator) RunOnce(ctx context.Context) { c.run(ctx) }

func (c *Coordinator) run(ctx context.Context) {
	// Self-fence is a HARD local gate: a doomed node (waiting for the watchdog to reboot
	// it) must not drive any failover decision during the live-but-doomed window, even if
	// it briefly reacquires quorum/lease. Checked before the lease so a fenced node also
	// stops renewing coordinator leadership.
	if c.selfFenced() {
		c.mAttempt(PhaseSkip, ResultSkipped, ErrSelfFenced)
		c.stepDownGauges()
		return
	}
	// Leader election: only one coordinator may drive recovery at a time.
	// Acquire (or renew) the lease; if another coordinator holds it, skip.
	if !c.acquireLease(ctx) {
		c.stepDownGauges()
		return
	}

	// Count *live* hosts for quorum: hosts we have recent health from. This
	// shrinks the denominator on the minority side of a partition so quorum
	// stays above the partitioned-observer count.
	liveHosts, err := c.countLiveHosts(ctx)
	if err != nil {
		slog.Error("failover: count live hosts", "error", err)
		c.mAttempt(PhaseQuorum, ResultError, ErrDBError)
		return
	}
	if liveHosts < 1 {
		c.mAttempt(PhaseQuorum, ResultSkipped, ErrNoQuorum)
		return
	}
	quorum := liveHosts/2 + 1

	// Clear the "already handled this down-episode" flag for any host that has
	// recovered to active. Without this, the in-memory fenced set — which is
	// also set by the offline/terminal-state skip below, not just by an actual
	// fence — permanently suppressed re-fencing a host that went down, recovered,
	// then failed again, for the life of the coordinator process. (The skip is
	// silent, so this manifested as the coordinator quietly never fencing.)
	c.clearRecoveredFromFenced(ctx)

	// Find hosts where enough *fresh* observers agree the target has exceeded
	// the failure threshold. The freshness predicate prevents stale rows from
	// dead observers from satisfying quorum.
	//
	// Freshness is filtered in GO via corrosion.ParseUpdatedAt, NOT a SQL
	// `updated_at > cutoff` string compare: updated_at is the LWW key, which becomes
	// an HLC string ("<physms>-…") once hlc_lww is enabled, and a lexical/text compare
	// can't span the RFC3339 and HLC forms (an HLC row would sort below an RFC3339
	// cutoff and read as permanently stale — silently killing fencing quorum). Both
	// forms decode to a wall instant, so the DISTINCT-observer-per-target quorum
	// aggregation is done here too. An unparseable/stale row simply doesn't count.
	freshCutoff := c.now().Add(-healthFreshness)
	hh, err := c.db.Query(ctx,
		`SELECT target, observer, updated_at
		 FROM host_health
		 WHERE target != ?
		   AND consecutive_failures >= ?`,
		c.hostName, offlineThreshold)
	if err != nil {
		slog.Error("failover: query host_health", "error", err)
		c.mAttempt(PhaseHealth, ResultError, ErrDBError)
		return
	}
	freshObservers := map[string]map[string]struct{}{}
	for _, r := range hh {
		inst, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !inst.After(freshCutoff) {
			continue // stale or unparseable → does not count toward quorum
		}
		t := r.String("target")
		if freshObservers[t] == nil {
			freshObservers[t] = map[string]struct{}{}
		}
		freshObservers[t][r.String("observer")] = struct{}{}
	}
	type fenceCandidate struct {
		target    string
		observers int
	}
	var candidates []fenceCandidate
	for t, obs := range freshObservers {
		if len(obs) >= quorum {
			candidates = append(candidates, fenceCandidate{t, len(obs)})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].target < candidates[j].target })

	for _, cand := range candidates {
		// Re-validate lease before each destructive action: long fence runs
		// (IPMI verify up to 15 s) can outlast the lease without renewal.
		if !c.holdLease(ctx) {
			slog.Warn("failover: lease lost mid-cycle, aborting", "host", c.hostName)
			c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
			// Losing the lease is a step-down: the node that takes it owns the
			// fleet's view from here.
			c.stepDownGauges()
			return
		}

		target := cand.target
		if c.fenced[target] {
			continue
		}

		// Skip if this host is already in a terminal state.
		h, err := corrosion.GetHost(ctx, c.db, target)
		if err != nil {
			// A store error here silently drops a fence candidate; surface it.
			slog.Warn("failover: resolve target host failed, skipping", "host", target, "error", err)
			c.mAttempt(PhaseHealth, ResultError, ErrDBError)
			continue
		}
		if h == nil {
			continue // unknown host (e.g. raced delete) — quiet skip
		}
		if h.State == "offline" || h.State == "maintenance" || h.State == "fenced" {
			c.fenced[target] = true
			c.mAttempt(PhaseSkip, ResultSkipped, ErrTerminalState)
			continue
		}
		// Skip hosts that are intentionally restarting (a self-upgrade, or a
		// graceful daemon restart that marked itself 'upgrading' on SIGTERM).
		// They're unreachable for tens of seconds; quorum agreeing they're
		// "down" is normal — fencing them turns a routine restart into a
		// destructive false-positive failover. BUT a host that entered
		// 'upgrading' and never returned must still fail over, or its VMs are
		// stranded — so we only skip while it's within upgradingTimeout. On a
		// timestamp parse error we err on the safe side and keep skipping.
		if h.State == "upgrading" {
			upd, ok := corrosion.ParseUpdatedAt(h.UpdatedAt)
			if !ok || c.now().Sub(upd) < upgradingTimeout {
				slog.Info("failover: target is upgrading, skipping fence", "host", target)
				c.mAttempt(PhaseSkip, ResultSkipped, ErrUpgrading)
				continue
			}
			slog.Warn("failover: host stuck 'upgrading' past timeout — treating as failed",
				"host", target, "upgrading_since", h.UpdatedAt)
			// fall through to fence
		}

		// Skip if fencing_log shows a recent successful fence — no double-fencing
		// across coordinator restarts or process race windows.
		if c.recentlyFenced(ctx, target) {
			slog.Info("failover: host has recent fence record, skipping", "host", target)
			c.fenced[target] = true
			c.mAttempt(PhaseSkip, ResultSkipped, ErrRecentlyFenced)
			continue
		}

		slog.Warn("failover: quorum reached — host exceeded failure threshold",
			"host", target, "observers", cand.observers, "quorum", quorum)

		c.failover(ctx, h)
	}

	// Recovery pass: bring a host the coordinator marked down (offline, or a
	// spurious no-VMs-moved fence) back to 'active' once a fresh quorum agrees
	// it's healthy again. A transient drop (a daemon restart, a brief blip) must
	// self-heal — otherwise health reconverges in seconds but hosts.state sticks.
	c.recoverHosts(ctx, quorum)

	// Settle any relocate-restore markers left by an indeterminate restore or a
	// coordinator crash mid-restore. This runs every cycle, independent of the
	// fence path (an already-fenced host is skipped above, so relocateContainers
	// won't re-run for it) — so a deferred restore still gets resolved.
	c.resolvePendingRelocations(ctx)

	// Report workloads left on a host the cluster considers down. Read-only: see
	// strandedWorkloads for what the number does and does not mean, and for why
	// this reports rather than recovers. Runs after recoverHosts and
	// resolvePendingRelocations so a host or marker settled THIS cycle is already
	// out of the count.
	if n, err := c.strandedWorkloads(ctx); err != nil {
		// Leave the gauge holding its last measured value: publishing 0 here
		// would clear an operator's alert using a number we failed to read.
		slog.Error("failover: count stranded workloads", "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
	} else {
		c.mStranded(n)
	}
}

// stepDownGauges clears the gauges this node owns when it is NOT driving
// failover — self-fenced, or not the lease holder. Every node runs a coordinator
// and every node serves /metrics, so without this a demoted leader pins its last
// value forever (Prometheus gauges retain) and pages the fleet after the
// condition heals, while every node that never held the lease publishes a
// permanent 0 that hides a real one. Same contract as stepDownDualRun: the
// leader's view is the fleet's view, and the rest keep their series clear.
//
// Nothing durable is lost by clearing. strandedWorkloads holds no state between
// cycles — it re-derives the count from hosts/vms/containers — so the new
// leader's first pass republishes the true value within one poll interval.
func (c *Coordinator) stepDownGauges() { c.mStranded(0) }

// resolvePendingRelocations re-derives every relocate-restore marker in the
// cluster (a container left "relocating" by an indeterminate restore or a crash),
// independent of the fence cycle. Leader-gated by run's lease.
func (c *Coordinator) resolvePendingRelocations(ctx context.Context) {
	// Decide-site gate (Phase 1): resuming a relocate-restore re-keys the container row —
	// imageRecreateOrSkip re-homes it and completeRestore tombstones the SOURCE — which is
	// a runtime-ownership DECISION. run()'s failover lease alone is insufficient: a CRDT
	// lease can be "held" on both sides of a partition, so a minority leader with a latched
	// gate could re-home the row to a minority target and tombstone the source without
	// quorum, manufacturing the two-row split Phase 6 exists to repair (execution on the
	// target is still ExecutionGate-blocked, so no double-run — but the DB ownership
	// diverges). Once enforced, require DecisionGate (quorum + coordinator-eligible).
	if c.gateEnforced(ctx) {
		if g := c.Gate.DecisionGate(ctx); !g.OK {
			c.noteGateRefused(ActionRelocate, g.Reason)
			return
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, "")
	if err != nil {
		return
	}
	for _, ct := range cts {
		target, token, restoring := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail)
		if !restoring {
			continue
		}
		src, err := corrosion.GetHost(ctx, c.db, ct.HostName)
		if err != nil || src == nil {
			continue
		}
		// candidates are only consulted if the marker carries no target
		// (it always does), so an empty candidate set is fine here.
		c.resumeRestoreRelocation(ctx, src, ct, target, token, nil)
	}
}

// recoverHosts promotes a host the coordinator marked down back to 'active'
// once a fresh quorum of observers reports it healthy (consecutive_failures = 0).
// Without this, a host that briefly dropped (a daemon restart, a transient blip,
// or a spurious fence) never returns to active on its own — health reconverges
// in seconds but the authoritative hosts.state stays stuck.
//
//   - 'offline' (a best-effort / unconfirmed fence — no successful fence, so no
//     VMs were rescheduled): recovered whenever healthy.
//   - 'fenced' (a SUCCESSFUL fence): recovered ONLY if THIS coordinator did the
//     fence AND it relocated no VMs (fenceRelocated == false). A fence that moved
//     VMs — or one this coordinator has no record of (e.g. a prior leader) —
//     stays manual (`lv host undrain`), so we never resurrect a host into a
//     split-brain where a moved VM runs in two places.
//   - 'maintenance'/'draining': operator intent, never auto-cleared.
func (c *Coordinator) recoverHosts(ctx context.Context, quorum int) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("failover: list hosts for recovery", "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return
	}
	freshCutoff := c.now().Add(-healthFreshness)
	for _, h := range hosts {
		switch h.State {
		case "offline":
			if c.recentlyFenced(ctx, h.Name) {
				continue // a real fence happened — treat like 'fenced'
			}
		case "fenced":
			reloc, fencedByMe := c.fenceRelocated[h.Name]
			if !fencedByMe || reloc {
				continue // not ours to clear, or VMs moved → manual undrain only
			}
		default:
			continue
		}

		// Freshness filtered in Go (both-format updated_at); see the fence-quorum
		// query above for why a SQL string compare can't span RFC3339 + HLC.
		rows, err := c.db.Query(ctx,
			`SELECT observer, updated_at
			 FROM host_health
			 WHERE target = ?
			   AND consecutive_failures = 0`,
			h.Name)
		if err != nil {
			// A query error would otherwise be indistinguishable from "not enough
			// healthy observers" and silently suppress recovery.
			slog.Warn("failover: recovery quorum query failed", "host", h.Name, "error", err)
			c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
			continue
		}
		fresh := map[string]struct{}{}
		for _, r := range rows {
			if inst, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && inst.After(freshCutoff) {
				fresh[r.String("observer")] = struct{}{}
			}
		}
		if len(fresh) < quorum {
			continue // not enough fresh healthy observers to recover
		}
		if err := corrosion.UpdateHostState(ctx, c.db, h.Name, "active"); err != nil {
			slog.Error("failover: recover host", "host", h.Name, "state", h.State, "error", err)
			c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
			continue
		}
		slog.Info("failover: host healthy again, marking active",
			"host", h.Name, "from", h.State, "healthy_observers", rows[0].Int("n"), "quorum", quorum)
		c.mAttempt(PhaseRecovery, ResultRecovered, errClassNone)
		delete(c.fenced, h.Name)
		delete(c.fenceRelocated, h.Name)
	}
}

// clearRecoveredFromFenced drops hosts that are back to "active" from the
// in-memory fenced set. The set is meant to mean "already handled this
// down-episode"; it is set both by an actual fence AND by the terminal-state
// skip in run(). Because it was never cleared on recovery, a host that went
// down, recovered, then failed again was silently skipped forever (until the
// coordinator process restarted). Clearing recovered hosts each cycle restores
// re-fencing.
func (c *Coordinator) clearRecoveredFromFenced(ctx context.Context) {
	for host := range c.fenced {
		if h, err := corrosion.GetHost(ctx, c.db, host); err == nil && h != nil && h.State == "active" {
			delete(c.fenced, host)
			delete(c.fenceRelocated, host)
		}
	}
}

// acquireLease tries to take or renew the failover-leader lease. Returns true
// if this coordinator holds the lease for at least leaseRenewBefore.
//
// The CRDT row store cannot offer linearisable CAS across partitions, so this
// is best-effort. We mitigate races by:
//  1. Updating only when the existing row is expired or already held by us.
//  2. Validating that precondition INSIDE the write transaction (the shared
//     helper's guard), so acquisition needs no post-write read; the renewal
//     path still reads back and refuses if the holder changed.
//  3. Re-validating before every destructive call (holdLease).
//  4. Renewing well before expiry (leaseRenewBefore head-room).
//
// The guarded upsert, its read-back, and the same-day expiry-compare fix now
// live in corrosion.AcquireLeaseWithTerm, shared with the rebalancer and the
// dual-run detector. leaseDuration and c.now() stay this coordinator's own:
// c.now() is the virtual clock the fleet harness overrides, and passing
// time.Now() instead would make its scenarios unable to advance past lease
// expiry without sleeping.
func (c *Coordinator) acquireLease(ctx context.Context) bool {
	held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, c.db, failoverLeaseKey, c.hostName, leaseDuration, c.now())
	if err != nil {
		// Covers both former error outcomes — the write failing and the
		// read-back failing — which reported this same metric triple.
		slog.Error("failover: lease write", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.leaseTerm.Store(0)
		return false
	}
	if !held {
		// Another coordinator holds it — the normal non-leader case.
		c.leaseTerm.Store(0)
		c.mAttempt(PhaseLease, ResultSkipped, ErrNotLeader)
		return false
	}
	c.leaseTerm.Store(term)
	c.mAttempt(PhaseLease, ResultOK, errClassNone)
	return true
}

// LeaseTerm is the fencing term of the lease incarnation this coordinator holds,
// 0 when it holds none. Exported for the Phase-2 enforcement path and for tests;
// nothing enforces on it yet.
func (c *Coordinator) LeaseTerm() int64 { return c.leaseTerm.Load() }

// holdLease re-validates that we still hold the failover lease and that the
// remaining TTL is at least leaseRenewBefore. Renews if low. Returns false if
// the lease is lost or read fails.
// Every false return here CLEARS leaseTerm. holdLease is this coordinator's
// displacement detector — it is called per fence candidate and again immediately
// before the destructive call — so it is the one path that most needs to stop
// reporting a token this node has demonstrably lost. It did not clear it, so a
// coordinator displaced mid-cycle kept answering with its old term for up to a
// poll interval, including at the pre-fence check. acquireLease cleared on every
// loss path, which made the asymmetry easy to miss.
func (c *Coordinator) holdLease(ctx context.Context) bool {
	_, ok := c.holdLeaseAtLeast(ctx, leaseRenewBefore)
	return ok
}

// holdLeaseAtLeast re-validates the failover lease and guarantees strictly more
// than `need` remaining on it, renewing when the margin is short. It returns
// the remaining TTL so a caller can bound a long operation by the authority it
// actually holds rather than by a hardcoded guess.
//
// A renewal that still cannot reach `need` is a refusal, not a success: it
// means this node no longer holds enough of the lease to finish the work
// safely, and proceeding would be acting past its own authority.
func (c *Coordinator) holdLeaseAtLeast(ctx context.Context, need time.Duration) (time.Duration, bool) {
	left, ok := c.leaseRemaining(ctx)
	if !ok {
		return 0, false
	}
	if left > need {
		return left, true
	}
	if !c.acquireLease(ctx) {
		return 0, false
	}
	left, ok = c.leaseRemaining(ctx)
	if !ok || left <= need {
		return 0, false
	}
	return left, true
}

// leaseRemaining reports how much of the failover lease this node still holds.
// It returns ok=false when the row is missing or unreadable, when the holder is
// someone else, or when expires_at cannot be parsed — every case in which this
// node cannot prove it is the leader.
//
// Every ok=false return CLEARS leaseTerm. This is the coordinator's
// displacement detector — holdLease reaches it per fence candidate and again
// immediately before the destructive call — so it is the one path that most
// needs to stop reporting a token this node has demonstrably lost. It did not
// clear it, so a coordinator displaced mid-cycle kept answering with its old
// term for up to a poll interval, including at the pre-fence check.
// acquireLease cleared on every loss path, which made the asymmetry easy to
// miss.
//
// Both callers inherit that: holdLease and the fence-bounding
// holdLeaseAtLeast read the lease through here and nowhere else.
func (c *Coordinator) leaseRemaining(ctx context.Context) (time.Duration, bool) {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil {
		slog.Error("failover: lease read", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.leaseTerm.Store(0)
		return 0, false
	}
	if len(rows) == 0 {
		// The lease row is absent while this coordinator believes it may hold
		// it. Nothing in the tree ever DELETEs a leader_election row, so this is
		// local corruption or truncation, not the ordinary non-leader case — it
		// must stay distinguishable from the skip that fires on N-1 nodes every
		// poll, and must keep tripping the result="error" alert.
		slog.Warn("failover: lease row missing")
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.leaseTerm.Store(0)
		return 0, false
	}
	if rows[0].String("holder") != c.hostName {
		c.leaseTerm.Store(0)
		return 0, false
	}
	expiresAt, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		slog.Error("failover: lease expiry unparseable", "value", rows[0].String("expires_at"))
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.leaseTerm.Store(0)
		return 0, false
	}
	return expiresAt.Sub(c.now()), true
}

// leaseTermEnforced reports whether this coordinator refuses to stamp on the
// strength of its lease term: the config flag AND the cluster-wide latch, the
// same `flag && Enforced` model as the rest of this family.
//
// Both halves are load-bearing, and the latch half especially. An operator sets
// enforcement.lease_term ahead of the latch during a roll — that is the intended
// order — and pre-latch a perfectly healthy leader holds term 0, because the
// ledger mint gate is still closed and AcquireLeaseWithTerm deliberately reports
// no term. Enforcing on the flag alone would therefore stand this coordinator
// down from every action it drives, on every node, for the whole rollout, while
// the executor (which gates on the same latch) went on accepting term-0 proofs.
// All cost, no safety.
func (c *Coordinator) leaseTermEnforced(ctx context.Context) bool {
	return c.LeaseTermEnforce && c.Gate != nil && c.Gate.Enforced(ctx, capabilities.LeaseTermV1)
}

// leaseTermStampAllowed reports whether this coordinator may stamp a proof with
// its recorded term.
//
// The term is c.LeaseTerm() — the incarnation this coordinator actually acquired
// — and NEVER a fresh ledger read. Deriving it here would let a displaced holder
// that has received the winner's term row stamp proofs with the winner's term,
// the privilege escalation Phase 1 closed. The ledger read below is the
// THRESHOLD, used only to reject, never to adopt.
func (c *Coordinator) leaseTermStampAllowed(ctx context.Context) bool {
	if !c.leaseTermEnforced(ctx) {
		// Nothing to check: pre-latch there is no term to be stale, and with the
		// flag off the operator has taken enforcement off this node deliberately.
		// Stamp whatever term we hold — 0 pre-latch — so the term is observable
		// before the flip rather than appearing for the first time with it.
		return true
	}
	term := c.LeaseTerm()
	if term <= 0 {
		// Enforcing, so the ledger has latched and a real holder has a real term.
		// No term here means this coordinator holds no lease incarnation — never
		// acquired one, or holdLease cleared it on a loss path — and acting as
		// leader without one produces exactly the unfenced write the term exists
		// to prevent.
		c.mAttempt(PhaseLease, ResultSkipped, ErrLeaseLost)
		return false
	}
	threshold, err := corrosion.CurrentLeaseTerm(ctx, c.db, failoverLeaseKey)
	if err != nil {
		// FAIL OPEN, deliberately, and this is the one place in the family that
		// does. Every caller is past the fence: the host is powered off and its
		// row is persisted offline, and a fenced host is processed only once, so
		// refusing here does not defer the work — it abandons it, and the
		// workload stays assigned to a dead host until an operator intervenes.
		//
		// Weigh that against what refusing buys. This precheck is an
		// optimisation; the executor's quorum barrier is the guarantee and runs
		// regardless. An unreadable threshold is no evidence we are superseded —
		// the overwhelmingly likely cause is a transient DB error on a
		// coordinator whose term is perfectly current — so stamping produces a
		// valid proof the executor accepts, and in the rare case we ARE stale the
		// barrier refuses it exactly as designed. Fail-closed here trades a
		// guaranteed stranded workload for a check that was never the guarantee.
		//
		// The error is still counted, so a threshold read that fails persistently
		// is visible rather than silently permissive.
		slog.Error("failover: read lease term threshold — stamping anyway (precheck fails open)",
			"error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		return true
	}
	if term < threshold {
		slog.Warn("failover: this coordinator's lease term is superseded — refusing to stamp",
			"term", term, "threshold", threshold)
		c.mAttempt(PhaseLease, ResultSkipped, ErrStaleLeaseTerm)
		return false
	}
	return true
}

// leaseStamp returns everything a proof records about this coordinator's tenure:
// the holder and expiry read from the lease row, and the fencing term from
// c.LeaseTerm(). ok is false when this coordinator must not stamp at all, and the
// caller must abandon the action rather than stamp a partial record.
//
// All three stamp sites go through this, and that is the point of it existing.
// The term is RETURNED rather than read at each site, so a site cannot silently
// omit it. And the holder comes from the lease row, not from c.hostName: two of
// the three sites previously wrote their own identity into LeaseHolder, which
// asserts "I hold the lease" on the authority of the process making the claim —
// precisely the assertion the fencing term exists to stop trusting. leaseSnapshot
// returns empty on a read error, so this field can be blank on a perfectly valid
// proof; blank is correct and self-reporting was a fabrication.
func (c *Coordinator) leaseStamp(ctx context.Context) (holder, expiresAt string, term int64, ok bool) {
	if !c.leaseTermStampAllowed(ctx) {
		return "", "", 0, false
	}
	holder, expiresAt = c.leaseSnapshot(ctx)
	return holder, expiresAt, c.LeaseTerm(), true
}

// leaseSnapshot returns the current failover-lease holder + expiry to record in a
// proof, as the human-readable record of the tenure.
//
// It is NOT the proof's enforceable token: that is ActionProof.LeaseTerm, which
// comes from c.LeaseTerm() via leaseStamp. This snapshot deliberately returns
// empty on a read error — an honesty record must not FABRICATE a holder — so it
// can be blank on a perfectly valid proof, which is exactly why the executor's
// equal-term check compares against Coordinator rather than LeaseHolder.
func (c *Coordinator) leaseSnapshot(ctx context.Context) (holder, expiresAt string) {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil || len(rows) == 0 {
		// An honesty record must not FABRICATE a holder on a read error — reporting self
		// would falsely assert this node held the lease. Return empty (unknown).
		return "", ""
	}
	return rows[0].String("holder"), rows[0].String("expires_at")
}

// recentlyFenced returns true if the fencing_log shows a successful fence for
// host within the recentFenceWindow. Prevents re-fence after restart or race.
func (c *Coordinator) recentlyFenced(ctx context.Context, host string) bool {
	return c.fenceWithinWindow(ctx, host, false)
}

// manualFenceConfirmed returns true if an operator has written a
// "manual-confirmed" row in fencing_log for this host within the recent
// fence window. The CLI command `lv host fence-confirm <host>` writes this
// row after the operator has physically powered the host off.
func (c *Coordinator) manualFenceConfirmed(ctx context.Context, host string) bool {
	return c.fenceWithinWindow(ctx, host, true)
}

// safeFenceRequiresProof reports whether a FAILED best-effort fence of h must be
// confirmed (like "manual") before rescheduling. True only when the safe-fence
// policy (SafeFenceDefaultV1) is enforced cluster-wide AND the host has not opted
// into the legacy proceed-anyway behavior via LabelUnsafeAutoFailover. Pre-flip
// (token not enforced) it is false, preserving today's behavior for a
// mixed-version roll. A nil Gate (tests without the split-brain gate wired) is
// also false — the policy is a strict addition on top of the gate.
func (c *Coordinator) safeFenceRequiresProof(ctx context.Context, h *corrosion.HostRecord) bool {
	// Config kill-switch (default false, zero value = legacy) AND the cluster-wide
	// capability latch. The flag short-circuits the latch, so it can be disabled
	// without a redeploy or marker deletion.
	if !c.SafeFenceEnforce || c.Gate == nil || !c.Gate.Enforced(ctx, capabilities.SafeFenceDefaultV1) {
		return false
	}
	return h == nil || h.Labels[corrosion.LabelUnsafeAutoFailover] != "true"
}

// sharedStorageFenceEnforced reports whether this coordinator enforces the
// shared-disk ownership-transfer fence gate: the config kill-switch AND the
// SharedStorageFenceV1 cluster-wide latch. Mirrors safeFenceRequiresProof's
// flag-short-circuits-latch model — a nil Gate (tests) is not enforcing.
func (c *Coordinator) sharedStorageFenceEnforced(ctx context.Context) bool {
	return c.SharedStorageFenceEnforce && c.Gate != nil && c.Gate.Enforced(ctx, capabilities.SharedStorageFenceV1)
}

// fenceWithinWindow reports whether host has a fencing_log row with an accepted
// result newer than now-recentFenceWindow. manualOnly restricts the accepted
// result to "manual-confirmed".
//
// The recency comparison is done in Go, NOT in SQL. fencing_log.timestamp is
// RFC3339 ("2026-06-08T11:52:15Z"); comparing it against datetime('now', …)
// (which yields space-separated text) is a string compare that breaks once the
// date matches — 'T' (0x54) sorts above ' ' (0x20) — so a same-day prior fence
// looks "recent" forever and the host is never re-fenced. SQLite's datetime()
// normalization of the Z suffix also differs between the CLI and the pure-Go
// (modernc) engine the daemon links, so neither SQL form is reliable here.
func (c *Coordinator) fenceWithinWindow(ctx context.Context, host string, manualOnly bool) bool {
	rows, err := c.db.Query(ctx,
		`SELECT result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		// Fail open (treat as no recent fence) but make the read error visible —
		// it affects both recent-fence suppression and manual confirmation.
		slog.Warn("failover: fencing_log read failed, treating as no recent fence", "host", host, "error", err)
		c.mAttempt(PhaseHealth, ResultError, ErrDBError)
		return false
	}
	cutoff := c.now().Add(-recentFenceWindow)
	for _, r := range rows {
		switch result := r.String("result"); {
		case manualOnly && result != "manual-confirmed":
			continue
		case !manualOnly && result != "fenced" && result != "manual-confirmed":
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		if ts.After(cutoff) {
			return true
		}
	}
	return false
}

// proofGradeFenceRef returns the fence_epoch binding for the newest PROOF-GRADE
// fence of host within recentFenceWindow, or "" when none exists (a best-effort /
// SSH fence, or no fence yet). A shared-disk cross-host transfer executor re-reads
// FenceID from fencing_log and re-verifies it (never a stale hosts.state). The
// recency filter mirrors fenceWithinWindow (Go-side, RFC3339). An IPMI fence
// finds the row this cycle just inserted; a manual fence finds the operator's
// "manual-confirmed" row (the fence-time "manual"/"partial" row is not proof-grade).
func (c *Coordinator) proofGradeFenceRef(ctx context.Context, host string) string {
	rows, err := c.db.Query(ctx,
		`SELECT id, method, result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		slog.Warn("failover: fencing_log read for fence_epoch failed", "host", host, "error", err)
		return ""
	}
	cutoff := c.now().Add(-recentFenceWindow)
	var best time.Time
	var bestRef corrosion.FenceEpochRef
	for _, r := range rows {
		if !corrosion.FenceProofGrade(r.String("method"), r.String("result")) {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil || !ts.After(cutoff) {
			continue
		}
		if bestRef.FenceID == "" || ts.After(best) {
			best = ts
			bestRef = corrosion.FenceEpochRef{Host: host, FenceID: r.String("id"), TS: r.String("timestamp")}
		}
	}
	return bestRef.String()
}

// autoPromoteEnabled reports whether vmName has a replication schedule with
// auto_promote set. Best-effort: a query error returns false (fall back to a
// bare reschedule rather than risk an unwanted promotion).
func (c *Coordinator) autoPromoteEnabled(ctx context.Context, vmName string) bool {
	rows, err := corrosion.ListBackupSchedules(ctx, c.db)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if r.Type == "replication" && r.AutoPromote && r.VMName == vmName {
			return true
		}
	}
	return false
}

// countLiveHosts returns the number of hosts whose state is neither offline,
// maintenance, nor fenced (all of which are terminal for failover purposes).
//
// Partition tolerance is provided by the *observer-count* gate in the quorum
// query, not by tightening this denominator: if the minority side has too few
// observers to satisfy `observer_count >= floor(N/2)+1`, it cannot fence even
// though it computes the same N. Tightening this further (e.g. requiring
// fresh self-probes) creates a bootstrap hole where a just-started coordinator
// has no probe rows yet and refuses to act on any failure.
func (c *Coordinator) countLiveHosts(ctx context.Context) (int, error) {
	rows, err := c.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM hosts
		 WHERE state NOT IN ('offline', 'maintenance', 'fenced')
		   AND deleted_at IS NULL`)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("cnt"), nil
}

// failover fences the host and reschedules its VMs.
func (c *Coordinator) failover(ctx context.Context, h *corrosion.HostRecord) {
	// Named span for the fence+reschedule sequence; the fence RPC and the
	// per-VM peer relocations hang off it, so an auto-failover is one connected
	// trace across the coordinator and the target hosts. No-op when tracing off.
	ctx, span := obs.Span(ctx, "failover.host")
	span.SetAttribute("host.name", h.Name)
	defer span.End()

	c.fenced[h.Name] = true
	// Track whether this fence actually relocates any VM. A fence that moves
	// nothing (e.g. a spurious fence of a host whose VMs all stayed put) is safe
	// to auto-recover later; one that relocated VMs must stay manual to avoid
	// split-brain. See recoverHosts.
	c.fenceRelocated[h.Name] = false

	// Re-validate the lease immediately before the destructive fence call, and
	// require enough of it left to FINISH that call. Checking only that the
	// lease is currently held is not sufficient: a fence run (IPMI verify alone
	// is up to 15 s) can outlast the remaining TTL, and once the row expires a
	// second coordinator can take the lease and start fencing the same host
	// while this call is still in flight.
	leaseLeft, ok := c.holdLeaseAtLeast(ctx, minFenceLease)
	if !ok {
		slog.Warn("failover: lease lost or too short to fence, aborting",
			"host", h.Name, "required", minFenceLease)
		c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
		return
	}

	// Bound the fence by the lease that authorises it. The deadline is derived
	// from the time this node actually holds, less a margin so the call returns
	// while it is still the leader — not from a constant that could quietly
	// exceed the lease if either value is ever retuned.
	fenceCtx, cancelFence := context.WithTimeout(ctx, leaseLeft-leaseFenceMargin)
	defer cancelFence()

	// Step 1: Fence the host.
	fr := c.fencer(fenceCtx, fence.HostConfig{
		Name:          h.Name,
		Address:       h.Address,
		SSHUser:       h.SSHUser,
		SSHPort:       h.SSHPort,
		FenceStrategy: h.FenceStrategy,
		IPMIAddress:   h.IPMIAddress,
		IPMIUser:      h.IPMIUser,
		IPMIPass:      h.IPMIPass,
		WatchdogDev:   h.WatchdogDev,
	})

	logResult := "fenced"
	if !fr.Success {
		logResult = "partial"
		c.mAttempt(PhaseFence, ResultPartial, ErrFenceFailed)
	} else {
		c.mAttempt(PhaseFence, ResultSuccess, errClassNone)
	}

	// Record fence event. Failure to log is a real problem — we are about to
	// reschedule VMs based on a fence that has no audit trail.
	if err := corrosion.InsertFenceLog(ctx, c.db, corrosion.FenceLogRecord{
		ID:       randid.New(),
		HostName: h.Name,
		Method:   fr.Method,
		Result:   logResult,
		Detail:   fr.Detail,
	}); err != nil {
		slog.Error("failover: write fence_log", "host", h.Name, "error", err)
		// Observable but intentionally non-blocking: the fence physically
		// happened; a lost audit row must not strand the VMs (no return here).
		c.mAttempt(PhaseFence, ResultError, ErrFenceLogWrite)
	}

	if c.OnFence != nil {
		c.OnFence(h.Name, fr.Method, logResult, fr.Detail)
	}

	// The fence is recorded; confirm this node is still the leader before acting
	// on it. If the lease expired while the fence ran, another coordinator may
	// already be driving this host's recovery, and continuing would mean two
	// coordinators rescheduling the same VMs. Deliberately placed AFTER the
	// fence log and OnFence: those record a physical act that did happen and
	// must survive regardless of who holds the lease now. What stops here is
	// everything that ASSERTS authority — the host state write and the
	// reschedule below.
	if !c.holdLease(ctx) {
		slog.Warn("failover: lease lost during fence, not rescheduling", "host", h.Name)
		c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
		return
	}

	// Step 2: Mark host as fenced (fr.Success) or offline (best-effort/manual
	// proceeding without confirmation). The "fenced" state is distinct from
	// "offline" so the coordinator's recentlyFenced check can suppress repeats
	// and the UI can surface the dangerous condition.
	newState := "offline"
	if fr.Success && fr.Method != "manual" {
		newState = "fenced"
	}
	if err := corrosion.UpdateHostState(ctx, c.db, h.Name, newState); err != nil {
		slog.Error("failover: mark host state", "host", h.Name, "state", newState, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
	}

	// Safe-fence default (gated by SafeFenceDefaultV1). A best-effort fence is
	// fire-and-forget SSH: it reports Success=true even when the poweroff never
	// landed (fence.fenceSSH lenient mode), so it can NEVER confirm the host is
	// actually down. This check must therefore run BEFORE the !fr.Success guard
	// below — a lenient best-effort success would otherwise sail straight through
	// to reschedule. Once the policy is enforced cluster-wide, a best-effort fence
	// is treated like "manual": reschedule only with an operator fence-confirm,
	// unless the host explicitly opts into legacy proceed-anyway. Pre-flip (token
	// not enforced) this is a no-op, so a mixed-version roll keeps today's behavior.
	if fence.ResolveStrategy(h.FenceStrategy) == "best-effort" && c.safeFenceRequiresProof(ctx, h) {
		if !c.manualFenceConfirmed(ctx, h.Name) {
			slog.Error("failover: best-effort fence unconfirmed under safe-fence policy, NOT rescheduling",
				"host", h.Name, "detail", fr.Detail,
				"hint", "run 'lv host fence-confirm "+h.Name+"' once the host is powered off, "+
					"or set host label "+corrosion.LabelUnsafeAutoFailover+"=true to opt into legacy proceed-anyway")
			c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
			return
		}
		slog.Info("failover: operator confirmed best-effort fence, proceeding", "host", h.Name)
		c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
	}

	// Split-brain guard. Reschedule only if:
	//   - fence succeeded (real fence happened), OR
	//   - strategy is "best-effort" (operator opted out of safety — a lenient SSH
	//     fence reports Success=true, so this switch is skipped; the safe-fence
	//     policy above is what gates it), OR
	//   - strategy is "manual" AND an operator confirmation row exists.
	// Manual fence used to claim Success=true unconditionally; it now reports
	// Success=false and the coordinator must see an explicit confirmation row
	// in fencing_log (written by `lv host fence-confirm`) before rescheduling.
	if !fr.Success {
		switch h.FenceStrategy {
		case "best-effort":
			slog.Warn("failover: best-effort fence did not fully succeed, proceeding anyway",
				"host", h.Name, "detail", fr.Detail)
			c.mAttempt(PhaseSplitBrain, ResultOK, ErrBestEffort)
		case "manual":
			if !c.manualFenceConfirmed(ctx, h.Name) {
				slog.Error("failover: manual fence not confirmed by operator, NOT rescheduling",
					"host", h.Name, "detail", fr.Detail,
					"hint", "run 'lv host fence-confirm "+h.Name+"' once the host is powered off")
				c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
				return
			}
			slog.Info("failover: operator confirmed manual fence, proceeding",
				"host", h.Name)
			c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
		default:
			slog.Error("failover: CRITICAL — fencing failed, NOT rescheduling VMs to prevent split-brain",
				"host", h.Name, "strategy", h.FenceStrategy, "detail", fr.Detail)
			c.mAttempt(PhaseSplitBrain, ResultRefused, ErrFenceFailed)
			return
		}
	}

	// The fence is done and h's state row is written; everything below is
	// recovery, and every refusal in it is therefore post-fence.
	c.recoverWorkloads(ctx, h)
}

// recoverWorkloads moves every recoverable workload off a host that is already
// fenced: VMs by replica promotion or reschedule, containers by relocation.
//
// It performs NO fencing. failover has already fenced h and written its state
// row by the time this runs, so re-fencing here would power-cycle a machine
// that is already down and mint a second fence epoch for one outage.
//
// Everything it needs is re-derived from persisted state rather than passed in:
// fenceEpoch from fencing_log via proofGradeFenceRef, the candidate set from
// healthyHosts, and the work itself from the rows still pointing at h. That
// makes it idempotent — a successful reschedule re-homes the VM row and a
// successful relocation tombstones the source row — which is what lets it be
// read as a separate step rather than as the tail of the fence.
//
// It is a separate function because the fence and the recovery answer different
// questions, and because every refusal inside it happens AFTER the fence: the
// host is already marked down, so a decline here leaves work assigned to a
// machine that will not run it. strandedWorkloads reports that condition.
//
// One consequence of taking fenceEpoch from fencing_log is deliberate:
// proofGradeFenceRef only counts a fence inside recentFenceWindow, so a VM with
// a writable shared disk fails CLOSED at the shared-storage gate once that
// window lapses. Transferring a shared disk on aged-out evidence of power-off is
// the split-brain the gate exists to prevent.
func (c *Coordinator) recoverWorkloads(ctx context.Context, h *corrosion.HostRecord) {
	// Bind cross-host transfer proofs to THIS fence: for a VM with a writable
	// shared disk the executor requires a proof-grade power-off of the old owner
	// (SharedStorageFenceV1), re-verified from fencing_log via this reference. ""
	// when the fence wasn't proof-grade (best-effort/SSH) — the executor then fails
	// a shared-disk transfer closed while a local-disk transfer still proceeds.
	fenceEpoch := c.proofGradeFenceRef(ctx, h.Name)

	// Step 3: Find VMs that should be restarted.
	vms, err := corrosion.ListVMs(ctx, c.db, "", h.Name)
	if err != nil {
		slog.Error("failover: list VMs", "host", h.Name, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
		return
	}

	// Step 4: Verify healthy hosts exist before attempting rescheduling.
	candidates, err := c.healthyHosts(ctx, h.Name)
	if err != nil {
		slog.Error("failover: list healthy hosts", "host", h.Name, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
		return
	}
	if len(candidates) == 0 {
		slog.Warn("failover: no healthy hosts available for VM rescheduling", "host", h.Name)
		c.mAttempt(PhaseFence, ResultRefused, ErrNoCandidates)
		return
	}

	// Step 5: Reschedule VMs using placement engine for proper resource-aware scheduling.
	type failoverPlan struct {
		vm             corrosion.VMRecord
		targetName     string
		needsPlacement bool
	}
	plans := make([]failoverPlan, 0, len(vms))
	placementReqs := make([]placement.Request, 0, len(vms))

	for _, vm := range vms {
		// A Secure-Boot/vTPM VM's firmware state (UEFI NVRAM + swtpm) is host-local,
		// so it died with the fenced host — neither a reschedule (would boot a fresh
		// TPM) nor a disk-only replica promotion can recover it. Skip automatic
		// failover and surface it; recovery is an explicit restore from a backup
		// that carried the firmware (G1).
		if vmUsesFirmwareState(vm) {
			slog.Warn("failover: skipping Secure Boot / vTPM VM — firmware state was host-local and died with the host; restore from backup",
				"vm", vm.Name, "host", h.Name)
			_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
				ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.skip",
				Target: vm.Name, Detail: "Secure Boot / vTPM VM not auto-failed-over (firmware state lost with " + h.Name + ")", Result: "skipped",
			})
			c.mVM(ActionReschedule, ResultSkipped, ErrFirmwareState)
			continue
		}

		// Automated recovery must never act on a workload whose OWNERSHIP is in
		// dispute. The fenced host is only ONE of the condition's holders: the
		// other side may still be live and unfenced, and rescheduling (or
		// promoting) this VM onto a third host manufactures exactly the
		// dual-writer the condition was raised to prevent. The owner-assert and
		// self-heal paths already refuse on this; failover is the remaining
		// automated writer. Fail closed on a read error — a coordinator that
		// cannot see the conditions must not assume there are none.
		if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, c.db, "vm", vm.Name); cerr != nil {
			slog.Warn("failover: cannot read health conditions; deferring VM recovery (fail closed)",
				"vm", vm.Name, "error", cerr)
			c.mVM(ActionReschedule, ResultError, ErrDBError)
			continue
		} else if disputed {
			slog.Warn("failover: refusing VM recovery — active ownership condition; resolve the dispute first",
				"vm", vm.Name, "condition", code)
			c.noteGateRefused(corrosion.ActionReschedule, health.ReasonOwnershipDispute)
			c.mVM(ActionReschedule, ResultRefused, ErrOwnershipDispute)
			_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
				ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.skip",
				Target: vm.Name, Detail: "active ownership condition " + code + " — automated recovery refused", Result: "refused",
			})
			continue
		}

		// Shared-disk split-brain gate (decide site): if this coordinator enforces
		// the shared-storage fence and the VM has a writable shared disk, a cross-host
		// transfer needs a PROOF-GRADE fence of the old owner. fenceEpoch is non-empty
		// ONLY when proofGradeFenceRef found one (IPMI / manual-confirmed); a
		// best-effort fence yields "". Refuse to CREATE the transfer (auto-promote OR
		// reschedule) at the SOURCE when there's no proof-grade fence — so a
		// config-skewed / regressed target can never receive (and ungated-start) a
		// shared-disk transfer lacking a proven power-off. When a proof-grade fence
		// DOES exist the transfer proceeds and even an unenforcing target starts
		// safely (the owner is provably down). The executor re-verifies as
		// defense-in-depth. Operator remediation: `lv host fence-confirm` (or an IPMI
		// fence strategy) makes fenceEpoch proof-grade on the next cycle.
		if fenceEpoch == "" && c.sharedStorageFenceEnforced(ctx) {
			if disks, derr := corrosion.GetVMDisks(ctx, c.db, vm.Name); derr == nil && corrosion.VMHasWritableSharedDisk(disks) {
				slog.Error("failover: shared-disk VM transfer refused — no proof-grade fence of old owner (storage_unverified); run 'lv host fence-confirm' or set an IPMI fence strategy",
					"vm", vm.Name, "old_owner", h.Name)
				c.noteGateRefused(corrosion.ActionReschedule, health.ReasonStorageUnverified)
				c.mVM(ActionReschedule, ResultError, ErrStorageUnverified)
				continue
			}
		}

		// Auto-promotion is an explicit per-schedule DR opt-in, so it takes
		// precedence over the VM's on_host_failure policy (which defaults to
		// "none" for `lv run` VMs). A VM on the fenced host's local storage has
		// no disk on any other host, so a bare reschedule can't start it;
		// promoting the freshest replica defines + starts the VM on the host
		// holding it and re-homes the record. On success, move to the next VM.
		// On failure, fall through to the policy-based reschedule below.
		if c.Promoter != nil && c.autoPromoteEnabled(ctx, vm.Name) {
			// Split-brain gate (Phase 1, decide site): promoting a replica is a
			// runtime-ownership action; once enforced, re-check DecisionGate before
			// initiating so an isolated minority coordinator can't promote. The
			// execute-side proof (metadata-carried, single-use) is the remaining
			// direct-RPC closeout. Fail-open until cluster-wide.
			if c.gateEnforced(ctx) {
				if g := c.Gate.DecisionGate(ctx); !g.OK {
					slog.Warn("failover: decision gate refused auto-promote", "vm", vm.Name, "reason", g.Reason)
					c.noteGateRefused(corrosion.ActionPromote, g.Reason)
					c.mVM(ActionPromote, ResultError, ErrNoQuorum)
					continue
				}
			}
			if err := c.Promoter.AutoPromoteReplica(ctx, vm.Name, fenceEpoch); err != nil {
				// Fall through to the reschedule path on ANY promote error, including a
				// retryable Unavailable (e.g. the fence_epoch fencing_log row hasn't
				// replicated to the replica host yet). This is NOT a downgrade to a
				// weaker path: the reschedule now carries the same fence_epoch, and the
				// TARGET reconciler re-enforces the shared-disk proof-grade gate before
				// starting — and, unlike this once-per-fenced-host loop, the reconciler
				// genuinely retries a not-yet-replicated fence on its next tick. A bare
				// `continue` here would strand the VM, since a fenced host is processed
				// only once (c.fenced / state=="fenced" / recentlyFenced all short-circuit
				// later cycles until the host recovers).
				slog.Warn("failover: auto-promote failed, falling back to reschedule",
					"vm", vm.Name, "error", err)
				c.mVM(ActionPromote, ResultError, ErrPromoteFailed)
			} else {
				slog.Info("failover: VM recovered via replica promotion", "vm", vm.Name)
				c.fenceRelocated[h.Name] = true
				c.mVM(ActionPromote, ResultSuccess, errClassNone)
				_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
					ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.promote",
					Target: vm.Name, Detail: "promoted replica after fencing " + h.Name, Result: "ok",
				})
				continue
			}
		}

		policy := vmFailurePolicy(vm)
		if policy == "none" || policy == "" {
			slog.Info("failover: VM skipped (on_host_failure=none)", "vm", vm.Name)
			c.mVM(ActionReschedule, ResultSkipped, ErrPolicyNone)
			continue
		}

		var targetName string

		if policy == "restart-same" {
			same, _ := corrosion.GetHost(ctx, c.db, vm.HostName)
			if same != nil && same.State == "active" {
				targetName = same.Name
			}
		}

		if targetName == "" {
			req := buildFailoverPlacementRequest(vm, h.Name, c.capacity)
			placementReqs = append(placementReqs, req)
			plans = append(plans, failoverPlan{vm: vm, needsPlacement: true})
			continue
		}

		plans = append(plans, failoverPlan{vm: vm, targetName: targetName, needsPlacement: false})
	}

	placements := map[string]placement.BatchResult{}
	if len(placementReqs) > 0 {
		allVMs, err := corrosion.ListVMs(ctx, c.db, "", "")
		if err != nil {
			slog.Error("failover: list VMs for batch placement", "host", h.Name, "error", err)
			c.mAttempt(PhaseFence, ResultError, ErrDBError)
			return
		}
		ctMem, err := corrosion.SumContainerMemoryByHost(ctx, c.db)
		if err != nil {
			ctMem = nil
		}
		// Effective-capacity observations, best-effort: absent, the batch
		// degrades to DB-only arithmetic; present, runtime-only usage counts
		// against headroom and an incomplete/stale host is excluded.
		observations, oerr := corrosion.ListHostCapacityObservations(ctx, c.db)
		if oerr != nil {
			observations = nil
		}
		// There is deliberately NO fallback on a batch error. The old code
		// round-robined the fenced host's VMs across whatever candidates were
		// healthy — blind to capacity, labels, affinity, spread, max-per-node,
		// and incomplete-inventory exclusions — and the target reconciler
		// re-checks none of those before starting, so an infeasible placement
		// simply landed. Refusing leaves the rows on the fenced host, loudly,
		// and the operator (or the next placement input change) recovers them;
		// hard constraints that no surviving host satisfies must strand the
		// workload, not relocate it somewhere it was never allowed to run.
		if selected, err := placement.SelectBatch(candidates, allVMs, nil, ctMem,
			observations, c.now(), placementReqs); err != nil {
			slog.Error("failover: batch placement failed — affected VMs are left for operator recovery, NOT round-robined",
				"host", h.Name, "error", err)
			for i := range plans {
				if plans[i].needsPlacement {
					c.mVM(ActionReschedule, ResultError, ErrPlacementFailed)
					_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
						ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.skip",
						Target: plans[i].vm.Name, Detail: "batch placement failed after fencing " + h.Name + ": " + err.Error(), Result: "error",
					})
				}
			}
			plans = plans[:0]
		} else {
			placements = selected
		}
	}

	for _, p := range plans {
		vm := p.vm
		if p.needsPlacement {
			result, ok := placements[vm.Name]
			if !ok || result.Host == "" {
				// No eligible host under the VM's hard constraints. Same
				// reasoning as the batch-error path above: skip loudly.
				slog.Warn("failover: no eligible host for VM — left for operator recovery, NOT round-robined",
					"vm", vm.Name, "from", h.Name)
				c.mVM(ActionReschedule, ResultSkipped, ErrPlacementFailed)
				_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
					ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.skip",
					Target: vm.Name, Detail: "no eligible host satisfies its placement constraints after fencing " + h.Name, Result: "skipped",
				})
				continue
			}
			p.targetName = result.Host
			p.needsPlacement = false
		}

		targetName := p.targetName

		slog.Info("failover: rescheduling VM",
			"vm", vm.Name, "from", vm.HostName, "to", targetName, "policy", vmFailurePolicy(vm))

		if c.gateEnforced(ctx) {
			// ListVMs deliberately omits operation-control columns, including
			// vm_owner_epoch. Re-read the full authoritative row at the decision
			// boundary so the proof binds the real ownership generation; the
			// transactional writer checks the same epoch again to close the race.
			freshVM, ferr := corrosion.GetVM(ctx, c.db, vm.Name)
			if ferr != nil || freshVM == nil || freshVM.HostName != h.Name {
				slog.Warn("failover: VM ownership changed before proof mint; deferring",
					"vm", vm.Name, "expected_host", h.Name, "error", ferr)
				c.mVM(ActionReschedule, ResultError, ErrDBError)
				continue
			}
			vm = *freshVM
			// Enforcement active: re-check DecisionGate (quorum + coordinator-eligible;
			// the lease is already held in this failover path) as close to the write as
			// possible, then write a durable proof linked to the pending transition so
			// the target's reconciler can validate + single-use-claim it before starting.
			if g := c.Gate.DecisionGate(ctx); !g.OK {
				slog.Warn("failover: decision gate refused reschedule", "vm", vm.Name, "reason", g.Reason)
				c.noteGateRefused(ActionReschedule, g.Reason)
				c.mVM(ActionReschedule, ResultError, ErrNoQuorum)
				continue
			}
			// Never stamp a proof for a target that no longer advertises the gate
			// (a regressed/replaced host that couldn't honor it) — fresh-Ping it
			// first and refuse (fail closed) rather than reschedule there ungated.
			if !c.destAdvertisesGate(ctx, targetName) {
				slog.Warn("failover: reschedule target does not advertise split-brain gate — refusing (fail closed)",
					"vm", vm.Name, "target", targetName)
				c.noteGateRefused(ActionReschedule, health.ReasonUnsupportedCapability)
				c.mVM(ActionReschedule, ResultError, ErrDestUngated)
				continue
			}
			_, live, needed := c.Gate.QuorumProof(ctx)
			// The fencing term of THIS tenure, taken from what the coordinator
			// recorded at acquisition — never from a fresh MAX(term) read, which
			// would let a displaced holder adopt the winner's term.
			//
			// reschedule is the one action in leaseTermRequiredActions, and this
			// is its only mint site, so an unstamped proof here is refused
			// outright once lease_term_v1 latches: judgeProofLeaseTerm sees
			// term 0 with an empty key and returns ReasonStaleLeaseTerm, so the
			// VM is never started and sits pending forever. Nothing detected
			// that, because LeaseTermReadiness checks whether this node can MINT
			// a term, not whether its producers STAMP one.
			leaseHolder, leaseExp, leaseTerm, ok := c.leaseStamp(ctx)
			if !ok {
				c.noteGateRefused(ActionReschedule, health.ReasonStaleLeaseTerm)
				c.mVM(ActionReschedule, ResultError, ErrStaleLeaseTerm)
				continue
			}
			proof := corrosion.ActionProof{
				ID: randid.New(), Action: corrosion.ActionReschedule, TargetKind: "vm",
				TargetName: vm.Name, DestHost: targetName, Coordinator: c.hostName,
				LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
				QuorumLive: live, QuorumNeeded: needed, FenceEpoch: fenceEpoch,
				OwnerEpoch: ownerEpochString(vm.OwnerEpoch),
				LeaseTerm:  leaseTerm, LeaseKey: corrosion.LeaseKeyFailover,
			}
			if err := corrosion.WriteVMRescheduleProof(ctx, c.db, proof, vm.Name, targetName); err != nil {
				slog.Error("failover: write reschedule proof", "vm", vm.Name, "error", err)
				c.mVM(ActionReschedule, ResultError, ErrDBError)
				continue
			}
		} else if err := corrosion.UpdateVMHost(ctx, c.db, vm.Name, targetName, "pending"); err != nil {
			// Legacy (pre-activation) path — unchanged.
			slog.Error("failover: update VM host", "vm", vm.Name, "error", err)
			c.mVM(ActionReschedule, ResultError, ErrDBError)
			continue
		}
		c.fenceRelocated[h.Name] = true
		c.mVM(ActionReschedule, ResultSuccess, errClassNone)

		_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
			ID:       randid.New(),
			Username: "failover-coordinator",
			HostName: c.hostName,
			Action:   "failover",
			Target:   vm.Name,
			Detail:   "rescheduled from " + h.Name + " to " + targetName,
			Result:   "ok",
		})
	}

	// Step 6: Relocate containers on the fenced host (B5). Unlike VMs, a
	// container's rootfs lived on the (now dead) host, so relocation re-creates
	// it from a re-pullable image origin on the target. This is state-only here
	// — re-key the row to the target as pending+relocate-recreate; the target's
	// container reconciler does the actual recreate. Stateful / non-re-pullable
	// containers are skipped and loudly audited (their data can't be recovered
	// without a backup — the backup-restore tier is a follow-up).
	c.relocateContainers(ctx, h, candidates)
}

// relocateContainers re-homes the fenced host's relocatable containers onto
// healthy hosts. For each, it prefers a faithful restore-from-backup (tier-2),
// falls back to image-recreate (tier-1), else skips — and re-derives the outcome
// of any in-flight restore-relocation (crash recovery). Shares the round-robin
func (c *Coordinator) relocateContainers(ctx context.Context, h *corrosion.HostRecord, candidates []corrosion.HostRecord) {
	// Split-brain gate (Phase 1, decide site): once enforced, re-check DecisionGate
	// (quorum + coordinator-eligible; lease already held in the failover path)
	// before relocating any container off the fenced host — an isolated minority
	// coordinator must not initiate relocation. Fail-open until cluster-wide.
	if c.gateEnforced(ctx) {
		if g := c.Gate.DecisionGate(ctx); !g.OK {
			slog.Warn("failover: decision gate refused container relocation", "host", h.Name, "reason", g.Reason)
			c.noteGateRefused(corrosion.ActionRelocate, g.Reason)
			c.mCt(ActionRelocate, ResultError, ErrNoQuorum)
			return
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, h.Name)
	if err != nil {
		slog.Error("failover: list containers", "host", h.Name, "error", err)
		c.mCt(ActionRelocate, ResultError, ErrDBError)
		return
	}
	for _, ct := range cts {
		if ct.OnHostFailure == "" || ct.OnHostFailure == "none" {
			continue
		}
		// Already triaged to skipped in a prior pass — left visible for operator
		// recovery; don't re-process (and don't loop on it).
		if ct.StateDetail == corrosion.ContainerRelocateSkippedDetail {
			continue
		}
		// Same ownership-dispute refusal as the VM loop: the other holder of the
		// dispute may be live on an unfenced host, and recreating this container
		// elsewhere adds a writer. Fail closed on a read error.
		if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, c.db, "container", ct.Name); cerr != nil {
			slog.Warn("failover: cannot read health conditions; deferring container relocation (fail closed)",
				"container", ct.Name, "error", cerr)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			continue
		} else if disputed {
			slog.Warn("failover: refusing container relocation — active ownership condition; resolve the dispute first",
				"container", ct.Name, "condition", code)
			c.noteGateRefused(corrosion.ActionRelocate, health.ReasonOwnershipDispute)
			c.mCt(ActionRelocate, ResultRefused, ErrOwnershipDispute)
			continue
		}
		// Crash recovery: a prior tick already began a restore-relocation (marker on
		// the source row, carrying the target + attempt token). Re-derive.
		if target, token, restoring := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail); restoring {
			c.resumeRestoreRelocation(ctx, h, ct, target, token, candidates)
			continue
		}
		c.startRelocation(ctx, h, ct, candidates)
	}
}

// startRelocation relocates one not-yet-marked container: restore-from-backup if
// possible, else image-recreate, else skip.
func (c *Coordinator) startRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord) {
	target := c.pickContainerTarget(ctx, ct, candidates)
	if target == "" {
		slog.Warn("failover: no target for container relocation", "container", ct.Name)
		return
	}

	// Tier-2: restore-from-backup when a restorer is wired and the survivor is
	// schema-compatible.
	if c.Restorer != nil && c.survivorSchemaCompatible(ctx, target) {
		// Mark the SOURCE row first (idempotent; carries the target + a fresh attempt
		// token) so a crash mid-restore is recoverable. The marker is load-bearing
		// for that recovery, so if its write FAILS we must NOT proceed with the
		// restore (an unmarked restore the next tick couldn't re-derive) — defer.
		token := randid.New()
		// Split-brain hardening: under active enforcement, mint a durable single-use
		// proof bound to this restore token so RestoreContainer validates + claims it
		// (dest==self + quorum) before importing/recording. Fail-open until cluster-wide.
		if c.gateEnforced(ctx) {
			// Never stamp a proof for a target that doesn't advertise the gate.
			if !c.destAdvertisesGate(ctx, target) {
				slog.Warn("failover: restore-relocation target does not advertise split-brain gate — refusing (fail closed)",
					"container", ct.Name, "target", target)
				c.noteGateRefused(ActionRelocate, health.ReasonUnsupportedCapability)
				c.mCt(ActionRelocate, ResultError, ErrDestUngated)
				return
			}
			leaseHolder, leaseExp, leaseTerm, ok := c.leaseStamp(ctx)
			if !ok {
				c.noteGateRefused(ActionRelocate, health.ReasonStaleLeaseTerm)
				c.mCt(ActionRelocate, ResultError, ErrStaleLeaseTerm)
				return
			}
			proof := corrosion.ActionProof{
				ID: randid.New(), Action: corrosion.ActionRelocate, TargetKind: "container",
				TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
				LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
				RelocationToken: token,
				OwnerEpoch:      ownerEpochString(ct.OwnerEpoch),
				LeaseTerm:       leaseTerm, LeaseKey: corrosion.LeaseKeyFailover,
			}
			if err := corrosion.WriteActionProof(ctx, c.db, proof); err != nil {
				slog.Warn("failover: write restore-relocation proof; deferring", "container", ct.Name, "error", err)
				c.mCt(ActionRelocate, ResultError, ErrDBError)
				return
			}
		}
		if err := corrosion.SetContainerStateDetail(ctx, c.db, h.Name, ct.Name, "relocating", corrosion.RelocateRestoreDetail(target, token)); err != nil {
			slog.Warn("failover: failed to mark relocate-restore; deferring relocation to next tick",
				"container", ct.Name, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			return
		}
		// We do NOT pre-create a target row — RestoreContainer refuses an existing
		// row, and a genuinely-failed restore must leave none. The token rides to the
		// target, which stamps it on the restored row so we can prove it's ours.
		switch outcome, err := c.Restorer.RestoreContainerFromBackup(ctx, ct.Name, target, token); outcome {
		case corrosion.RestoreLanded:
			// The target recorded its row (even if a later start errored) — complete
			// the handoff; do NOT image-recreate over a valid restored container.
			c.completeRestore(ctx, h, ct, target)
			return
		case corrosion.RestoreUnknown:
			// Indeterminate: the row MAY have been recorded on the target (the
			// confirmation frame/stream was lost). Destructively falling back could
			// clobber a landed restore — instead leave the relocate-restore marker
			// and let resolvePendingRelocations settle it on a later tick (target row
			// appears ⇒ complete; stale + absent ⇒ image-recreate).
			slog.Warn("failover: container restore outcome indeterminate; leaving marker for the resolve pass",
				"container", ct.Name, "target", target, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrRestoreUnknown)
			return
		default: // RestoreNotAttempted | RestoreFailedBeforeRow → nothing landed
			slog.Warn("failover: container restore not attempted / failed before any row; falling back to image-recreate",
				"container", ct.Name, "target", target, "error", err)
		}
	}
	// Tier-1: image-recreate (re-pullable) or skip. RelocateContainer (recreate)
	// soft-deletes the source row, clearing any relocate-restore marker; the skip
	// path replaces the marker with a terminal relocate-skipped detail.
	c.imageRecreateOrSkip(ctx, h, ct, target)
}

// resumeRestoreRelocation re-derives a relocate-restore marker on a re-tick
// (typically after a coordinator restart mid-restore).
func (c *Coordinator) resumeRestoreRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target, token string, candidates []corrosion.HostRecord) {
	// Restore already landed? (crashed after the target row was created but before
	// the source was tombstoned). Require PROVENANCE: the (target,name) row must
	// carry OUR attempt token (the target stamps relocate_token from the marker's
	// token). Names aren't cluster-unique, so a same-name row could otherwise be an
	// unrelated container (operator create / delayed anti-entropy) — completing on
	// that would tombstone the source over it. A token match proves it's our restore.
	if target != "" && token != "" {
		if tgt, _ := corrosion.GetContainer(ctx, c.db, target, ct.Name); tgt != nil && tgt.RelocateToken == token {
			c.completeRestore(ctx, h, ct, target)
			return
		}
	}
	// No target row. Fresh marker → a restore may be in flight; skip to avoid a
	// duplicate. Stale marker → it never completed; fall back to image-recreate.
	if c.markerFresh(ct) {
		return
	}
	slog.Warn("failover: stale relocate-restore marker — falling back to image-recreate",
		"container", ct.Name, "target", target)
	if target == "" {
		target = c.pickContainerTarget(ctx, ct, candidates)
	}
	c.imageRecreateOrSkip(ctx, h, ct, target)
}

// completeRestore finalizes a successful restore: the target row was created by
// RestoreContainer, so tombstone the dead-host source row to complete the
// (logical, idempotent) handoff — the source host is fenced and won't write again.
func (c *Coordinator) completeRestore(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target string) {
	if err := corrosion.DeleteContainer(ctx, c.db, h.Name, ct.Name); err != nil {
		// The restore itself landed, but the handoff is INCOMPLETE: the dead
		// host's source row is still live next to the target's — a duplicate
		// the scheduler and quota both count. Recording success here would
		// declare the relocation clean while that duplicate exists. Report a
		// partial result instead and DON'T mark the host relocated: the next
		// sweep re-enters this path (the marker and token-matched target row
		// are still in place) and retries the tombstone until it lands.
		slog.Warn("failover: source row tombstone failed after restore — will retry next sweep",
			"container", ct.Name, "from", h.Name, "to", target, "error", err)
		c.mCt(ActionRelocate, ResultPartial, ErrDBError)
		c.auditRelocate(ctx, "ct.relocate.restored", ct.Name,
			"restored to "+target+" but the source row on "+h.Name+" is still live (tombstone failed; retrying)", "error")
		return
	}
	c.fenceRelocated[h.Name] = true
	c.mCt(ActionRelocate, ResultSuccess, errClassNone)
	slog.Info("failover: container relocated via restore-from-backup", "container", ct.Name, "from", h.Name, "to", target)
	c.auditRelocate(ctx, "ct.relocate.restored", ct.Name, "restored from backup to "+target+" after fencing "+h.Name, "ok")
}

// imageRecreateOrSkip is the tier-1 path: recreate from a re-pullable image, else
// skip. The skip leaves the row VISIBLE (for operator recovery) with a terminal
// relocate-skipped detail — which also replaces any relocate-restore marker, so
// the relocate loop won't re-process it.
func (c *Coordinator) imageRecreateOrSkip(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target string) {
	// A container with no re-pullable image can't be rebuilt here (its rootfs died
	// with the host) — skip and loudly audit so the operator knows to recover it.
	if !containerImageRepullable(ct.Image) {
		// Keep the row visible; "stopped" reflects that it isn't running anywhere,
		// and the terminal detail stops the relocate loop from re-processing it.
		if err := corrosion.SetContainerStateDetail(ctx, c.db, h.Name, ct.Name, "stopped", corrosion.ContainerRelocateSkippedDetail); err != nil {
			slog.Warn("failover: mark container relocate-skipped", "container", ct.Name, "error", err)
		}
		slog.Warn("failover: container not relocatable (no re-pullable image, no usable backup) — skipping",
			"container", ct.Name, "image", ct.Image, "host", h.Name)
		c.auditRelocate(ctx, "ct.relocate.skipped", ct.Name,
			"no re-pullable image and no usable backup after fencing "+h.Name+" (left for operator recovery)", "skipped")
		c.mCt(ActionRelocate, ResultSkipped, ErrNonRepullable)
		return
	}
	// No collision-free target (none available, or the only candidate already runs
	// a same-name container). Skip — leave the source visible; recreating would
	// either have nowhere to go or clobber an unrelated container. Mark terminal so
	// it doesn't loop (and so any relocate-restore marker is cleared, not left for
	// the resolve pass to misread against an unrelated target row).
	if target == "" || c.targetHasLiveContainer(ctx, target, ct.Name) {
		if err := corrosion.SetContainerStateDetail(ctx, c.db, h.Name, ct.Name, "stopped", corrosion.ContainerRelocateSkippedDetail); err != nil {
			slog.Warn("failover: mark container relocate-skipped", "container", ct.Name, "error", err)
		}
		slog.Warn("failover: no collision-free target for container relocation — skipping",
			"container", ct.Name, "target", target, "host", h.Name)
		c.auditRelocate(ctx, "ct.relocate.skipped", ct.Name,
			"no collision-free relocation target after fencing "+h.Name+" (left for operator recovery)", "skipped")
		c.mCt(ActionRelocate, ResultSkipped, ErrNoCandidates)
		return
	}
	// Split-brain hardening (Phase 1): under active enforcement, mint a durable
	// single-use proof bound to a relocation token and stamp the token on the
	// re-keyed row, so the target claims it by token before recreating. Fail-open
	// (empty token, no proof) until split_brain_gate_v1 is cluster-wide.
	relocToken := ""
	if c.gateEnforced(ctx) {
		// Never stamp a proof for a target that doesn't advertise the gate.
		if !c.destAdvertisesGate(ctx, target) {
			slog.Warn("failover: relocation target does not advertise split-brain gate — refusing (fail closed)",
				"container", ct.Name, "target", target)
			c.noteGateRefused(ActionRelocate, health.ReasonUnsupportedCapability)
			c.mCt(ActionRelocate, ResultError, ErrDestUngated)
			return
		}
		leaseHolder, leaseExp, leaseTerm, ok := c.leaseStamp(ctx)
		if !ok {
			c.noteGateRefused(ActionRelocate, health.ReasonStaleLeaseTerm)
			c.mCt(ActionRelocate, ResultError, ErrStaleLeaseTerm)
			return
		}
		relocToken = randid.New()
		proof := corrosion.ActionProof{
			ID: randid.New(), Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
			LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
			RelocationToken: relocToken,
			OwnerEpoch:      ownerEpochString(ct.OwnerEpoch),
			LeaseTerm:       leaseTerm, LeaseKey: corrosion.LeaseKeyFailover,
		}
		if err := corrosion.WriteActionProof(ctx, c.db, proof); err != nil {
			slog.Error("failover: write relocation proof", "container", ct.Name, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			return
		}
	}
	if err := corrosion.RelocateContainerWithToken(ctx, c.db, h.Name, ct.Name, target, relocToken); err != nil {
		// Includes the no-clobber guard (a same-name container appeared on the
		// target since the check above) — never lose the source.
		slog.Error("failover: relocate container (image-recreate)", "container", ct.Name, "error", err)
		c.mCt(ActionRelocate, ResultError, ErrRelocateFailed)
		return
	}
	c.fenceRelocated[h.Name] = true
	c.mCt(ActionRelocate, ResultSuccess, errClassNone)
	slog.Info("failover: relocating container (image-recreate)", "container", ct.Name, "from", h.Name, "to", target)
	c.auditRelocate(ctx, "ct.relocate.recreate", ct.Name,
		"relocated from "+h.Name+" to "+target+" (recreate from image)", "ok")
}

// pickContainerTarget chooses a survivor via the placement engine, falling back
// to round-robin over the candidate list. It skips any host that already runs a
// LIVE container of the same name (names aren't cluster-unique), so relocation
// never collides with / clobbers an unrelated container. Returns "" if no
// collision-free target exists.
func (c *Coordinator) pickContainerTarget(ctx context.Context, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord) string {
	// The single-VM Select path carries the full capacity model (observations,
	// reserves, incomplete-host exclusion). There is deliberately NO
	// round-robin fallback on its failure: the old one walked the raw healthy
	// candidate list — blind to capacity and to incomplete-inventory exclusions
	// — so a container that genuinely fit nowhere was relocated somewhere it
	// did not fit. "" tells the caller to skip loudly and leave the row for
	// operator recovery instead.
	target, err := placement.Select(ctx, c.db, placement.Request{
		VMName: ct.Name, CPUNeeded: ct.CPULimit, MemMiBNeeded: ct.MemMiB,
		Capacity: c.capacity,
	})
	if err != nil {
		slog.Warn("failover: container placement failed — left for operator recovery, NOT round-robined",
			"container", ct.Name, "error", err)
		return ""
	}
	if c.targetHasLiveContainer(ctx, target, ct.Name) {
		// The chosen host already runs an unrelated container of this name
		// (names are per-host). Rare; skip rather than blind-pick elsewhere.
		slog.Warn("failover: container relocation target holds a same-name container — left for operator recovery",
			"container", ct.Name, "target", target)
		return ""
	}
	return target
}

// targetHasLiveContainer reports whether host already runs a live (non-deleted)
// container of the given name — a relocation collision (names are PK'd by
// (host_name,name), so the same name can legitimately exist on another host).
func (c *Coordinator) targetHasLiveContainer(ctx context.Context, host, name string) bool {
	r, err := corrosion.GetContainer(ctx, c.db, host, name)
	return err == nil && r != nil
}

// survivorSchemaCompatible reports whether the survivor is at least as new as
// this coordinator's schema, so it fully supports the restore/create_spec path. A
// behind survivor (mid rolling-upgrade) or unknown schema → fall back to
// image-recreate (graceful; restore-failure also falls back regardless).
func (c *Coordinator) survivorSchemaCompatible(ctx context.Context, target string) bool {
	hr, err := corrosion.GetHost(ctx, c.db, target)
	if err != nil || hr == nil {
		return false
	}
	return hr.SchemaVersion >= corrosion.CurrentSchemaVersion
}

// markerFresh reports whether a relocate-restore marker is still within the
// in-flight window (a restore might still be running).
func (c *Coordinator) markerFresh(ct corrosion.ContainerRecord) bool {
	to := c.RelocateRestoreTimeout
	if to <= 0 {
		to = defaultRelocateRestoreTimeout
	}
	t, ok := corrosion.ParseUpdatedAt(ct.UpdatedAt)
	if !ok {
		return true // unparseable → conservatively treat as fresh (avoid double-restore)
	}
	return c.now().Sub(t) < to
}

func (c *Coordinator) auditRelocate(ctx context.Context, action, target, detail, result string) {
	_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
		ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName,
		Action: action, Target: target, Detail: detail, Result: result,
	})
}

// containerImageRepullable reports whether a container's image origin can be
// re-pulled to rebuild its rootfs on another host (an OCI/registry ref or a
// download-template ref). An empty image (e.g. a hand-built rootfs) can't.
func containerImageRepullable(image string) bool {
	if image == "" {
		return false
	}
	// oci://… , docker.io/…:tag , alpine:3.19 — anything with a registry scheme
	// or a name:tag form is re-pullable. A bare path / empty is not.
	return strings.Contains(image, "://") || strings.Contains(image, ":") || strings.Contains(image, "/")
}

// healthyHosts returns active hosts excluding the failed host.
func (c *Coordinator) healthyHosts(ctx context.Context, excludeHost string) ([]corrosion.HostRecord, error) {
	all, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil, err
	}
	var out []corrosion.HostRecord
	for _, h := range all {
		if h.Name != excludeHost && h.State == "active" {
			out = append(out, h)
		}
	}
	return out, nil
}

// vmNeedsFailover reports whether this VM is one the coordinator would ever try
// to move off a dead host.
//
// It answers only the PERMANENT question — is this workload a failover candidate
// at all — and deliberately not "can it move right now", which depends on
// quorum, gates, candidate hosts and this coordinator's lease term. A VM this
// returns false for stays on its dead host by design.
//
// Auto-promotion is checked by the caller, not here: the reschedule loop reaches
// AutoPromoteReplica BEFORE it consults on_host_failure, so a VM enrolled in
// replication with the default policy of "none" is still recoverable — by
// promotion rather than reschedule.
func vmNeedsFailover(vm corrosion.VMRecord, autoPromote bool) bool {
	// Secure Boot / vTPM state (UEFI NVRAM + swtpm) was host-local and died with
	// the host. Neither a reschedule nor a disk-only replica promotion
	// reconstructs it, so this is not work that becomes possible later — recovery
	// is an operator restore from a backup that carried the firmware.
	if vmUsesFirmwareState(vm) {
		return false
	}
	if p := vmFailurePolicy(vm); p != "" && p != "none" {
		return true
	}
	return autoPromote
}

// containerNeedsFailover is the container half of vmNeedsFailover.
func containerNeedsFailover(ct corrosion.ContainerRecord) bool {
	if ct.OnHostFailure == "" || ct.OnHostFailure == "none" {
		return false
	}
	// Already triaged as unrecoverable on an earlier pass (no re-pullable image
	// and no usable backup) and left in place on purpose so an operator can see
	// it. Re-processing it would loop on a decision already made.
	if ct.StateDetail == corrosion.ContainerRelocateSkippedDetail {
		return false
	}
	// A relocate-restore marker means this row has an ACTIVE owner, not that it
	// is stranded: resolvePendingRelocations re-derives every marker cluster-wide
	// on EVERY cycle, independent of the fence path, and retries until the marker
	// ages out at defaultRelocateRestoreTimeout. Counting these reports work
	// somebody is doing — and in the worst case inverts the truth, since a
	// restore that LANDED but failed to tombstone its source row leaves the
	// container running on the target with only this row behind.
	if _, _, ok := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail); ok {
		return false
	}
	return true
}

// strandedWorkloads counts workloads still assigned to a host in state 'fenced'
// or 'offline' that the coordinator would move off a dead host.
//
// It measures exactly that and claims nothing more. It is NOT a count of
// post-fence refusals, and the difference matters because the two sets are not
// the same. A refusal inside recoverWorkloads does land here — the host is
// already marked down when the refusal happens. But three ordinary paths reach
// those states with their workloads intact and no refusal anywhere:
//
//   - `lv host fence` marks a host 'offline' unconditionally and never
//     enumerates workloads (see FenceHost's own comment), so it counts a live
//     host's VMs until recoverHosts clears the state.
//   - `lv host fence-confirm` writes 'fenced' on any host with no precondition.
//   - failover itself writes 'offline' and RETURNS above recoverWorkloads when a
//     safe-fence or manual fence is unconfirmed, or the fence failed. For a
//     manual-strategy host that is a documented NORMAL state, awaiting an
//     operator's confirmation — and it is the likeliest real non-zero.
//
// So a non-zero value means "workloads are sitting on a host the cluster
// considers down", which is worth an operator's attention however it arose, and
// the remedy depends on which of the above it is. docs/operating-model.md
// branches on that; a blanket `lv host undrain` is wrong for the third case,
// where the fence was never confirmed and undraining is the split-brain move the
// gate refused to make.
//
// Two limits are inherent to deriving this from hosts.state. A host whose state
// write failed after a successful fence is invisible here even with work
// stranded on it (the write logs and does not return, by design, so the fence
// still counts). And a workload counted here may have an owner: containers with
// a live relocate-restore marker are excluded for that reason, but a VM the
// operator is restoring by hand is not distinguishable.
//
// It REPORTS and does not act. Every refusal inside recoverWorkloads happens
// after the fence, because the checks that can refuse are deliberately as late
// as possible — they close races, and moving them earlier would make them staler
// than the writes they guard. That window is structural and cannot be reordered
// away. Automatic recovery from it was attempted and withdrawn: acting safely
// requires proving the host was POWERED OFF, and no evidence available to a
// coordinator supports that. hosts.state records only that somebody decided it,
// while health quorum proves unreachability — equally true of a partitioned host
// still running its VMs. Evacuating on either produces two writers on one disk.
// Proving it needs a fence proof bound to the current outage, which the schema
// does not carry today. Until it does, this surfaces the condition in seconds
// instead of whenever somebody notices VMs are down, and the recovery stays a
// decision an operator makes with commands they already have.
//
// Returns an error rather than a partial count: a number the caller publishes as
// a gauge must be measured, not guessed. A read failure leaves the previous
// value in place and reports through the error metric instead, because "0"
// during a store outage is the all-clear on the one signal an operator alerts on.
func (c *Coordinator) strandedWorkloads(ctx context.Context) (int, error) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return 0, err
	}
	// Read ONCE per cycle, not once per down host: ListBackupSchedules has no
	// host or vm_name predicate (a full scan), and the map it builds is keyed by
	// VM name across the whole fleet, so it is byte-identical for every host.
	// The c.Promoter guard mirrors the reschedule loop's, so a VM is treated as
	// promotable here exactly when that loop would try to promote it.
	enrolled := map[string]bool{}
	if c.Promoter != nil {
		rows, serr := corrosion.ListBackupSchedules(ctx, c.db)
		if serr != nil {
			return 0, serr
		}
		for _, r := range rows {
			if r.Type == "replication" && r.AutoPromote {
				enrolled[r.VMName] = true
			}
		}
	}
	total := 0
	for _, h := range hosts {
		if h.State != "fenced" && h.State != "offline" {
			continue
		}
		vms, verr := corrosion.ListVMs(ctx, c.db, "", h.Name)
		if verr != nil {
			return 0, verr
		}
		for _, vm := range vms {
			if vmNeedsFailover(vm, enrolled[vm.Name]) {
				total++
			}
		}
		cts, cerr := corrosion.ListContainers(ctx, c.db, h.Name)
		if cerr != nil {
			return 0, cerr
		}
		for _, ct := range cts {
			if containerNeedsFailover(ct) {
				total++
			}
		}
	}
	return total, nil
}

// vmFailurePolicy extracts on_host_failure from a VM's spec JSON.
func vmFailurePolicy(vm corrosion.VMRecord) string {
	var spec struct {
		OnHostFailure string `json:"on_host_failure"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.OnHostFailure
}

// vmUsesFirmwareState reports whether a VM uses Secure Boot or a vTPM — i.e. has
// host-local firmware state (NVRAM + swtpm) that can't survive its host dying (G1).
func vmUsesFirmwareState(vm corrosion.VMRecord) bool {
	var spec struct {
		SecureBoot bool `json:"secure_boot"`
		Tpm        bool `json:"tpm"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.SecureBoot || spec.Tpm
}
