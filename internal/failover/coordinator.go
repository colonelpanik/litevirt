// Package failover implements the fast failover coordinator for litevirt.
// When a host is detected as offline (consecutive health failures ≥ threshold),
// the coordinator fences it and reschedules its VMs onto healthy hosts.
package failover

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/placement"
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
	AutoPromoteReplica(ctx context.Context, vmName string) error
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

// now is the coordinator's clock — defaults to time.Now, overridable
// for virtual-time scenarios via the exported Now field.
func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
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
		return
	}
	// Leader election: only one coordinator may drive recovery at a time.
	// Acquire (or renew) the lease; if another coordinator holds it, skip.
	if !c.acquireLease(ctx) {
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
	// host_health.updated_at is RFC3339; the cutoff must be RFC3339 too, NOT
	// datetime('now', …) — a string compare against datetime()'s space text is
	// always true once the date matches ('T' > ' '), which would let a DEAD
	// observer's stale "suspect" row still count toward fencing quorum
	// (defeating the freshness gate — a false-positive-fence safety hole).
	freshCutoff := c.now().Add(-healthFreshness).UTC().Format(time.RFC3339)
	rows, err := c.db.Query(ctx,
		`SELECT target, COUNT(DISTINCT observer) AS observer_count
		 FROM host_health
		 WHERE target != ?
		   AND consecutive_failures >= ?
		   AND updated_at > ?
		 GROUP BY target
		 HAVING observer_count >= ?`,
		c.hostName, offlineThreshold, freshCutoff, quorum)
	if err != nil {
		slog.Error("failover: query host_health", "error", err)
		c.mAttempt(PhaseHealth, ResultError, ErrDBError)
		return
	}

	for _, r := range rows {
		// Re-validate lease before each destructive action: long fence runs
		// (IPMI verify up to 15 s) can outlast the lease without renewal.
		if !c.holdLease(ctx) {
			slog.Warn("failover: lease lost mid-cycle, aborting", "host", c.hostName)
			c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
			return
		}

		target := r.String("target")
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
			upd, perr := time.Parse(time.RFC3339, h.UpdatedAt)
			if perr != nil || c.now().Sub(upd) < upgradingTimeout {
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
			"host", target, "observers", r.Int("observer_count"), "quorum", quorum)

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
}

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
		// candidates/fallbackIdx are only consulted if the marker carries no target
		// (it always does), so an empty candidate set is fine here.
		c.resumeRestoreRelocation(ctx, src, ct, target, token, nil, new(int))
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
	freshCutoff := c.now().Add(-healthFreshness).UTC().Format(time.RFC3339)
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

		rows, err := c.db.Query(ctx,
			`SELECT COUNT(DISTINCT observer) AS n
			 FROM host_health
			 WHERE target = ?
			   AND consecutive_failures = 0
			   AND updated_at > ?`,
			h.Name, freshCutoff)
		if err != nil {
			// A query error would otherwise be indistinguishable from "not enough
			// healthy observers" and silently suppress recovery.
			slog.Warn("failover: recovery quorum query failed", "host", h.Name, "error", err)
			c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
			continue
		}
		if len(rows) == 0 || rows[0].Int("n") < quorum {
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
//  2. Re-reading after the write and refusing to act if the holder changed.
//  3. Re-validating before every destructive call (holdLease).
//  4. Renewing well before expiry (leaseRenewBefore head-room).
func (c *Coordinator) acquireLease(ctx context.Context) bool {
	now := c.now().UTC()
	nowRFC := now.Format(time.RFC3339)
	expiresAt := now.Add(leaseDuration).Format(time.RFC3339)
	// The expired-check compares against a bound RFC3339 `now` (?), NOT
	// datetime('now'): expires_at is stored RFC3339 ("…T…Z") and datetime('now')
	// yields space-separated text, so a string compare breaks once the date
	// matches ('T' > ' ') — a same-day lease NEVER looked expired, so a dead
	// leader's lease could never transfer to another host (failover stalls
	// cluster-wide until the UTC date rolls over). Same format on both sides
	// fixes the compare; using c.now() also keeps virtual-time tests correct.
	if err := c.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE leader_election.expires_at < ?
		      OR leader_election.holder = excluded.holder`,
		c.hostName, expiresAt, nowRFC, nowRFC); err != nil {
		slog.Error("failover: lease write", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		return false
	}

	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = 'failover'`)
	if err != nil {
		slog.Error("failover: lease read", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		return false
	}
	if len(rows) == 0 {
		// Write succeeded but read returned nothing — abort cycle.
		slog.Warn("failover: lease row missing after write")
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		return false
	}
	holder := rows[0].String("holder")
	if holder != c.hostName {
		// Another coordinator holds it — the normal non-leader case.
		c.mAttempt(PhaseLease, ResultSkipped, ErrNotLeader)
		return false
	}
	c.mAttempt(PhaseLease, ResultOK, errClassNone)
	return true
}

// holdLease re-validates that we still hold the failover lease and that the
// remaining TTL is at least leaseRenewBefore. Renews if low. Returns false if
// the lease is lost or read fails.
func (c *Coordinator) holdLease(ctx context.Context) bool {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = 'failover'`)
	if err != nil || len(rows) == 0 {
		return false
	}
	if rows[0].String("holder") != c.hostName {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		return false
	}
	if expiresAt.Sub(c.now()) > leaseRenewBefore {
		return true
	}
	// Renew.
	return c.acquireLease(ctx)
}

// leaseSnapshot returns the current failover-lease holder + expiry to record in a
// proof. leader_election has no lease TERM column, so the proof captures the
// snapshot (holder + expires_at), matching the plan's honest trust model.
func (c *Coordinator) leaseSnapshot(ctx context.Context) (holder, expiresAt string) {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = 'failover'`)
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

	// Re-validate lease immediately before the destructive fence call. Fence
	// runs (especially IPMI verify) can take ~15 s; a second coordinator must
	// not begin fencing the same host concurrently.
	if !c.holdLease(ctx) {
		slog.Warn("failover: lease lost before fence, aborting", "host", h.Name)
		c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
		return
	}

	// Step 1: Fence the host.
	fr := c.fencer(ctx, fence.HostConfig{
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
		ID:       newID(),
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
	fallbackIdx := 0
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
				ID: newID(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.skip",
				Target: vm.Name, Detail: "Secure Boot / vTPM VM not auto-failed-over (firmware state lost with " + h.Name + ")", Result: "skipped",
			})
			c.mVM(ActionReschedule, ResultSkipped, ErrFirmwareState)
			continue
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
			if err := c.Promoter.AutoPromoteReplica(ctx, vm.Name); err != nil {
				slog.Warn("failover: auto-promote failed, falling back to reschedule",
					"vm", vm.Name, "error", err)
				c.mVM(ActionPromote, ResultError, ErrPromoteFailed)
			} else {
				slog.Info("failover: VM recovered via replica promotion", "vm", vm.Name)
				c.fenceRelocated[h.Name] = true
				c.mVM(ActionPromote, ResultSuccess, errClassNone)
				_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
					ID: newID(), Username: "failover-coordinator", HostName: c.hostName, Action: "failover.promote",
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

		// Use placement engine to find the best host (respects CPU, memory,
		// anti-affinity, labels, device requirements).
		if targetName == "" {
			req := placement.Request{
				VMName:       vm.Name,
				CPUNeeded:    vm.CPUActual,
				MemMiBNeeded: vm.MemActual,
			}
			// Parse placement constraints from stored spec if available.
			if vm.Spec != "" {
				var spec struct {
					Placement *struct {
						Host         string            `json:"host"`
						AntiAffinity []string          `json:"anti_affinity"`
						Affinity     []string          `json:"affinity"`
						Require      map[string]string `json:"require"`
						Prefer       map[string]string `json:"prefer"`
						Spread       bool              `json:"spread"`
						MaxPerNode   int32             `json:"max_per_node"`
					} `json:"placement"`
				}
				if json.Unmarshal([]byte(vm.Spec), &spec) == nil && spec.Placement != nil {
					p := spec.Placement
					// Don't pin to the failed host during failover.
					if p.Host != "" && p.Host != h.Name {
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
				}
			}

			selected, err := placement.Select(ctx, c.db, req)
			if err != nil {
				// Fallback to round-robin if placement fails (degraded mode).
				slog.Warn("failover: placement failed, using round-robin fallback",
					"vm", vm.Name, "error", err)
				c.mVM(ActionReschedule, ResultError, ErrPlacementFailed)
				targetName = candidates[fallbackIdx%len(candidates)].Name
				fallbackIdx++
			} else {
				targetName = selected
			}
		}

		slog.Info("failover: rescheduling VM",
			"vm", vm.Name, "from", vm.HostName, "to", targetName, "policy", policy)

		if c.gateEnforced(ctx) {
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
			leaseHolder, leaseExp := c.leaseSnapshot(ctx)
			proof := corrosion.ActionProof{
				ID: newID(), Action: corrosion.ActionReschedule, TargetKind: "vm",
				TargetName: vm.Name, DestHost: targetName, Coordinator: c.hostName,
				LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
				QuorumLive: live, QuorumNeeded: needed,
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
			ID:       newID(),
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
	c.relocateContainers(ctx, h, candidates, &fallbackIdx)
}

// relocateContainers re-homes the fenced host's relocatable containers onto
// healthy hosts. For each, it prefers a faithful restore-from-backup (tier-2),
// falls back to image-recreate (tier-1), else skips — and re-derives the outcome
// of any in-flight restore-relocation (crash recovery). Shares the round-robin
// fallbackIdx with the VM loop so placement-failure fallbacks stay spread.
func (c *Coordinator) relocateContainers(ctx context.Context, h *corrosion.HostRecord, candidates []corrosion.HostRecord, fallbackIdx *int) {
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
		// Crash recovery: a prior tick already began a restore-relocation (marker on
		// the source row, carrying the target + attempt token). Re-derive.
		if target, token, restoring := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail); restoring {
			c.resumeRestoreRelocation(ctx, h, ct, target, token, candidates, fallbackIdx)
			continue
		}
		c.startRelocation(ctx, h, ct, candidates, fallbackIdx)
	}
}

// startRelocation relocates one not-yet-marked container: restore-from-backup if
// possible, else image-recreate, else skip.
func (c *Coordinator) startRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord, fallbackIdx *int) {
	target := c.pickContainerTarget(ctx, ct, candidates, fallbackIdx)
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
		token := newID()
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
			proof := corrosion.ActionProof{
				ID: newID(), Action: corrosion.ActionRelocate, TargetKind: "container",
				TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
				LeaseHolder: c.hostName, RelocationToken: token,
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
func (c *Coordinator) resumeRestoreRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target, token string, candidates []corrosion.HostRecord, fallbackIdx *int) {
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
		target = c.pickContainerTarget(ctx, ct, candidates, fallbackIdx)
	}
	c.imageRecreateOrSkip(ctx, h, ct, target)
}

// completeRestore finalizes a successful restore: the target row was created by
// RestoreContainer, so tombstone the dead-host source row to complete the
// (logical, idempotent) handoff — the source host is fenced and won't write again.
func (c *Coordinator) completeRestore(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target string) {
	if err := corrosion.DeleteContainer(ctx, c.db, h.Name, ct.Name); err != nil {
		slog.Warn("failover: tombstone source row after restore", "container", ct.Name, "error", err)
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
		relocToken = newID()
		proof := corrosion.ActionProof{
			ID: newID(), Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
			LeaseHolder: c.hostName, RelocationToken: relocToken,
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
func (c *Coordinator) pickContainerTarget(ctx context.Context, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord, fallbackIdx *int) string {
	if target, err := placement.Select(ctx, c.db, placement.Request{
		VMName: ct.Name, CPUNeeded: ct.CPULimit, MemMiBNeeded: ct.MemMiB,
	}); err == nil && !c.targetHasLiveContainer(ctx, target, ct.Name) {
		return target
	}
	// Placement failed or its pick collides — round-robin a collision-free candidate.
	for i := 0; i < len(candidates); i++ {
		cand := candidates[*fallbackIdx%len(candidates)].Name
		*fallbackIdx++
		if !c.targetHasLiveContainer(ctx, cand, ct.Name) {
			return cand
		}
	}
	return ""
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
	t, err := time.Parse(time.RFC3339, ct.UpdatedAt)
	if err != nil {
		return true // unparseable → conservatively treat as fresh (avoid double-restore)
	}
	return c.now().Sub(t) < to
}

func (c *Coordinator) auditRelocate(ctx context.Context, action, target, detail, result string) {
	_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
		ID: newID(), Username: "failover-coordinator", HostName: c.hostName,
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

// newID generates a short random hex ID.
func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
