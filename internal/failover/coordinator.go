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
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
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

// Coordinator watches for host failures and triggers failover.
type Coordinator struct {
	hostName string
	db       *corrosion.Client
	fencer   Fencer
	// Promoter, when set, lets failover promote replicas for auto_promote VMs.
	Promoter ReplicaPromoter
	// fencing tracks hosts that have already been fenced in this session
	// to avoid double-fencing on repeated poll cycles.
	fenced map[string]bool
	// Now is the time source for lease TTL / fencing-log timestamps.
	// Defaults to time.Now; the fleet harness overrides it with a
	// virtual clock so scenarios can advance time deterministically
	// past the recentFenceWindow / lease expiry without sleeping.
	Now func() time.Time
	// OnFence, when set, is invoked after a fence is recorded so the daemon can
	// emit an operator notification (#5). Best-effort; must not block.
	OnFence func(host, method, result, detail string)
}

// NewCoordinator creates a new failover coordinator with the real fencer.
func NewCoordinator(hostName string, db *corrosion.Client) *Coordinator {
	return &Coordinator{
		hostName: hostName,
		db:       db,
		fencer:   fence.Execute,
		fenced:   make(map[string]bool),
		Now:      func() time.Time { return time.Now() },
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
		return
	}
	if liveHosts < 1 {
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
		return
	}

	for _, r := range rows {
		// Re-validate lease before each destructive action: long fence runs
		// (IPMI verify up to 15 s) can outlast the lease without renewal.
		if !c.holdLease(ctx) {
			slog.Warn("failover: lease lost mid-cycle, aborting", "host", c.hostName)
			return
		}

		target := r.String("target")
		if c.fenced[target] {
			continue
		}

		// Skip if this host is already in a terminal state.
		h, err := corrosion.GetHost(ctx, c.db, target)
		if err != nil || h == nil {
			continue
		}
		if h.State == "offline" || h.State == "maintenance" || h.State == "fenced" {
			c.fenced[target] = true
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
			continue
		}

		slog.Warn("failover: quorum reached — host exceeded failure threshold",
			"host", target, "observers", r.Int("observer_count"), "quorum", quorum)

		c.failover(ctx, h)
	}

	// Recovery pass: bring hosts that were marked 'offline' back to 'active'
	// once a fresh quorum agrees they're healthy again. A transient drop (a
	// daemon restart, a brief network blip) must self-heal — otherwise health
	// reconverges in seconds but the authoritative hosts.state stays stuck.
	c.recoverOfflineHosts(ctx, quorum)
}

// recoverOfflineHosts promotes hosts stuck in 'offline' back to 'active' once a
// fresh quorum of observers reports them healthy (consecutive_failures = 0).
//
// Why this is needed: the coordinator only ever writes "down" states, and a
// host's own startup self-active write (daemon.go) can lose a last-writer-wins
// race with a slightly-later offline write from this coordinator. With no
// recovery path, a briefly-dropped-then-healthy host stays 'offline' forever
// until an operator runs `lv host undrain`.
//
// Only 'offline' is auto-recovered. 'fenced' is left manual on purpose: a
// SUCCESSFUL fence may have rescheduled the host's VMs, so resurrecting it
// without operator confirmation risks split-brain. 'maintenance'/'draining'
// reflect operator intent and must not be cleared automatically either. As a
// belt-and-suspenders guard we also skip any host with a recent successful
// fence in the fencing_log.
func (c *Coordinator) recoverOfflineHosts(ctx context.Context, quorum int) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("failover: list hosts for recovery", "error", err)
		return
	}
	freshCutoff := c.now().Add(-healthFreshness).UTC().Format(time.RFC3339)
	for _, h := range hosts {
		if h.State != "offline" {
			continue
		}
		if c.recentlyFenced(ctx, h.Name) {
			continue
		}
		rows, err := c.db.Query(ctx,
			`SELECT COUNT(DISTINCT observer) AS n
			 FROM host_health
			 WHERE target = ?
			   AND consecutive_failures = 0
			   AND updated_at > ?`,
			h.Name, freshCutoff)
		if err != nil || len(rows) == 0 {
			continue
		}
		if rows[0].Int("n") < quorum {
			continue
		}
		if err := corrosion.UpdateHostState(ctx, c.db, h.Name, "active"); err != nil {
			slog.Error("failover: recover offline host", "host", h.Name, "error", err)
			continue
		}
		slog.Info("failover: offline host healthy again, marking active",
			"host", h.Name, "healthy_observers", rows[0].Int("n"), "quorum", quorum)
		delete(c.fenced, h.Name)
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
		return false
	}

	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = 'failover'`)
	if err != nil {
		slog.Error("failover: lease read", "error", err)
		return false
	}
	if len(rows) == 0 {
		// Write succeeded but read returned nothing — abort cycle.
		slog.Warn("failover: lease row missing after write")
		return false
	}
	holder := rows[0].String("holder")
	if holder != c.hostName {
		// Another coordinator holds it.
		return false
	}
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
	c.fenced[h.Name] = true

	// Re-validate lease immediately before the destructive fence call. Fence
	// runs (especially IPMI verify) can take ~15 s; a second coordinator must
	// not begin fencing the same host concurrently.
	if !c.holdLease(ctx) {
		slog.Warn("failover: lease lost before fence, aborting", "host", h.Name)
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
	}

	// Split-brain guard. Reschedule only if:
	//   - fence succeeded (real fence happened), OR
	//   - strategy is "best-effort" (operator opted out of safety), OR
	//   - strategy is "manual" AND an operator confirmation row exists.
	// Manual fence used to claim Success=true unconditionally; it now reports
	// Success=false and the coordinator must see an explicit confirmation row
	// in fencing_log (written by `lv host fence-confirm`) before rescheduling.
	if !fr.Success {
		switch h.FenceStrategy {
		case "best-effort":
			slog.Warn("failover: best-effort fence did not fully succeed, proceeding anyway",
				"host", h.Name, "detail", fr.Detail)
		case "manual":
			if !c.manualFenceConfirmed(ctx, h.Name) {
				slog.Error("failover: manual fence not confirmed by operator, NOT rescheduling",
					"host", h.Name, "detail", fr.Detail,
					"hint", "run 'lv host fence-confirm "+h.Name+"' once the host is powered off")
				return
			}
			slog.Info("failover: operator confirmed manual fence, proceeding",
				"host", h.Name)
		default:
			slog.Error("failover: CRITICAL — fencing failed, NOT rescheduling VMs to prevent split-brain",
				"host", h.Name, "strategy", h.FenceStrategy, "detail", fr.Detail)
			return
		}
	}

	// Step 3: Find VMs that should be restarted.
	vms, err := corrosion.ListVMs(ctx, c.db, "", h.Name)
	if err != nil {
		slog.Error("failover: list VMs", "host", h.Name, "error", err)
		return
	}

	// Step 4: Verify healthy hosts exist before attempting rescheduling.
	candidates, err := c.healthyHosts(ctx, h.Name)
	if err != nil || len(candidates) == 0 {
		slog.Warn("failover: no healthy hosts available for VM rescheduling", "host", h.Name)
		return
	}

	// Step 5: Reschedule VMs using placement engine for proper resource-aware scheduling.
	fallbackIdx := 0
	for _, vm := range vms {
		// Auto-promotion is an explicit per-schedule DR opt-in, so it takes
		// precedence over the VM's on_host_failure policy (which defaults to
		// "none" for `lv run` VMs). A VM on the fenced host's local storage has
		// no disk on any other host, so a bare reschedule can't start it;
		// promoting the freshest replica defines + starts the VM on the host
		// holding it and re-homes the record. On success, move to the next VM.
		// On failure, fall through to the policy-based reschedule below.
		if c.Promoter != nil && c.autoPromoteEnabled(ctx, vm.Name) {
			if err := c.Promoter.AutoPromoteReplica(ctx, vm.Name); err != nil {
				slog.Warn("failover: auto-promote failed, falling back to reschedule",
					"vm", vm.Name, "error", err)
			} else {
				slog.Info("failover: VM recovered via replica promotion", "vm", vm.Name)
				_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
					ID: newID(), Username: "failover-coordinator", Action: "failover.promote",
					Target: vm.Name, Detail: "promoted replica after fencing " + h.Name, Result: "ok",
				})
				continue
			}
		}

		policy := vmFailurePolicy(vm)
		if policy == "none" || policy == "" {
			slog.Info("failover: VM skipped (on_host_failure=none)", "vm", vm.Name)
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
				targetName = candidates[fallbackIdx%len(candidates)].Name
				fallbackIdx++
			} else {
				targetName = selected
			}
		}

		slog.Info("failover: rescheduling VM",
			"vm", vm.Name, "from", vm.HostName, "to", targetName, "policy", policy)

		if err := corrosion.UpdateVMHost(ctx, c.db, vm.Name, targetName, "pending"); err != nil {
			slog.Error("failover: update VM host", "vm", vm.Name, "error", err)
			continue
		}

		_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
			ID:       newID(),
			Username: "failover-coordinator",
			Action:   "failover",
			Target:   vm.Name,
			Detail:   "rescheduled from " + h.Name + " to " + targetName,
			Result:   "ok",
		})
	}
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

// newID generates a short random hex ID.
func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
