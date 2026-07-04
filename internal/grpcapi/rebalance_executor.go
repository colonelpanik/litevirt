package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// RebalanceExecutor applies operator-approved rebalance proposals. The
// rebalancer (internal/scheduler) only ever *proposes* moves and marks them
// pending/approved; nothing executed them before this. The executor is the
// missing half: a leader-gated loop that atomically claims `approved` rows,
// re-validates them against live state, runs the live migration, and records
// the terminal status.
//
// Safe by construction:
//   - Acts ONLY on `approved` rows. Auto-approval stays opt-in per VM policy
//     (placement.rebalance.mode=auto); dry-run/on-demand proposals require an
//     explicit operator `lv rebalance approve`.
//   - Leader-gated on the SAME lease as the proposing loop, so exactly one node
//     executes.
//   - Honors the cluster rebalance budget (max concurrent in-flight + max per
//     hour), resolved from VM policies — the same budget the proposer uses.
//   - Re-validates every claim before migrating (VM still exists, still running,
//     still on the proposed source, still migratable; destination still active).
type RebalanceExecutor struct {
	svc *Server
	rb  *scheduler.Rebalancer // shared lease gating
	db  *corrosion.Client

	// Interval between executor ticks. Default 30s.
	Interval time.Duration
	// StaleTimeout reaps `applying` rows whose migration goroutine never
	// recorded a terminal status (daemon killed mid-migration, etc.).
	StaleTimeout time.Duration
	// Now is the time source (overridable in tests).
	Now func() time.Time

	// migrateOverride replaces the real live-migration call in unit tests
	// (which have no libvirt / second daemon). Production leaves it nil.
	migrateOverride func(ctx context.Context, vmName, dstHost string) error
}

// NewRebalanceExecutor builds an executor sharing the rebalancer leader lease.
func NewRebalanceExecutor(svc *Server, hostName string, db *corrosion.Client) *RebalanceExecutor {
	return &RebalanceExecutor{
		svc:          svc,
		rb:           scheduler.NewRebalancer(hostName, db),
		db:           db,
		Interval:     30 * time.Second,
		StaleTimeout: 30 * time.Minute,
		Now:          time.Now,
	}
}

func (e *RebalanceExecutor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Start runs the executor loop until ctx is cancelled.
func (e *RebalanceExecutor) Start(ctx context.Context) {
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.RunOnce(ctx)
		}
	}
}

// approvedRow is the executor's view of one claimable proposal.
type approvedRow struct {
	ID, VMName, SrcHost, DstHost, ExpiresAt string
}

// RunOnce performs one executor tick. Idempotent; safe to call from tests.
func (e *RebalanceExecutor) RunOnce(ctx context.Context) {
	if !e.rb.HoldsLease(ctx) {
		return
	}
	// Split-brain gate (Phase 1): the CRDT rebalance lease can be "held" on both
	// sides of a partition, so it can't authorize an automated ownership move alone.
	// Once enforced, require DecisionGate (quorum + coordinator-eligible) too, so a
	// partitioned leader can't rebalance-migrate VMs on stale placement data without
	// quorum. Fail-open until split_brain_gate_v1 is cluster-wide. reapStale (below)
	// is local bookkeeping, not a runtime move, so it stays outside the gate.
	if reason, refused := e.svc.decideGateRefused(ctx); refused {
		slog.Info("rebalance executor: decision gate refused (no quorum) — skipping tick", "reason", reason)
		e.svc.noteGateRefused(corrosion.ActionReschedule, reason)
		return
	}
	e.reapStale(ctx)

	maxConcurrent, maxPerHour, _ := scheduler.ClusterRebalanceBudget(ctx, e.db)
	applied := e.countApplied(ctx, e.now().Add(-time.Hour))
	if applied >= maxPerHour {
		return
	}
	inflight := e.countStatus(ctx, "applying")
	slots := maxConcurrent - inflight
	if rem := maxPerHour - applied; rem < slots {
		slots = rem
	}
	if slots <= 0 {
		return
	}

	for _, p := range e.listApproved(ctx) {
		if slots <= 0 {
			break
		}
		nowStr := e.now().UTC().Format(time.RFC3339)
		// Expired proposals are not executed (defensive — the proposer only
		// expires `pending` rows, so an approved-then-expired row is possible).
		if p.ExpiresAt != "" && p.ExpiresAt < nowStr {
			e.markFailed(ctx, p.ID, "proposal expired before execution")
			continue
		}
		if !e.claim(ctx, p.ID, nowStr) {
			continue
		}
		if reason := e.validate(ctx, p); reason != "" {
			slog.Info("rebalance executor: skipping stale proposal", "id", p.ID, "vm", p.VMName, "reason", reason)
			e.markFailed(ctx, p.ID, reason)
			continue
		}
		slots--
		go e.execute(ctx, p)
	}
}

// claim atomically transitions a row approved→applying. It stamps a unique
// updated_at and re-reads to confirm THIS loop won the row (Execute reports no
// rows-affected, so we verify by marker).
func (e *RebalanceExecutor) claim(ctx context.Context, id, marker string) bool {
	if err := e.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='applying', updated_at=?
		 WHERE id=? AND status='approved'`, marker, id); err != nil {
		slog.Warn("rebalance executor: claim", "id", id, "error", err)
		return false
	}
	rows, err := e.db.Query(ctx,
		`SELECT status, updated_at FROM rebalance_proposals WHERE id=?`, id)
	if err != nil || len(rows) == 0 {
		return false
	}
	return rows[0].String("status") == "applying" && rows[0].String("updated_at") == marker
}

// validate re-checks a claimed proposal against live state. Returns a non-empty
// reason if the move should be abandoned.
func (e *RebalanceExecutor) validate(ctx context.Context, p approvedRow) string {
	vm, err := corrosion.GetVM(ctx, e.db, p.VMName)
	if err != nil || vm == nil {
		return "vm no longer exists"
	}
	if vm.State != "running" {
		return fmt.Sprintf("vm not running (state=%s)", vm.State)
	}
	if vm.HostName != p.SrcHost {
		return fmt.Sprintf("vm already moved off source (now on %s)", vm.HostName)
	}
	if spec := (&pb.VMSpec{}); vm.Spec != "" {
		if json.Unmarshal([]byte(vm.Spec), spec) == nil {
			if spec.Placement != nil && spec.Placement.NoMigrate {
				return "vm opted out of migration"
			}
			if spec.Migrate != nil && spec.Migrate.Strategy == pb.MigrateStrategy_MIGRATE_NONE {
				return "vm opted out of migration"
			}
		}
	}
	dst, err := corrosion.GetHost(ctx, e.db, p.DstHost)
	if err != nil || dst == nil {
		return "destination host not found"
	}
	if dst.State != "active" {
		return fmt.Sprintf("destination not active (state=%s)", dst.State)
	}
	if dst.IsWitness() {
		return "destination is a witness"
	}
	return ""
}

// execute runs the live migration and records the terminal status. Runs in its
// own goroutine so multiple migrations (up to the budget) overlap; the
// `applying` row count is the live concurrency gauge.
func (e *RebalanceExecutor) execute(ctx context.Context, p approvedRow) {
	var err error
	if e.migrateOverride != nil {
		err = e.migrateOverride(ctx, p.VMName, p.DstHost)
	} else {
		err = e.doMigrate(ctx, p.VMName, p.DstHost)
	}
	if err != nil {
		slog.Warn("rebalance executor: migration failed", "id", p.ID, "vm", p.VMName, "dst", p.DstHost, "error", err)
		e.markFailed(ctx, p.ID, err.Error())
		return
	}
	e.markApplied(ctx, p.ID)
	slog.Info("rebalance executor: migration applied", "id", p.ID, "vm", p.VMName, "src", p.SrcHost, "dst", p.DstHost)
}

// doMigrate drives the full MigrateVM path with an injected system principal
// and a discard stream (same pattern as MigrateVMForHealthCheck).
func (e *RebalanceExecutor) doMigrate(ctx context.Context, vmName, dstHost string) error {
	authCtx := context.WithValue(ctx, ctxKeyRole, "admin")
	authCtx = context.WithValue(authCtx, ctxKeyUsername, "system:rebalancer")
	return e.svc.MigrateVM(&pb.MigrateVMRequest{
		VmName:     vmName,
		TargetHost: dstHost,
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}, &discardMigrateStream{ctx: authCtx})
}

func (e *RebalanceExecutor) markApplied(ctx context.Context, id string) {
	now := e.now().UTC().Format(time.RFC3339)
	if err := e.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='applied', applied_at=?, updated_at=?
		 WHERE id=? AND status='applying'`, now, now, id); err != nil {
		slog.Warn("rebalance executor: mark applied", "id", id, "error", err)
	}
}

func (e *RebalanceExecutor) markFailed(ctx context.Context, id, reason string) {
	now := e.now().UTC().Format(time.RFC3339)
	if err := e.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='failed', detail=?, updated_at=? WHERE id=?`,
		reason, now, id); err != nil {
		slog.Warn("rebalance executor: mark failed", "id", id, "error", err)
	}
}

// reapStale fails `applying` rows whose goroutine never recorded a terminal
// status within StaleTimeout (e.g. the daemon was killed mid-migration).
func (e *RebalanceExecutor) reapStale(ctx context.Context) {
	cutoff := e.now().Add(-e.StaleTimeout).UTC().Format(time.RFC3339)
	now := e.now().UTC().Format(time.RFC3339)
	if err := e.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='failed', detail='execution timed out', updated_at=?
		 WHERE status='applying' AND updated_at < ?`, now, cutoff); err != nil {
		slog.Warn("rebalance executor: reap stale", "error", err)
	}
}

func (e *RebalanceExecutor) listApproved(ctx context.Context) []approvedRow {
	rows, err := e.db.Query(ctx,
		`SELECT id, vm_name, src_host, dst_host, expires_at FROM rebalance_proposals
		 WHERE status='approved' ORDER BY expected_gain DESC, proposed_at ASC`)
	if err != nil {
		slog.Warn("rebalance executor: list approved", "error", err)
		return nil
	}
	out := make([]approvedRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, approvedRow{
			ID:        r.String("id"),
			VMName:    r.String("vm_name"),
			SrcHost:   r.String("src_host"),
			DstHost:   r.String("dst_host"),
			ExpiresAt: r.String("expires_at"),
		})
	}
	return out
}

func (e *RebalanceExecutor) countStatus(ctx context.Context, status string) int {
	rows, err := e.db.Query(ctx,
		`SELECT COUNT(*) AS c FROM rebalance_proposals WHERE status=?`, status)
	if err != nil || len(rows) == 0 {
		return 0
	}
	return rows[0].Int("c")
}

func (e *RebalanceExecutor) countApplied(ctx context.Context, since time.Time) int {
	rows, err := e.db.Query(ctx,
		`SELECT COUNT(*) AS c FROM rebalance_proposals
		 WHERE status='applied' AND applied_at > ?`, since.UTC().Format(time.RFC3339))
	if err != nil || len(rows) == 0 {
		return 0
	}
	return rows[0].Int("c")
}
