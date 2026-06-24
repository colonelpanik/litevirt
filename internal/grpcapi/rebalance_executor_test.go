package grpcapi

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// budgetSpec is a VM spec declaring a rebalance budget, used so
// ClusterRebalanceBudget resolves the caps the executor enforces.
func budgetSpec(maxConcurrent, maxPerHour int) string {
	return fmt.Sprintf(`{"placement":{"policy":"balance","rebalance":{"mode":"auto","budget":{"max_concurrent":%d,"max_per_hour":%d}}}}`,
		maxConcurrent, maxPerHour)
}

func insertProposal(t *testing.T, ctx context.Context, db *corrosion.Client, id, vm, src, dst, status string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO rebalance_proposals
		   (id, vm_name, src_host, dst_host, policy, expected_gain, status, proposed_at, expires_at, detail, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		id, vm, src, dst, "balance", 20.0, status, now, expires, "", now); err != nil {
		t.Fatalf("insert proposal %s: %v", id, err)
	}
}

func proposalStatus(t *testing.T, ctx context.Context, db *corrosion.Client, id string) (status, detail, appliedAt string) {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT status, detail, applied_at FROM rebalance_proposals WHERE id=?`, id)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read proposal %s: err=%v rows=%d", id, err, len(rows))
	}
	return rows[0].String("status"), rows[0].String("detail"), rows[0].String("applied_at")
}

func countProposalStatus(t *testing.T, ctx context.Context, db *corrosion.Client, status string) int {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT COUNT(*) AS c FROM rebalance_proposals WHERE status=?`, status)
	if err != nil || len(rows) == 0 {
		return 0
	}
	return rows[0].Int("c")
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

// An approved proposal is claimed, migrated, and marked applied.
func TestRebalanceExecutor_AppliesApproved(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")

	// Buffered channel is a sync point: capture the migrate args without a race.
	gotCh := make(chan [2]string, 1)
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, vm, dst string) error {
		gotCh <- [2]string{vm, dst}
		return nil
	}
	e.RunOnce(ctx)

	eventually(t, func() bool {
		st, _, _ := proposalStatus(t, ctx, s.db, "p1")
		return st == "applied"
	})
	select {
	case got := <-gotCh:
		if got[0] != "vm-a" || got[1] != "dst" {
			t.Fatalf("migrate called with (%q,%q), want (vm-a,dst)", got[0], got[1])
		}
	default:
		t.Fatal("migrate was not called")
	}
	_, _, appliedAt := proposalStatus(t, ctx, s.db, "p1")
	if appliedAt == "" {
		t.Error("applied_at not set")
	}
}

// A failed migration marks the proposal failed with the error as detail.
func TestRebalanceExecutor_FailedMigrate(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")

	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error {
		return fmt.Errorf("boom: target unreachable")
	}
	e.RunOnce(ctx)

	eventually(t, func() bool {
		st, _, _ := proposalStatus(t, ctx, s.db, "p1")
		return st == "failed"
	})
	_, detail, _ := proposalStatus(t, ctx, s.db, "p1")
	if detail == "" {
		t.Error("failed proposal should record the error in detail")
	}
}

// The executor acts ONLY on approved rows; pending/rejected are untouched.
func TestRebalanceExecutor_IgnoresNonApproved(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "pend", "vm-a", "src", "dst", "pending")
	insertProposal(t, ctx, s.db, "rej", "vm-a", "src", "dst", "rejected")

	var called atomic.Bool
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error { called.Store(true); return nil }
	e.RunOnce(ctx)
	time.Sleep(50 * time.Millisecond)

	if called.Load() {
		t.Error("executor migrated a non-approved proposal")
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "pend"); st != "pending" {
		t.Errorf("pending proposal changed to %q", st)
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "rej"); st != "rejected" {
		t.Errorf("rejected proposal changed to %q", st)
	}
}

// A proposal whose VM has already moved off the source fails re-validation and
// is never migrated.
func TestRebalanceExecutor_ValidateStaleSource(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestHostR2(t, ctx, s.db, "elsewhere", "active")
	// VM is on "elsewhere", but the proposal says src="src".
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "elsewhere", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")

	var called atomic.Bool
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error { called.Store(true); return nil }
	e.RunOnce(ctx)
	time.Sleep(50 * time.Millisecond)

	if called.Load() {
		t.Error("executor migrated a stale proposal (VM already moved)")
	}
	st, detail, _ := proposalStatus(t, ctx, s.db, "p1")
	if st != "failed" {
		t.Errorf("stale proposal status = %q, want failed", st)
	}
	if detail == "" {
		t.Error("stale proposal should record a reason")
	}
}

// The concurrency budget caps how many proposals are claimed per tick: with
// max_concurrent=1, only one row goes 'applying'; the rest stay 'approved'.
func TestRebalanceExecutor_RespectsConcurrencyBudget(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	for i := 0; i < 3; i++ {
		insertTestVMR2WithSpec(t, ctx, s.db, fmt.Sprintf("vm-%d", i), "src", "running", budgetSpec(1, 10))
		insertProposal(t, ctx, s.db, fmt.Sprintf("p%d", i), fmt.Sprintf("vm-%d", i), "src", "dst", "approved")
	}

	release := make(chan struct{})
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error {
		<-release // hold the in-flight migration so 'applying' persists
		return nil
	}
	e.RunOnce(ctx)

	// Claims are synchronous within RunOnce → exactly one 'applying', two left.
	if n := countProposalStatus(t, ctx, s.db, "applying"); n != 1 {
		t.Errorf("applying = %d, want 1 (max_concurrent budget)", n)
	}
	if n := countProposalStatus(t, ctx, s.db, "approved"); n != 2 {
		t.Errorf("approved (unclaimed) = %d, want 2", n)
	}
	close(release)
	eventually(t, func() bool { return countProposalStatus(t, ctx, s.db, "applying") == 0 })
}

// The hourly budget blocks claiming when the per-hour applied count is reached.
func TestRebalanceExecutor_RespectsHourlyBudget(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(5, 1)) // max_per_hour=1

	// One already applied within the last hour → budget exhausted.
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO rebalance_proposals
		   (id, vm_name, src_host, dst_host, policy, expected_gain, status, proposed_at, applied_at, expires_at, detail, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		"done", "vm-old", "src", "dst", "balance", 20.0, "applied", now, now, now, "", now); err != nil {
		t.Fatalf("seed applied: %v", err)
	}
	insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")

	var called atomic.Bool
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error { called.Store(true); return nil }
	e.RunOnce(ctx)
	time.Sleep(50 * time.Millisecond)

	if called.Load() {
		t.Error("executor exceeded the hourly budget")
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "p1"); st != "approved" {
		t.Errorf("proposal status = %q, want approved (budget blocked)", st)
	}
}

// Stale 'applying' rows (goroutine never recorded a terminal status) are reaped
// to 'failed'.
func TestRebalanceExecutor_ReapsStale(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")

	// An 'applying' row whose updated_at is an hour old.
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO rebalance_proposals
		   (id, vm_name, src_host, dst_host, policy, expected_gain, status, proposed_at, expires_at, detail, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"stuck", "vm-z", "src", "dst", "balance", 20.0, "applying", old, old, "", old); err != nil {
		t.Fatalf("seed applying: %v", err)
	}

	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.StaleTimeout = 30 * time.Minute
	e.migrateOverride = func(_ context.Context, _, _ string) error { return nil }
	e.RunOnce(ctx)

	st, detail, _ := proposalStatus(t, ctx, s.db, "stuck")
	if st != "failed" {
		t.Errorf("stale applying row status = %q, want failed", st)
	}
	if detail != "execution timed out" {
		t.Errorf("stale reap detail = %q", detail)
	}
}

// End-to-end with REAL components: the rebalancer proposes (auto-mode →
// auto-approved) on an imbalanced cluster, then the executor claims and applies
// it. Exercises the full propose→approve→execute path, not hand-inserted rows.
func TestRebalanceExecutor_EndToEndAutoApprove(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "loaded", "active")
	insertTestHostR2(t, ctx, s.db, "empty", "active")
	// Pile auto-mode VMs on `loaded`; `empty` is free → clear imbalance.
	for i := 0; i < 4; i++ {
		insertTestVMR2WithSpec(t, ctx, s.db, fmt.Sprintf("vm-%d", i), "loaded", "running", budgetSpec(4, 10))
	}

	// Rebalancer proposes + auto-approves (mode=auto in budgetSpec).
	if err := scheduler.NewRebalancer("loaded", s.db).RunOnce(ctx); err != nil {
		t.Fatalf("rebalancer RunOnce: %v", err)
	}
	approved := countProposalStatus(t, ctx, s.db, "approved")
	if approved == 0 {
		t.Fatal("rebalancer produced no auto-approved proposals on an imbalanced cluster")
	}

	var migrations atomic.Int32
	e := NewRebalanceExecutor(s, "loaded", s.db)
	e.migrateOverride = func(ctx context.Context, vm, dst string) error {
		migrations.Add(1)
		// Reflect the move in state so the VM record stays consistent.
		_ = corrosion.UpdateVMHost(ctx, s.db, vm, dst, "running")
		return nil
	}
	e.RunOnce(ctx)

	eventually(t, func() bool {
		return countProposalStatus(t, ctx, s.db, "applied") >= 1
	})
	if migrations.Load() == 0 {
		t.Error("executor applied an approved proposal without migrating")
	}
}

// A non-leader executor does nothing.
func TestRebalanceExecutor_NotLeader(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")

	// Another node holds the rebalancer lease with a future expiry.
	future := time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES ('rebalancer','other-node',?,?)`,
		future, now); err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	var called atomic.Bool
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(_ context.Context, _, _ string) error { called.Store(true); return nil }
	e.RunOnce(ctx)
	time.Sleep(50 * time.Millisecond)

	if called.Load() {
		t.Error("non-leader executor ran a migration")
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "p1"); st != "approved" {
		t.Errorf("non-leader executor changed proposal to %q", st)
	}
}
