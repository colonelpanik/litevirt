package scheduler

import (
	"context"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// newRebalancerTestDB returns a corrosion client with the schema initialized.
func newRebalancerTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func insertHost(t *testing.T, db *corrosion.Client, name string, cpu, mem int) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), db, corrosion.HostRecord{
		Name:     name,
		Address:  "10.0.0." + name,
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    "active",
		CPUTotal: cpu,
		MemTotal: mem,
	}); err != nil {
		t.Fatalf("InsertHost %s: %v", name, err)
	}
}

func insertVM(t *testing.T, db *corrosion.Client, name, host string, cpu, mem int, spec string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		State:     "running",
		CPUActual: cpu,
		MemActual: mem,
		Spec:      spec,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// TestRebalancer_NoMovesWhenBalanced verifies that a balanced cluster
// produces no proposals.
func TestRebalancer_NoMovesWhenBalanced(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "h1", 16, 65536)
	insertHost(t, db, "h2", 16, 65536)
	insertHost(t, db, "h3", 16, 65536)

	// 1 small VM per host — perfectly balanced.
	for i, h := range []string{"h1", "h2", "h3"} {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), h, 2, 4096, balanceDryRunSpec)
	}

	r := NewRebalancer("h1", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n := proposalCount(t, db); n != 0 {
		t.Errorf("balanced cluster produced %d proposals; want 0", n)
	}
}

// TestRebalancer_ProposesMoveFromOverloaded verifies the engine proposes a
// move when one host is heavily loaded and another is empty.
func TestRebalancer_ProposesMoveFromOverloaded(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)

	// 4 VMs piled on `loaded`; nothing on `empty`.
	for i := 0; i < 4; i++ {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 4, 8192, balanceDryRunSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	props := listProposals(t, db)
	if len(props) == 0 {
		t.Fatalf("expected at least one proposal")
	}
	for _, p := range props {
		if p.Src != "loaded" {
			t.Errorf("proposal Src = %q, want loaded", p.Src)
		}
		if p.Dst != "empty" {
			t.Errorf("proposal Dst = %q, want empty", p.Dst)
		}
		if p.Status != "pending" {
			t.Errorf("dry-run proposal Status = %q, want pending", p.Status)
		}
	}
}

// TestRebalancer_RespectsModeOff verifies VMs with mode=off are skipped.
func TestRebalancer_RespectsModeOff(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n := proposalCount(t, db); n != 0 {
		t.Errorf("mode=off cluster produced %d proposals; want 0", n)
	}
}

// TestRebalancer_RespectsNoMigrate verifies the no_migrate flag is honored.
func TestRebalancer_RespectsNoMigrate(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fmt.Sprintf("pinned-%d", i), "loaded", 4, 8192, noMigrateSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n := proposalCount(t, db); n != 0 {
		t.Errorf("no_migrate cluster produced %d proposals; want 0", n)
	}
}

// TestRebalancer_SkipsFirmwareVMs verifies a Secure-Boot/vTPM VM is never
// proposed for a move (it migrates cold only; the executor live-migrates, so a
// proposal would be rejected at apply) — even on an overloaded cluster (G1).
func TestRebalancer_SkipsFirmwareVMs(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fmt.Sprintf("fw-%d", i), "loaded", 4, 8192, firmwareAutoSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n := proposalCount(t, db); n != 0 {
		t.Errorf("firmware VMs produced %d proposals; want 0", n)
	}
}

// TestRebalancer_AutoMarksApproved verifies that mode=auto proposals are
// transitioned to "approved" in the same cycle.
func TestRebalancer_AutoMarksApproved(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	for i := 0; i < 4; i++ {
		// Use balance + auto (admission would warn for bin-pack+auto).
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 4, 8192, balanceAutoSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	props := listProposals(t, db)
	if len(props) == 0 {
		t.Fatal("expected proposals")
	}
	for _, p := range props {
		if p.Status != "approved" {
			t.Errorf("auto proposal Status = %q, want approved", p.Status)
		}
	}
}

// TestRebalancer_NoThrashAcrossCycles verifies the per-VM cooldown stops
// the SAME VM from being re-proposed in immediate successive cycles.
// Cycle 2 may still propose moves for OTHER VMs if the first cycle's
// budget cap left them unproposed — that's correct behavior.
func TestRebalancer_NoThrashAcrossCycles(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 16, 65536)
	insertHost(t, db, "empty", 16, 65536)
	// Only 2 VMs so budget cap (defaultMaxConcurrent=2) takes the entire set
	// in cycle 1; cycle 2 should propose no more.
	for i := 0; i < 2; i++ {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 4, 8192, balanceDryRunSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if proposalCount(t, db) == 0 {
		t.Fatal("expected proposals on first cycle")
	}

	// Run several more cycles. Since the underlying DB doesn't actually
	// move VMs (this is dry-run + no migration controller), each cycle
	// re-reads the same imbalance. The cooldown is the only thing
	// preventing infinite duplicate proposals for the same VM.
	for i := 0; i < 5; i++ {
		if err := r.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce iteration %d: %v", i, err)
		}
	}

	props := listProposals(t, db)
	seen := make(map[string]int)
	for _, p := range props {
		seen[p.VMName]++
	}
	for vm, count := range seen {
		if count > 1 {
			t.Errorf("VM %q proposed %d times across cycles; cooldown failed", vm, count)
		}
	}
}

// TestRebalancer_BudgetCapsPerCycle verifies that no more than
// defaultMaxConcurrent proposals are emitted in one cycle.
func TestRebalancer_BudgetCapsPerCycle(t *testing.T) {
	db := newRebalancerTestDB(t)

	insertHost(t, db, "loaded", 64, 256*1024)
	insertHost(t, db, "spare", 64, 256*1024)

	// 10 VMs on the loaded host; expecting at most defaultMaxConcurrent (2).
	for i := 0; i < 10; i++ {
		insertVM(t, db, fmt.Sprintf("vm-%d", i), "loaded", 2, 4096, balanceDryRunSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	n := proposalCount(t, db)
	if n > defaultMaxConcurrent {
		t.Errorf("emitted %d proposals; per-cycle cap is %d", n, defaultMaxConcurrent)
	}
	if n == 0 {
		t.Errorf("emitted 0 proposals; expected up to %d", defaultMaxConcurrent)
	}
}

// ─── helpers ───────────────────────────────────────────────────────────

const (
	balanceDryRunSpec = `{"placement":{"policy":"balance","rebalance":{"mode":"dry-run","threshold":5,"cooldown":"5m"}}}`
	balanceAutoSpec   = `{"placement":{"policy":"balance","rebalance":{"mode":"auto","threshold":5,"cooldown":"5m"}}}`
	modeOffSpec       = `{"placement":{"policy":"balance","rebalance":{"mode":"off"}}}`
	noMigrateSpec     = `{"placement":{"policy":"balance","no_migrate":true,"rebalance":{"mode":"dry-run"}}}`
	firmwareAutoSpec  = `{"tpm":true,"placement":{"policy":"balance","rebalance":{"mode":"auto","threshold":5,"cooldown":"5m"}}}`
)

type proposalRow struct {
	ID, VMName, Src, Dst, Status, Policy string
	ExpectedGain                         float64
}

func listProposals(t *testing.T, db *corrosion.Client) []proposalRow {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT id, vm_name, src_host, dst_host, status, policy, expected_gain
		 FROM rebalance_proposals ORDER BY proposed_at`)
	if err != nil {
		t.Fatalf("Query proposals: %v", err)
	}
	out := make([]proposalRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, proposalRow{
			ID:           r.String("id"),
			VMName:       r.String("vm_name"),
			Src:          r.String("src_host"),
			Dst:          r.String("dst_host"),
			Status:       r.String("status"),
			Policy:       r.String("policy"),
			ExpectedGain: float64(r.Int("expected_gain")),
		})
	}
	return out
}

func proposalCount(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT COUNT(*) AS c FROM rebalance_proposals`)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Int("c")
}
