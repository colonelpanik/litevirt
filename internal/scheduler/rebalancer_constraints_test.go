package scheduler

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// These tests lock in the constraint-aware rebalancing fix: a proposed move
// must pass the SAME hard filters as initial placement, so the rebalancer can
// never propose a destination that violates anti-affinity, required labels,
// max-per-node, or a pin. Before the fix, bestMove scored only CPU/Mem and
// would happily propose constraint-violating moves.

func insertHostLabeled(t *testing.T, db *corrosion.Client, name string, cpu, mem int, labels map[string]string) {
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
		Labels:   labels,
	}); err != nil {
		t.Fatalf("InsertHost %s: %v", name, err)
	}
}

// dstFor returns the proposal destination for vm, or "" if none was proposed.
func dstFor(props []proposalRow, vm string) string {
	for _, p := range props {
		if p.VMName == vm {
			return p.Dst
		}
	}
	return ""
}

// Low-threshold balance spec so an obvious imbalance always triggers a move.
const balanceEagerSpec = `{"placement":{"policy":"balance","rebalance":{"mode":"dry-run","threshold":1,"cooldown":"5m"}}}`

func antiAffinitySpec(peer string) string {
	return `{"placement":{"policy":"balance","anti_affinity":["` + peer + `"],"rebalance":{"mode":"dry-run","threshold":1,"cooldown":"5m"}}}`
}

// Anti-affinity excludes the only candidate destination → no move is proposed
// for the constrained VM (even though the cluster is imbalanced).
func TestRebalancer_RespectsAntiAffinity(t *testing.T) {
	db := newRebalancerTestDB(t)
	insertHost(t, db, "loaded", 64, 256*1024)
	insertHost(t, db, "empty", 64, 256*1024)

	// web-1 on loaded wants to spread, but its only destination (empty) already
	// runs its anti-affinity peer web-2 → empty is excluded.
	insertVM(t, db, "web-1", "loaded", 4, 8192, antiAffinitySpec("web-2"))
	insertVM(t, db, "web-2", "empty", 4, 8192, modeOffSpec)
	// Pile filler (mode=off) on loaded so it's clearly the heavier host.
	for i := 0; i < 4; i++ {
		insertVM(t, db, fName(i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if d := dstFor(listProposals(t, db), "web-1"); d != "" {
		t.Errorf("web-1 proposed to move to %q; anti-affinity should have blocked the only destination", d)
	}
}

// Control: with a non-conflicting host available, anti-affinity excludes only
// the conflicting host — the move goes to the allowed one.
func TestRebalancer_AntiAffinity_MovesToNonConflicting(t *testing.T) {
	db := newRebalancerTestDB(t)
	insertHost(t, db, "loaded", 64, 256*1024)
	insertHost(t, db, "conflict", 64, 256*1024)
	insertHost(t, db, "free", 64, 256*1024)

	insertVM(t, db, "web-1", "loaded", 4, 8192, antiAffinitySpec("web-2"))
	insertVM(t, db, "web-2", "conflict", 4, 8192, modeOffSpec)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fName(i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	d := dstFor(listProposals(t, db), "web-1")
	if d != "free" {
		t.Errorf("web-1 moved to %q; want free (conflict is anti-affinity-excluded)", d)
	}
}

// A required label excludes hosts that lack it.
func TestRebalancer_RespectsRequiredLabels(t *testing.T) {
	db := newRebalancerTestDB(t)
	insertHostLabeled(t, db, "loaded", 64, 256*1024, map[string]string{"zone": "a"})
	insertHostLabeled(t, db, "empty", 64, 256*1024, map[string]string{"zone": "b"}) // wrong zone

	spec := `{"placement":{"policy":"balance","require":{"zone":"a"},"rebalance":{"mode":"dry-run","threshold":1,"cooldown":"5m"}}}`
	insertVM(t, db, "db-1", "loaded", 4, 8192, spec)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fName(i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if d := dstFor(listProposals(t, db), "db-1"); d != "" {
		t.Errorf("db-1 proposed to move to %q which lacks required label zone=a", d)
	}
}

// max_per_node excludes a destination already at the per-host replica cap.
func TestRebalancer_RespectsMaxPerNode(t *testing.T) {
	db := newRebalancerTestDB(t)
	insertHost(t, db, "loaded", 64, 256*1024)
	insertHost(t, db, "empty", 64, 256*1024)

	// max_per_node=1; empty already runs web-2 (a replica of base "web") → the
	// only destination is excluded for web-1.
	spec := `{"placement":{"policy":"balance","max_per_node":1,"rebalance":{"mode":"dry-run","threshold":1,"cooldown":"5m"}}}`
	insertVM(t, db, "web-1", "loaded", 4, 8192, spec)
	insertVM(t, db, "web-2", "empty", 4, 8192, modeOffSpec)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fName(i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if d := dstFor(listProposals(t, db), "web-1"); d != "" {
		t.Errorf("web-1 proposed to move to %q at/over max_per_node=1", d)
	}
}

// A pinned VM is never proposed for migration.
func TestRebalancer_PinnedNeverMoves(t *testing.T) {
	db := newRebalancerTestDB(t)
	insertHost(t, db, "loaded", 64, 256*1024)
	insertHost(t, db, "empty", 64, 256*1024)

	spec := `{"placement":{"policy":"balance","host":"loaded","rebalance":{"mode":"dry-run","threshold":1,"cooldown":"5m"}}}`
	insertVM(t, db, "pinned-1", "loaded", 4, 8192, spec)
	for i := 0; i < 4; i++ {
		insertVM(t, db, fName(i), "loaded", 4, 8192, modeOffSpec)
	}

	r := NewRebalancer("loaded", db)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if d := dstFor(listProposals(t, db), "pinned-1"); d != "" {
		t.Errorf("pinned-1 proposed to move to %q; pinned VMs must never move", d)
	}
}

func fName(i int) string {
	return "filler-" + string(rune('a'+i))
}
