package fleet

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Fleet scenario: two nodes reap the same finished operation at nearly the same
// moment (lab 1, 2026-10-12, finding F6).
//
// ReapTerminalOperations runs on every node, and each reaper writes its own
// (deleted_at, updated_at) pair onto the operations header and every step. The
// peer's copy of that tombstone then arrives as `UPDATE ... WHERE deleted_at IS
// NULL` and no-ops, and anti-entropy's immutable merge used to keep the local
// row whenever both sides were tombstoned with equal facts. Each node therefore
// held its own tombstone for good, and `lv cluster converge` reported
// operations and operation_steps DIVERGENT forever: noise that hides real drift.
//
// The property: after concurrent reaps, the cluster's anti-entropy pass (what
// `lv cluster converge` kicks) brings every node to ONE row per key, so the
// two tables digest equal everywhere.
//
// Two operation kinds, because operation_steps of a workload_create operation
// pass an extra merge-authority gate (operationStepAuthorityKeepsLocal) that
// kept the local step outright whenever the local header was tombstoned.
func TestFleet_OperationReap_ConcurrentReapsConverge(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, x := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	ops := []struct {
		id, kind, resourceKind, resourceID string
		steps                              []string
	}{
		{"op-reap-update", string(corrosion.OpResourceUpdateRunning), "capacity", "",
			[]string{corrosion.OpStepPlanned, corrosion.OpStepReserved, corrosion.OpStepCompleted}},
		{"op-reap-create", string(corrosion.OpWorkloadCreate), "vm", "vm-reap",
			[]string{corrosion.OpStepPlanned, corrosion.OpStepReserved, corrosion.OpStepCompleted}},
	}
	for _, op := range ops {
		if err := corrosion.InsertOperation(ctx, a.DB, corrosion.OperationRecord{
			ID: op.id, Method: "Test", Principal: "admin@local", Project: "_default",
			ResourceKind: op.resourceKind, ResourceID: op.resourceID,
			OperationKind: op.kind, RequestHash: "h-" + op.id,
		}); err != nil {
			t.Fatalf("InsertOperation %s: %v", op.id, err)
		}
		for _, s := range op.steps {
			if err := corrosion.AppendOperationStep(ctx, a.DB, corrosion.OperationStepRecord{
				OperationID: op.id, StepName: s,
			}); err != nil {
				t.Fatalf("AppendOperationStep %s/%s: %v", op.id, s, err)
			}
		}
	}
	// Every node holds the finished, live operations.
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, x)
	assertOpTablesConverged(t, c, "precondition: before any reap")

	// a and b reap before either hears of the other's reap. Negative retention
	// puts the cutoff in the future, as in opjournal_recovery_test.go.
	for _, n := range []*Node{a, b} {
		reaped, err := corrosion.ReapTerminalOperations(ctx, n.DB, -time.Minute)
		if err != nil {
			t.Fatalf("reap on %s: %v", n.Name, err)
		}
		if reaped != len(ops) {
			t.Fatalf("reap on %s reaped %d operations, want %d", n.Name, reaped, len(ops))
		}
	}
	if ta, tb := tombstoneOf(t, a, ops[0].id), tombstoneOf(t, b, ops[0].id); ta == tb {
		t.Fatalf("precondition: the two reaps wrote one tombstone (%s); the scenario needs two", ta)
	}

	// The tombstones replicate as production sends them. Each lands as a no-op
	// on a node that has already reaped.
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, b, a)
	pumpMutations(t, c, a, x)
	pumpMutations(t, c, b, x)

	// What `lv cluster converge --all` does: a full anti-entropy pass on every
	// node. Two rounds is generous: one already pulls every node's copy.
	for round := 0; round < 2; round++ {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
	}
	assertOpTablesConverged(t, c, "after concurrent reaps and a converge pass")

	// Converging must not have resurrected anything.
	for _, n := range c.Nodes {
		for _, op := range ops {
			if got, err := corrosion.GetOperation(ctx, n.DB, op.id); err != nil || got != nil {
				t.Errorf("%s: operation %s is live again after converge (err %v)", n.Name, op.id, err)
			}
			rows, err := n.DB.Query(ctx,
				`SELECT step_name FROM operation_steps WHERE operation_id = ? AND deleted_at IS NULL`, op.id)
			if err != nil || len(rows) != 0 {
				t.Errorf("%s: %d steps of %s are live again after converge (err %v)", n.Name, len(rows), op.id, err)
			}
		}
	}
}

// tombstoneOf returns an operation header's (updated_at, deleted_at) on n.
func tombstoneOf(t *testing.T, n *Node, id string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT updated_at, COALESCE(deleted_at, '') AS deleted_at FROM operations WHERE id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read operation %s on %s: rows=%d err=%v", id, n.Name, len(rows), err)
	}
	return rows[0].String("updated_at") + "/" + rows[0].String("deleted_at")
}

// assertOpTablesConverged fails when the nodes' digests of operations or
// operation_steps differ — the tables `lv cluster converge` reported DIVERGENT.
func assertOpTablesConverged(t *testing.T, c *Cluster, when string) {
	t.Helper()
	apart, err := opDigestDivergence(c.Nodes)
	if err != nil {
		t.Fatalf("%s: divergence: %v", when, err)
	}
	var bad []string
	for _, name := range apart {
		if name == "operations" || name == "operation_steps" {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		var detail []string
		for _, n := range c.Nodes {
			rows, _ := n.DB.Query(context.Background(),
				`SELECT id, updated_at, COALESCE(deleted_at, '') AS deleted_at FROM operations ORDER BY id`)
			for _, r := range rows {
				detail = append(detail, n.Name+" "+r.String("id")+" "+r.String("updated_at")+" "+r.String("deleted_at"))
			}
		}
		t.Fatalf("%s: %v digest differently across nodes:\n%s", when, bad, strings.Join(detail, "\n"))
	}
}

// opDigestDivergence names the tables on which the nodes' state digests
// differ, empty when they agree.
func opDigestDivergence(nodes []*Node) ([]string, error) {
	ctx := context.Background()
	var base map[string]corrosion.TableDigest
	apart := map[string]bool{}
	for i, n := range nodes {
		ds, err := n.DB.StateDigest(ctx)
		if err != nil {
			return nil, err
		}
		d := make(map[string]corrosion.TableDigest, len(ds))
		for _, t := range ds {
			d[t.Name] = t
		}
		if i == 0 {
			base = d
			continue
		}
		for name, bd := range base {
			if od, ok := d[name]; !ok || od.Hash != bd.Hash || od.Count != bd.Count {
				apart[name] = true
			}
		}
		for name := range d {
			if _, ok := base[name]; !ok {
				apart[name] = true
			}
		}
	}
	out := make([]string, 0, len(apart))
	for name := range apart {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
