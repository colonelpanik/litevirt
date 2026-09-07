package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The startup cluster-record heal writes LOCALLY, and this is the multi-node
// half of why that is safe.
//
// corrosion.EnsureClusterRecord runs on every daemon start with no capability
// gate and no config flag, and `cluster` carried no replicated statement shape
// at the previous release. A replicated write would therefore reach a peer on
// the previous binary as a fingerprint its ledger cannot resolve, which fails
// the apply closed, rolls back the whole batch and stalls that peer's
// watermark — head-of-line blocking the WAL stream into every not-yet-rolled
// node, on the recommended (pre-staged) rollout in particular.
//
// A single-package test can show the write emits no replicated statement. It
// structurally cannot show that the row still reaches every node, which is the
// property that makes local-only a fix rather than a regression. Two mechanisms
// carry it, and this scenario drives both:
//
//   - CONVERGENCE BY CONSTRUCTION. Every node shares one CA, so every node's
//     heal derives the identical ca_cert under the identical fixed row id. The
//     cluster fingerprint — the only thing anything downstream reads — is the
//     same on every node with no replication at all.
//   - ANTI-ENTROPY FOR A NODE THAT CANNOT DERIVE IT. A node that has not been
//     enrolled yet has no ca.crt, so its heal writes nothing. `cluster` is in
//     the anti-entropy table set and anti-entropy runs NO ledger check, so the
//     row is repaired onto it over the real StreamStateDump →
//     MergeStateBytesLWW path — the same route partition_test.go uses.
func TestFleet_ClusterRecordHealConvergesWithoutReplicating(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, unenrolled := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")

	// A plain fleet seeds no cluster row (only NetBox clusters do, through this
	// same heal), so every node starts without one.
	for _, n := range []*Node{a, b, unenrolled} {
		if got := clusterRowCount(t, n); got != 0 {
			t.Fatalf("precondition: %s already has %d cluster row(s)", n.Name, got)
		}
	}

	// Two enrolled nodes heal independently, from their own copy of the one
	// fleet CA. Nothing is replicated between them.
	for _, n := range []*Node{a, b} {
		if err := corrosion.EnsureClusterRecord(ctx, n.DB, n.PKIDir); err != nil {
			t.Fatalf("heal on %s: %v", n.Name, err)
		}
	}
	// The un-enrolled node runs the same heal against a directory with no
	// ca.crt: it must come up, and it must write nothing rather than a blank row.
	if err := corrosion.EnsureClusterRecord(ctx, unenrolled.DB, t.TempDir()); err != nil {
		t.Fatalf("heal on a node with no CA on disk must not fail: %v", err)
	}
	if got := clusterRowCount(t, unenrolled); got != 0 {
		t.Fatalf("a node with no CA on disk wrote %d cluster row(s), want 0", got)
	}

	// NOTHING went on the wire. Every node's mutation_log — the replication WAL
	// — must be free of the cluster table, or a previous-release peer would be
	// asked to apply a shape it cannot resolve.
	for _, n := range []*Node{a, b, unenrolled} {
		if stmt, found := replicatedStatementNaming(t, n, "INTO cluster"); found {
			t.Fatalf("%s logged a replicated statement naming the cluster table (%s): a peer on "+
				"the previous release cannot resolve that fingerprint, fails the apply closed and "+
				"stalls its watermark", n.Name, stmt)
		}
	}

	// Convergence by construction: the two nodes that healed on their own agree.
	fpA, err := corrosion.ClusterFingerprint(ctx, a.DB)
	if err != nil {
		t.Fatalf("fingerprint on %s: %v", a.Name, err)
	}
	fpB, err := corrosion.ClusterFingerprint(ctx, b.DB)
	if err != nil {
		t.Fatalf("fingerprint on %s: %v", b.Name, err)
	}
	if fpA != fpB {
		t.Fatalf("two nodes healing independently derived different cluster identities: %q vs %q — "+
			"local-only convergence depends on the shared CA being the only input", fpA, fpB)
	}

	// Anti-entropy for the node that could not derive it, over the real repair RPC.
	unenrolled.DB.MergeStateBytesLWW(pullDump(t, c, a))

	if got := clusterRowCount(t, unenrolled); got != 1 {
		t.Fatalf("after anti-entropy %s has %d cluster row(s), want 1 — `cluster` is in the "+
			"anti-entropy table set precisely so a local-only heal still reaches every node",
			unenrolled.Name, got)
	}
	fpU, err := corrosion.ClusterFingerprint(ctx, unenrolled.DB)
	if err != nil {
		t.Fatalf("fingerprint on %s after anti-entropy: %v", unenrolled.Name, err)
	}
	if fpU != fpA {
		t.Fatalf("%s converged on a different cluster identity: %q, want %q", unenrolled.Name, fpU, fpA)
	}
}

func clusterRowCount(t *testing.T, n *Node) int {
	t.Helper()
	return rowCount(t, n, `SELECT COUNT(*) AS n FROM cluster`)
}

// replicatedStatementNaming reports the first statement this node logged for
// replication that contains needle, so a failure names the offending write
// rather than dumping the whole WAL.
func replicatedStatementNaming(t *testing.T, n *Node, needle string) (string, bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT seq, stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log on %s: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), needle) {
			return fmt.Sprintf("mutation_log seq %d", r.Int("seq")), true
		}
	}
	return "", false
}
