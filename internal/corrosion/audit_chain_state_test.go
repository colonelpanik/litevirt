package corrosion

import (
	"context"
	"testing"
)

// The audit chain tail is per-CLIENT state, not per-process state.
//
// It used to live in a package-level `auditChainState`, which is correct only
// while exactly one Client exists per process — true of a daemon, false of
// tests/fleet, where N daemons share one `go test` process. There, node B's
// first insert linked its prev_hash to node A's tail, because A's insert had
// already set the global `known` flag. B's sub-chain then failed to verify on
// B's own DB, and the failure had nothing to do with B.
//
// The existing multi-host test hides this: it calls ResetChainStateForTests()
// between the two hosts to stand in for "a separate process". That is exactly
// the seam the global forces, and it means no test drives two live Clients at
// once — which is the only shape the fleet harness has.
//
// This matters more once rows are signed. A signature binds the row to its
// chain position, so a prev_hash borrowed from another node's tail is not a
// stale hash to be resealed away — it is a permanently unverifiable row.
func TestAuditChain_TwoClientsInOneProcessKeepSeparateChains(t *testing.T) {
	ctx := context.Background()

	a := newAuditTestClient(t)
	b := newAuditTestClient(t)

	// Node A's daemon appends first, which is what primes the tail.
	ins(t, a, "a1", "hostA", "2026-06-23T10:00:01Z")

	// Node B's daemon, in the same process, appends to its OWN database. Its
	// first row must be a genesis row: prev_hash empty, because B's database
	// has nothing before it.
	ins(t, b, "b1", "hostB", "2026-06-23T10:00:02Z")

	rows, err := b.Query(ctx, `SELECT prev_hash FROM audit_log WHERE id = 'b1'`)
	if err != nil {
		t.Fatalf("read b1: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("b1 not found in node B's database")
	}
	if prev := rows[0].String("prev_hash"); prev != "" {
		t.Errorf("node B's first row links to prev_hash %q; it borrowed node A's chain tail "+
			"from process-global state and its sub-chain can never verify", prev)
	}

	res, err := VerifyAuditChain(ctx, b)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("node B's chain broke at %q (checked=%d) because of a write on node A",
			res.BrokenAt, res.RowsChecked)
	}
}
