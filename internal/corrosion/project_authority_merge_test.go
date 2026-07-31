package corrosion

import (
	"context"
	"fmt"
	"testing"
)

// project_authority_epochs is the ONE immutable table whose primary key two nodes
// can legitimately mint concurrently.
//
// operations and operation_steps are keyed by a globally-unique minted id, so the
// same PK arriving with different facts really is a fault worth freezing. But an
// authority row is keyed by (project, authority_epoch) — a NAME plus a small
// integer — and ClaimInitialProjectAuthority is explicitly designed for two nodes
// to race it (it returns applied=false for the loser). Both racers write
// (project, 1), and immutableMergeKeepLocalRow compares every column except
// updated_at/deleted_at, so the per-node wall-clock created_at made two IDENTICAL
// logical claims look like an immutable-facts conflict: each side kept its own row
// forever and anti-entropy re-reported the drift every cycle.
//
// These tests pin the two cases apart: same facts must converge silently, and
// genuinely different facts must still converge — on THIS table, unlike an
// operation journal, refusing to converge leaves two nodes each believing they
// hold the project's admission authority, which is precisely the split D1 exists
// to prevent.

// authorityRows returns every project_authority_epochs row as a canonical string,
// so two nodes' tables can be compared byte-for-byte including the timestamps that
// the digest — and therefore anti-entropy's drift report — also sees.
func authorityRows(t *testing.T, c *Client) []string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT project, authority_epoch, holder, transfer_kind, fence_proof_ref,
		        created_at, updated_at, COALESCE(deleted_at, '')
		 FROM project_authority_epochs ORDER BY project, authority_epoch`)
	if err != nil {
		t.Fatalf("query authority rows: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s/%d holder=%s kind=%s proof=%s created=%s updated=%s deleted=%s",
			r.String("project"), r.Int64("authority_epoch"), r.String("holder"),
			r.String("transfer_kind"), r.String("fence_proof_ref"),
			r.String("created_at"), r.String("updated_at"), r.String("deleted_at")))
	}
	return out
}

// stampAuthority forces one node's row timestamps to a known value. The real
// writers stamp created_at at bare-second resolution, so two claims inside one
// test would usually land on the SAME second and the test would pass without
// proving anything. Fixing both sides explicitly is what makes these tests fail
// when the merge is wrong.
func stampAuthority(t *testing.T, c *Client, project, createdAt, updatedAt string) {
	t.Helper()
	if _, err := c.db.Exec(
		`UPDATE project_authority_epochs SET created_at = ?, updated_at = ? WHERE project = ?`,
		createdAt, updatedAt, project); err != nil {
		t.Fatalf("stamp authority timestamps: %v", err)
	}
}

// gossip merges each node's full state into the other, the way anti-entropy does.
func gossipBoth(t *testing.T, a, b *Client) {
	t.Helper()
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("merge a→b: %v", err)
	}
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatalf("merge b→a: %v", err)
	}
}

// TestProjectAuthorityMerge_ConcurrentIdenticalClaimsConverge is the lab bug: two
// nodes derive the SAME holder, both mint epoch 1, and the rows differ only in
// per-node wall-clock provenance. That is one logical fact written twice, not a
// conflict, and it must converge without flagging anything.
func TestProjectAuthorityMerge_ConcurrentIdenticalClaimsConverge(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)

	for _, c := range []*Client{a, b} {
		if applied, err := ClaimInitialProjectAuthority(ctx, c, "acme", "node-1"); err != nil || !applied {
			t.Fatalf("claim: applied=%v err=%v", applied, err)
		}
	}
	// Different nodes, different clocks — the only thing that actually differed on
	// the lab.
	stampAuthority(t, a, "acme", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	stampAuthority(t, b, "acme", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipBoth(t, a, b)

	ra, rb := authorityRows(t, a), authorityRows(t, b)
	if len(ra) != 1 || len(rb) != 1 || ra[0] != rb[0] {
		t.Fatalf("authority rows did not converge — anti-entropy will re-report this drift every cycle:\n  a: %v\n  b: %v", ra, rb)
	}
	for name, c := range map[string]*Client{"a": a, "b": b} {
		if n := c.unresolvedLen.Load(); n != 0 {
			t.Errorf("node %s flagged %d unresolved tie(s) for two identical claims; "+
				"a duplicate write of the same fact is not a conflict and must not "+
				"burn the operator's divergence signal", name, n)
		}
	}
}

// TestProjectAuthorityMerge_DivergentHoldersConverge covers the /qa row the lab
// still carries from before the derived-holder fix: node-1 says node-1, everyone
// else says node-2, at the same epoch, unhealed for hours.
//
// Keeping local here is not the safe choice it is for an operation journal. Two
// nodes that each believe they hold /qa's authority both admit against its quota,
// which is the double-decider split the whole D1 design exists to prevent. So this
// converges deterministically — every node picks the same winner from the row
// content alone — and the fact that a conflict happened is still reported.
func TestProjectAuthorityMerge_DivergentHoldersConverge(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)

	if applied, err := ClaimInitialProjectAuthority(ctx, a, "qa", "node-1"); err != nil || !applied {
		t.Fatalf("claim on a: applied=%v err=%v", applied, err)
	}
	if applied, err := ClaimInitialProjectAuthority(ctx, b, "qa", "node-2"); err != nil || !applied {
		t.Fatalf("claim on b: applied=%v err=%v", applied, err)
	}
	stampAuthority(t, a, "qa", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	stampAuthority(t, b, "qa", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipBoth(t, a, b)

	ra, rb := authorityRows(t, a), authorityRows(t, b)
	if len(ra) != 1 || len(rb) != 1 || ra[0] != rb[0] {
		t.Fatalf("two nodes still disagree on who holds /qa — both will admit against its quota:\n  a: %v\n  b: %v", ra, rb)
	}

	// Whoever wins, every node must agree, and the survivor must be one of the two
	// real claimants rather than a merged hybrid.
	cur, ok, err := CurrentProjectAuthority(ctx, a, "qa")
	if err != nil || !ok {
		t.Fatalf("current authority: ok=%v err=%v", ok, err)
	}
	if cur.Holder != "node-1" && cur.Holder != "node-2" {
		t.Fatalf("converged holder %q is neither claimant", cur.Holder)
	}
}

// TestAuthorityClaimsConflict separates the two ways two rows differ. The merge
// tests above prove convergence either way, so they cannot tell a real conflict
// from timestamp provenance — and getting that distinction wrong is precisely the
// lab bug, just relocated from "drifts forever" to "warns forever".
func TestAuthorityClaimsConflict(t *testing.T) {
	cols := []string{"project", "authority_epoch", "holder", "transfer_kind",
		"fence_proof_ref", "created_at", "updated_at", "deleted_at"}
	const updatedAtIdx, deletedAtIdx = 6, 7
	claim := func(holder, kind, proof, created, updated string) []interface{} {
		return []interface{}{"acme", int64(1), holder, kind, proof, created, updated, ""}
	}

	for _, tc := range []struct {
		name            string
		local, incoming []interface{}
		want            bool
	}{{
		name:     "same claim, different per-node clocks",
		local:    claim("node-1", "initial", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		incoming: claim("node-1", "initial", "", "2026-01-01T00:00:05Z", "2026-01-01T00:00:09Z"),
		want:     false,
	}, {
		name:     "different holder is a real conflict",
		local:    claim("node-1", "initial", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		incoming: claim("node-2", "initial", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		want:     true,
	}, {
		name:     "different transfer kind is a real conflict",
		local:    claim("node-1", "planned", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		incoming: claim("node-1", "fenced", "proof:1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		want:     true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorityClaimsConflict(cols, tc.local, tc.incoming, updatedAtIdx, deletedAtIdx); got != tc.want {
				t.Fatalf("authorityClaimsConflict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProjectAuthorityMerge_ConvergenceIsOrderIndependent pins the property that
// makes convergence real rather than an artifact of who merged first: the winner
// is chosen from the row content, so a third node that hears the two claims in the
// opposite order lands on the same answer.
func TestProjectAuthorityMerge_ConvergenceIsOrderIndependent(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	if _, err := ClaimInitialProjectAuthority(ctx, a, "qa", "node-1"); err != nil {
		t.Fatalf("claim on a: %v", err)
	}
	if _, err := ClaimInitialProjectAuthority(ctx, b, "qa", "node-2"); err != nil {
		t.Fatalf("claim on b: %v", err)
	}
	stampAuthority(t, a, "qa", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	stampAuthority(t, b, "qa", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")
	dumpA, dumpB := a.DumpStateBytes(), b.DumpStateBytes()

	forward, backward := newTestDB(t), newTestDB(t)
	if err := forward.MergeStateBytesLWW(dumpA); err != nil {
		t.Fatalf("forward a: %v", err)
	}
	if err := forward.MergeStateBytesLWW(dumpB); err != nil {
		t.Fatalf("forward b: %v", err)
	}
	if err := backward.MergeStateBytesLWW(dumpB); err != nil {
		t.Fatalf("backward b: %v", err)
	}
	if err := backward.MergeStateBytesLWW(dumpA); err != nil {
		t.Fatalf("backward a: %v", err)
	}

	rf, rb := authorityRows(t, forward), authorityRows(t, backward)
	if len(rf) != 1 || len(rb) != 1 || rf[0] != rb[0] {
		t.Fatalf("delivery order changed the winner — the merge is not a CRDT join:\n  a-then-b: %v\n  b-then-a: %v", rf, rb)
	}
}
