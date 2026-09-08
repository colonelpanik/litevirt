package corrosion

import (
	"context"
	"fmt"
	"testing"
)

// leader_lease_terms is the second table whose primary key two nodes can
// legitimately mint concurrently, and the reason is structural rather than
// incidental: the term is computed as MAX(term)+1 locally, so two partitioned
// nodes that both see an expired lease necessarily arrive at the SAME number
// with different holders. That is the two-leaders episode the ledger exists to
// record, not a fault.
//
// It needs NO bespoke merge, which was not obvious and is worth recording. The
// registration that makes it correct is the same one audit_chain_heads uses —
// append-only plus the default content chain:
//
//   - appendOnlyTables makes a replicated INSERT apply as INSERT OR IGNORE, so a
//     row is immutable once written and a stale peer cannot replay its losing
//     claim over the converged holder.
//   - contentDefaultChain resolves an exact updated_at tie by a deterministic
//     total order over row content, so every node picks the same winner and the
//     executor's (term, holder) check agrees everywhere.
//
// project_authority_epochs needs a custom merge for a different reason: its rows
// are MUTABLE for one primary key, and the immutable merge wrongly froze them.
// Putting the term in the primary key here — done to stop LWW deciding a mutable
// counter — also removed any need for a bespoke merge.

// leaseTermRows returns every leader_lease_terms row as a canonical string, so
// two nodes' tables can be compared byte-for-byte including the timestamps that
// anti-entropy's drift report also sees.
func leaseTermRows(t *testing.T, c *Client) []string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT key, term, holder, acquired_at, created_at, updated_at,
		        COALESCE(deleted_at, '') AS del
		 FROM leader_lease_terms ORDER BY key, term`)
	if err != nil {
		t.Fatalf("query lease term rows: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s/%d holder=%s acquired=%s created=%s updated=%s deleted=%s",
			r.String("key"), r.Int64("term"), r.String("holder"), r.String("acquired_at"),
			r.String("created_at"), r.String("updated_at"), r.String("del")))
	}
	return out
}

// putLeaseTerm writes a term row directly. Task 3's mint API does not exist
// yet, and these tests are about the MERGE, so the writer is deliberately not
// under test here.
func putLeaseTerm(t *testing.T, c *Client, key string, term int64, holder, createdAt, updatedAt string) {
	t.Helper()
	if _, err := c.db.Exec(
		`INSERT OR REPLACE INTO leader_lease_terms
		   (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		key, term, holder, createdAt, createdAt, updatedAt); err != nil {
		t.Fatalf("put lease term %s/%d: %v", key, term, err)
	}
}

func tombstoneLeaseTerm(t *testing.T, c *Client, key string, term int64, deletedAt string) {
	t.Helper()
	if _, err := c.db.Exec(
		`UPDATE leader_lease_terms SET deleted_at = ? WHERE key = ? AND term = ?`,
		deletedAt, key, term); err != nil {
		t.Fatalf("tombstone lease term %s/%d: %v", key, term, err)
	}
}

// gossipLeaseTerms merges each node's full state into the other, the way
// anti-entropy does. Driving the real path matters: these assertions are about
// what the CLUSTER converges on, and a test that reached into the resolver
// directly would pass against rules the merge path never applies.
func gossipLeaseTerms(t *testing.T, a, b *Client) {
	t.Helper()
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("merge a→b: %v", err)
	}
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatalf("merge b→a: %v", err)
	}
}

// TestLeaseTermMerge_ConcurrentClaimantsConverge is the case the table exists
// for: two partitioned nodes each compute MAX(term)+1 = 1 and each name
// themselves holder.
//
// Both rows are legitimate. What must not happen is the two nodes ending up
// believing different things about who held term 1, because the executor's
// (term, holder) check would then refuse the loser on one node and accept it on
// another — which is not fencing, it is a coin flip per node.
func TestLeaseTermMerge_ConcurrentClaimantsConverge(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)

	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	ra, rb := leaseTermRows(t, a), leaseTermRows(t, b)
	if len(ra) != 1 || len(rb) != 1 || ra[0] != rb[0] {
		t.Fatalf("two nodes disagree about who held term 1, so the executor's (term, holder) "+
			"check refuses the loser on one node and accepts it on another:\n  a: %v\n  b: %v", ra, rb)
	}

	// The survivor must be one of the two real claimants, never a merged hybrid.
	holder := ""
	rows, err := a.Query(context.Background(),
		`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read converged holder: err=%v rows=%d", err, len(rows))
	}
	holder = rows[0].String("holder")
	if holder != "host-a" && holder != "host-b" {
		t.Fatalf("converged holder %q is neither claimant", holder)
	}
}

// TestLeaseTermMerge_IdenticalRowsAreQuiet pins that a converged table stops
// talking.
//
// authorityMergeRow's comment records the bug this prevents: created_at is a
// per-node wall clock, so counting it as a fact made two identical logical
// claims look like a conflict, and an idle cluster re-reported the drift every
// anti-entropy cycle — burning the operator's divergence signal permanently.
func TestLeaseTermMerge_IdenticalRowsAreQuiet(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)

	// Same facts — same key, term and holder — differing only in the per-node
	// clock stamped into created_at/updated_at.
	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-a", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	ra, rb := leaseTermRows(t, a), leaseTermRows(t, b)
	if len(ra) != 1 || len(rb) != 1 || ra[0] != rb[0] {
		t.Fatalf("one logical claim written twice did not converge:\n  a: %v\n  b: %v", ra, rb)
	}
	for name, c := range map[string]*Client{"a": a, "b": b} {
		if n := c.unresolvedLen.Load(); n != 0 {
			t.Errorf("node %s flagged %d unresolved tie(s) for one claim written twice; "+
				"timestamp provenance is not a fact, and counting it re-reports drift on "+
				"every cycle forever", name, n)
		}
	}
}

// TestLeaseTermMerge_TermsDoNotCompete pins that terms are separate rows, not
// rivals. (key, term) is the primary key, so term 2 arriving must never displace
// term 1 — losing retained history is what would let the counter restart, which
// is the whole reason the term is in the key rather than a mutable column.
func TestLeaseTermMerge_TermsDoNotCompete(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)

	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 2, "host-b", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	for name, c := range map[string]*Client{"a": a, "b": b} {
		got := leaseTermRows(t, c)
		if len(got) != 2 {
			t.Errorf("node %s retained %d of 2 terms (%v); a lost term is a counter that can "+
				"restart", name, len(got), got)
		}
		rows, err := c.Query(context.Background(),
			`SELECT COALESCE(MAX(term), 0) AS m FROM leader_lease_terms WHERE key = 'failover'`)
		if err != nil {
			t.Fatalf("max term on %s: %v", name, err)
		}
		if m := rows[0].Int64("m"); m != 2 {
			t.Errorf("node %s reports MAX(term) = %d, want 2 — the rejection threshold is wrong",
				name, m)
		}
	}
}

// TestLeaseTermMerge_TombstoneDominates pins that a GC'd term does not come back
// from a peer still holding a live copy. Resurrecting a term would move
// MAX(term) backwards on that node, and the threshold must never regress.
func TestLeaseTermMerge_TombstoneDominates(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)

	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	tombstoneLeaseTerm(t, a, "failover", 1, "2026-01-02T00:00:00Z")

	gossipLeaseTerms(t, a, b)

	for name, c := range map[string]*Client{"a": a, "b": b} {
		rows, err := c.Query(context.Background(),
			`SELECT COALESCE(deleted_at, '') AS del FROM leader_lease_terms
			 WHERE key = 'failover' AND term = 1`)
		if err != nil {
			t.Fatalf("read tombstone on %s: %v", name, err)
		}
		if len(rows) == 0 {
			continue // row gone entirely is also a dominated tombstone
		}
		if rows[0].String("del") == "" {
			t.Errorf("node %s resurrected a tombstoned term from a delayed live copy", name)
		}
	}
}

// The WAL-path immutability test that belongs here — a stale peer's replayed
// INSERT must not rewrite a term's holder — lives with Task 3 instead. It needs
// a statement shape registered in the compatibility ledger, and a shape may only
// be registered once a real caller emits it ("a registered shape with no emitter
// never reaches a peer"), so it cannot exist before the mint API does.
//
// That is a genuine gap in THIS task's coverage: appendOnlyTables is registered
// below but nothing here proves it takes effect, because the four tests above
// drive the anti-entropy dump path and appendOnlyTables governs the WAL path.

// TestLeaseTermMerge_IsRegisteredEverywhere is the wiring test.
//
// Deliberately NOT asserting a customMergeTables entry. This table needs no
// bespoke merge: appendOnlyTables makes rows immutable on the WAL path and
// contentDefaultChain converges an exact tie deterministically, which is exactly
// how audit_chain_heads — append-only with (host_name, epoch, seq) in its key —
// is registered. project_authority_epochs needs a custom merge because its rows
// are MUTABLE for one primary key and the immutable merge was wrongly freezing
// them; nothing here enters that bucket.
func TestLeaseTermMerge_IsRegisteredEverywhere(t *testing.T) {
	if _, ok := customMergeTables["leader_lease_terms"]; ok {
		t.Error("leader_lease_terms has a customMergeTables entry. It does not need one — see " +
			"this test's comment — and a bespoke merge that duplicates contentDefaultChain is " +
			"a second implementation of the same rules, free to drift from it")
	}
	var inSync bool
	for _, n := range tableNames {
		if n == "leader_lease_terms" {
			inSync = true
			break
		}
	}
	if !inSync {
		t.Error("leader_lease_terms is not in tableNames, so anti-entropy never repairs it; a node " +
			"that missed a replicated term keeps a low MAX(term) and under-fences forever")
	}
	if !appendOnlyTables["leader_lease_terms"] {
		t.Error("leader_lease_terms is not in appendOnlyTables, so a replicated INSERT is LWW-gated " +
			"rather than INSERT OR IGNORE")
	}
	if _, ok := capabilityMap["leader_lease_terms"]; !ok {
		t.Error("leader_lease_terms has no capabilityMap entry")
	}
}
