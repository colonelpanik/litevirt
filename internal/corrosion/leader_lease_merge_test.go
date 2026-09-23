package corrosion

import (
	"context"
	"fmt"
	"strings"
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
//   - appendOnlyTables makes a replicated INSERT apply as INSERT OR IGNORE ON THE
//     WAL PATH, so a stale peer cannot replay its losing claim over the converged
//     holder there.
//   - contentDefaultChain resolves an exact updated_at tie by a deterministic
//     total order over row content, so every node picks the same winner and the
//     executor's (term, holder) check agrees everywhere.
//
// Immutability is PATH-DEPENDENT and the distinction is load-bearing: the dump
// path compares updated_at first and reaches the content chain only on an exact
// tie, so a newer live row CAN replace an older tombstone there. Convergence
// holds on both paths; strict immutability holds only on the WAL path. See
// TestLeaseTermMerge_TombstoneLosesToANewerLiveRow, which pins the real
// behaviour rather than the tidier claim.
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

// TestLeaseTermMerge_ContestedTermIsFlaggedNotConverged is the case the table
// exists for, and its assertion is the opposite of what an earlier revision
// claimed.
//
// Two partitioned nodes each compute MAX(term)+1 = 1 and each name themselves
// holder. That earlier revision asserted the two nodes must CONVERGE on one
// holder, and the merge was registered to do exactly that. Both were wrong.
//
// Converging silently elects a winner for a question the cluster never agreed
// on: it destroys the losing claim, so no query can afterwards show that two
// nodes believed they held one tenure, and Phase-2 enforcement would read a
// confident (term, holder) answer with no indication it was invented by a
// tie-break. Worse, the two replication paths converged DIFFERENTLY — the WAL
// path first-writer-wins, the dump path last-writer-wins — so nodes refused
// opposite claimants and a WAL-converged node flipped its own answer on its next
// repair cycle.
//
// immutableMergeKeepLocalRow keeps each node's own claim and records an
// unresolved immutable_conflict. The nodes deliberately DISAGREE, and that
// disagreement is a durable, alertable safety fault instead of a coin flip.
func TestLeaseTermMerge_ContestedTermIsFlaggedNotConverged(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	sma, smb := &fakeSyncMetrics{}, &fakeSyncMetrics{}
	a.SetSyncMetrics(sma)
	b.SetSyncMetrics(smb)

	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	// Each node keeps its own claim: first-writer-wins locally, on both paths.
	for name, want := range map[string]string{"a": "host-a", "b": "host-b"} {
		c := map[string]*Client{"a": a, "b": b}[name]
		rows, err := c.Query(context.Background(),
			`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read term 1 on %s: err=%v rows=%d", name, err, len(rows))
		}
		if got := rows[0].String("holder"); got != want {
			t.Errorf("node %s resolved term 1 to %q, want its own claim %q — a contested "+
				"term must not be silently reassigned", name, got, want)
		}
	}

	// And both nodes RAISE it. Without this the disagreement above would just be
	// undetected divergence.
	for name, sm := range map[string]*fakeSyncMetrics{"a": sma, "b": smb} {
		sm.mu.Lock()
		unres := append([]string{}, sm.tieUnresolved...)
		sm.mu.Unlock()
		found := false
		for _, s := range unres {
			if strings.HasPrefix(s, "leader_lease_terms/") {
				found = true
			}
		}
		if !found {
			t.Errorf("node %s did not flag the contested term (saw %v). Two holders for one "+
				"tenure has to be observable, or it is just silent divergence", name, unres)
		}
	}
	if a.UnresolvedTieCount() == 0 || b.UnresolvedTieCount() == 0 {
		t.Error("the unresolved-tie GAUGE stayed 0; litevirt_lww_tie_unresolved_current is what " +
			"an operator alerts on for 'something is divergent now'")
	}
}

// TestLeaseTermMerge_IdenticalRowsAreQuiet pins that a converged table stops
// talking.
//
// A node re-delivering a claim it already holds must merge idempotently. The
// earlier version of this test asserted the same thing but could not fail:
// contentDefaultChain is [ruleTombstone, ruleContentMax] and neither rule can
// return decideUnresolved, so its central unresolvedLen == 0 check was vacuous.
// Under a merge that CAN flag a conflict the assertion has teeth — it now
// distinguishes an idempotent re-delivery from a genuine one.
func TestLeaseTermMerge_IdenticalRowsAreQuiet(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	sma, smb := &fakeSyncMetrics{}, &fakeSyncMetrics{}
	a.SetSyncMetrics(sma)
	b.SetSyncMetrics(smb)

	// The SAME claim on both nodes — same key, term and holder — differing only
	// in the per-node clock stamped into updated_at.
	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	for name, c := range map[string]*Client{"a": a, "b": b} {
		rows, err := c.Query(context.Background(),
			`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read on %s: err=%v rows=%d", name, err, len(rows))
		}
		if got := rows[0].String("holder"); got != "host-a" {
			t.Errorf("node %s holder = %q, want host-a", name, got)
		}
		if n := c.unresolvedLen.Load(); n != 0 {
			t.Errorf("node %s flagged %d unresolved tie(s) for ONE logical claim delivered "+
				"twice. updated_at is provenance, not a fact; counting it re-reports drift "+
				"on every anti-entropy cycle forever and burns the operator's signal", name, n)
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

// TestLeaseTermMerge_TombstoneDominatesRegardlessOfTimestamp: a tombstoned term
// must not come back from a peer still holding a live copy, whichever side's
// updated_at is newer. Resurrecting a term moves MAX(term) backwards on that
// node, and the rejection threshold must never regress.
//
// Two revisions of this test were wrong in instructive ways. The first asserted
// tombstone dominance on the DEFAULT chain, where it held only on an exact
// updated_at tie — the dump path compares updated_at first and never reached
// ruleTombstone otherwise. The second recorded that as documented behaviour and
// proved it with `updated_at = "2999-01-01T00:00:00Z"`, which production's
// future-skew quarantine refuses outright once LWWSkewGuardV1 is latched
// (sync.go reads hlcSkewGuardOn; the test client leaves it nil, so the guard was
// simply off) — so the load-bearing claim was pinned by a merge that half the
// cluster configurations would reject.
//
// Both are fixed by the custom merge: tombstoneDominates runs FIRST, before any
// timestamp compare, so the delta below is a realistic few seconds and the
// assertion holds under either latch state.
func TestLeaseTermMerge_TombstoneDominatesRegardlessOfTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name              string
		localTS, remoteTS string
	}{
		{"incoming live row is newer", "2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:05.000000Z"},
		{"exact tie", "2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.000000Z"},
		{"local tombstone is newer", "2026-01-01T00:00:05.000000Z", "2026-01-01T00:00:00.000000Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newTestDB(t), newTestDB(t)

			// Node a tombstoned term 1; node b still holds it live.
			putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", tc.localTS)
			tombstoneLeaseTerm(t, a, "failover", 1, "2026-01-01T00:00:30Z")
			putLeaseTerm(t, b, "failover", 1, "host-a", "2026-01-01T00:00:00Z", tc.remoteTS)

			if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
				t.Fatalf("merge b→a: %v", err)
			}

			rows, err := a.Query(context.Background(),
				`SELECT COALESCE(deleted_at, '') AS del FROM leader_lease_terms
				 WHERE key = 'failover' AND term = 1`)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(rows) == 0 {
				return // row gone entirely is also a dominated tombstone
			}
			if rows[0].String("del") == "" {
				t.Errorf("a delayed live copy resurrected a tombstoned term. The GC "+
					"prohibition at nextLeaseTerm rests on this holding on BOTH paths and "+
					"at any timestamp delta (case: %s)", tc.name)
			}
		})
	}
}

// TestLeaseTermMerge_IsRegisteredEverywhere is the wiring test, and every
// assertion in it is the reverse of the version that shipped first.
//
// That version asserted NO customMergeTables entry, on the analogy to
// audit_chain_heads — append-only, composite key, default content chain. The
// analogy failed on the one property that matters: audit_chain_heads has a
// PER-HOST primary key, so two nodes never contend for one row, while
// (key, term) is contended by construction. With contention reachable, the WAL
// and anti-entropy paths resolved it by different rules.
func TestLeaseTermMerge_IsRegisteredEverywhere(t *testing.T) {
	if customMergeTables["leader_lease_terms"] == nil {
		t.Error("leader_lease_terms has no customMergeTables entry, so the anti-entropy path " +
			"resolves a contested term by LWW on updated_at while the WAL path resolves it " +
			"first-writer-wins — nodes then refuse opposite claimants for the same term")
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
	if appendOnlyTables["leader_lease_terms"] {
		t.Error("leader_lease_terms is in appendOnlyTables AND customMergeTables. " +
			"deriveDisposition checks customMergeTables first, so the append-only entry is " +
			"unreachable and only creates a second source of truth that can drift")
	}
	if _, ok := capabilityMap["leader_lease_terms"]; ok {
		t.Error("leader_lease_terms is in capabilityMap as well as customMergeTables; " +
			"TestCapabilityMap_PartitionsSchema requires exactly one bucket")
	}
	if !reseedKeepTables["leader_lease_terms"] {
		t.Error("leader_lease_terms is not in reseedKeepTables, so a reseed DELETEs the whole " +
			"term ledger. The terms an isolated node minted are exactly the ones the peer it " +
			"reseeds from never received, so MAX(term) regresses and a term number is reused")
	}
	if !proofDropExemptTables["leader_lease_terms"] {
		t.Error("leader_lease_terms is not proof-drop exempt. Its mint is co-batched with the " +
			"leader_election upsert, and leader_election is anti-entropy excluded — so " +
			"dropping the entry for a peer lacking proof support would stop replicating " +
			"lease ownership with no repair path")
	}
}
