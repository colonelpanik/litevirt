package corrosion

import (
	"context"
	"strings"
	"testing"
)

// These tests pin what an operator can ACTUALLY observe when two nodes claim one
// lease term, because docs/operating-model.md tells operators where to look and
// a documented signal that does not fire is worse than no documentation.
//
// The short answer, established below: after convergence the losing claimant is
// GONE from leader_lease_terms, and a signal fires only when the two claims
// carry the exact same updated_at. Different timestamps are ordinary LWW and are
// completely silent.

// TestLeaseTermObservability_EqualTimestampsFireATieBreak: two claims for one
// term with the SAME updated_at reach the content chain, and the tie-break is
// counted against this table.
//
// This is the case a `litevirt_lww_tie_break_total{table="leader_lease_terms"}`
// alert can catch.
func TestLeaseTermObservability_EqualTimestampsFireATieBreak(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	sm := &fakeSyncMetrics{}
	b.SetSyncMetrics(sm)

	const ts = "2026-01-01T00:00:00.000000Z"
	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", ts)
	putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:00Z", ts)

	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("merge a→b: %v", err)
	}

	var got []string
	sm.mu.Lock()
	got = append(got, sm.tieBreaks...)
	sm.mu.Unlock()

	found := false
	for _, s := range got {
		if strings.HasPrefix(s, "leader_lease_terms/") {
			found = true
		}
	}
	if !found {
		t.Errorf("two same-timestamp claims for one term produced no tie-break for "+
			"leader_lease_terms (saw %v). docs/operating-model.md points operators at "+
			"litevirt_lww_tie_break_total for this table; if nothing fires, that "+
			"instruction is wrong", got)
	}
}

// TestLeaseTermObservability_DifferentTimestampsAreSilent is the uncomfortable
// half, and the reason the docs must not promise a signal.
//
// The anti-entropy dump path compares updated_at FIRST and only reaches the
// content chain on an exact tie. Two nodes that mint the same term a second
// apart are therefore resolved as ordinary LWW: the newer row wins, the losing
// holder is overwritten, and NOTHING is counted. A concurrent-leadership episode
// can pass through this table leaving no trace at all.
func TestLeaseTermObservability_DifferentTimestampsAreSilent(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	sm := &fakeSyncMetrics{}
	b.SetSyncMetrics(sm)

	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("merge a→b: %v", err)
	}

	sm.mu.Lock()
	ties := append([]string{}, sm.tieBreaks...)
	unres := append([]string{}, sm.tieUnresolved...)
	sm.mu.Unlock()

	for _, s := range append(ties, unres...) {
		if strings.HasPrefix(s, "leader_lease_terms/") {
			t.Errorf("a different-timestamp concurrent claim produced signal %q; if this "+
				"now fires, docs/operating-model.md understates what is observable and "+
				"should be corrected in the operator's favour", s)
		}
	}

	// And the losing claimant is not recoverable from the table.
	rows, err := b.Query(context.Background(),
		`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read converged holder: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("holder"); got != "host-b" {
		t.Errorf("converged holder = %q, want host-b (the newer updated_at)", got)
	}
}

// TestLeaseTermObservability_OneRowPerTermIsStructural: the composite primary key
// makes "two rows for one term" unrepresentable, so no query can surface a
// contested term after the fact.
//
// An earlier draft of the operator documentation told people to look for exactly
// that. This test exists so the claim cannot come back: SQLite refuses the second
// row outright.
func TestLeaseTermObservability_OneRowPerTermIsStructural(t *testing.T) {
	c := newTestDB(t)

	if _, err := c.db.Exec(
		`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES ('failover', 1, 'host-a', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	_, err := c.db.Exec(
		`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES ('failover', 1, 'host-b', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	if err == nil {
		t.Fatal("a second holder for one term was accepted; the operator query for " +
			"'two rows sharing key and term' would then be meaningful, and the docs " +
			"should say so")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Errorf("second claim rejected by %v, expected a UNIQUE constraint failure", err)
	}
}
