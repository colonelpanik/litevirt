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
// The answer changed when the table moved to a custom merge, and it changed in
// the operator's favour. Under the default LWW chain only an exact-timestamp
// collision produced a signal; a collision a second apart was resolved silently
// by updated_at, with the losing holder overwritten and nothing counted. Under
// immutableMergeKeepLocalRow, ANY genuine conflict is flagged regardless of the
// timestamp delta.

// TestLeaseTermObservability_ConflictIsFlaggedAtAnyTimestampDelta is the
// property the docs now rest on.
func TestLeaseTermObservability_ConflictIsFlaggedAtAnyTimestampDelta(t *testing.T) {
	for _, tc := range []struct {
		name              string
		localTS, remoteTS string
	}{
		{"exact tie", "2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.000000Z"},
		{"seconds apart", "2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:05.000000Z"},
		{"incoming older", "2026-01-01T00:00:05.000000Z", "2026-01-01T00:00:00.000000Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newTestDB(t), newTestDB(t)
			sm := &fakeSyncMetrics{}
			a.SetSyncMetrics(sm)

			putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", tc.localTS)
			putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:00Z", tc.remoteTS)

			if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
				t.Fatalf("merge b→a: %v", err)
			}

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
				t.Errorf("two holders for term 1 (%s) produced no unresolved-tie signal "+
					"(saw %v). docs/operating-model.md points operators at "+
					"litevirt_lww_tie_unresolved_total for this table", tc.name, unres)
			}
			if a.UnresolvedTieCount() == 0 {
				t.Error("the unresolved-tie gauge stayed 0; litevirt_lww_tie_unresolved_current " +
					"is the 'divergent now' alert")
			}

			// And the local claim is kept, not overwritten by the newer row.
			rows, err := a.Query(context.Background(),
				`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read: err=%v rows=%d", err, len(rows))
			}
			if got := rows[0].String("holder"); got != "host-a" {
				t.Errorf("local holder was rewritten to %q; a term row must be immutable "+
					"on this path too, or the WAL and dump paths disagree", got)
			}
		})
	}
}

// TestLeaseTermObservability_OneRowPerTermIsStructural: the composite primary key
// makes "two rows for one term" unrepresentable, so no single node's query can
// surface a contested term.
//
// An earlier draft of the operator documentation told people to look for exactly
// that. This test exists so the claim cannot come back: SQLite refuses the second
// row outright. The conflict is visible in the METRIC and in the disagreement
// BETWEEN nodes, never as two rows on one node.
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
