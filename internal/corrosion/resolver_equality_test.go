package corrosion

import "testing"

// Order-invariant equality short-circuit in resolveTie.
//
// policyChain = [ruleTombstone, ruleUnresolved] has no content-equality gate: any equal-timestamp,
// non-tombstoned policy row that reaches resolveTie is flagged unresolved — even when the two row
// images are actually equal (identical values, or a value that decodes as int64 locally from SQL but
// float64 from the JSON dump). That inflates litevirt_lww_tie_unresolved_current with false
// positives. The short-circuit compares the two rows under the order-invariant, type-normalized
// encodeRowCellsV2 and, if equal, resolves without tracking a tie — while a GENUINE difference (or a
// tombstone race) still flows through the chain unchanged.

// TestResolver_IdenticalPolicyRowNotTracked: identical rows at equal timestamp are not a conflict.
func TestResolver_IdenticalPolicyRowNotTracked(t *testing.T) {
	cols := []string{"name", "description", "updated_at"}
	c, sm, keepLocal, unresolved := resolve(t, "roles", cols,
		[]interface{}{"admin", "cfg", "T"},
		[]interface{}{"admin", "cfg", "T"})
	if unresolved || c.UnresolvedTieCount() != 0 || len(sm.tieUnresolved) != 0 {
		t.Fatalf("identical policy row must not be tracked as a tie: unresolved=%v count=%d metric=%v",
			unresolved, c.UnresolvedTieCount(), sm.tieUnresolved)
	}
	if !keepLocal {
		t.Fatalf("identical row must keep local (no write needed)")
	}
}

// TestResolver_IntFloatSameValueNotTracked: the real anti-entropy case — the local cell scans from
// SQLite as int64, the incoming cell decodes from the JSON dump as float64. Same value ⇒ equal under
// the type-normalizing v2 encoding ⇒ not a tie.
func TestResolver_IntFloatSameValueNotTracked(t *testing.T) {
	cols := []string{"name", "quota", "updated_at"}
	c, sm, keepLocal, unresolved := resolve(t, "roles", cols,
		[]interface{}{"admin", int64(5), "T"},   // local: SQL scan
		[]interface{}{"admin", float64(5), "T"}) // incoming: JSON dump
	if unresolved || c.UnresolvedTieCount() != 0 || len(sm.tieUnresolved) != 0 {
		t.Fatalf("int64-vs-float64 of the same value must not be tracked: unresolved=%v count=%d",
			unresolved, c.UnresolvedTieCount())
	}
	if !keepLocal {
		t.Fatalf("equal-value row must keep local")
	}
}

// TestResolver_GenuinePolicyDiffStillTracked: a genuine equal-timestamp content difference must
// still be flagged (the safety signal is preserved).
func TestResolver_GenuinePolicyDiffStillTracked(t *testing.T) {
	cols := []string{"name", "description", "updated_at"}
	c, sm, _, unresolved := resolve(t, "roles", cols,
		[]interface{}{"admin", "cfgA", "T"},
		[]interface{}{"admin", "cfgB", "T"})
	if !unresolved || c.UnresolvedTieCount() != 1 || len(sm.tieUnresolved) != 1 {
		t.Fatalf("a genuine equal-TS policy difference must still be tracked: unresolved=%v count=%d metric=%v",
			unresolved, c.UnresolvedTieCount(), sm.tieUnresolved)
	}
}

// TestResolver_GenuineNumericDiffStillTracked: the fail-safe direction — a real numeric difference is
// never suppressed.
func TestResolver_GenuineNumericDiffStillTracked(t *testing.T) {
	cols := []string{"name", "quota", "updated_at"}
	c, _, _, unresolved := resolve(t, "roles", cols,
		[]interface{}{"admin", int64(5), "T"},
		[]interface{}{"admin", int64(6), "T"})
	if !unresolved || c.UnresolvedTieCount() != 1 {
		t.Fatalf("a genuine numeric difference must still be tracked: unresolved=%v count=%d",
			unresolved, c.UnresolvedTieCount())
	}
}

// TestResolver_TombstoneRaceStillResolves: a tombstone race (live vs deleted, else identical) differs
// in deleted_at, so the full-row compare is NOT equal — it falls through to ruleTombstone and
// resolves (delete wins), rather than being swallowed by the equality short-circuit.
func TestResolver_TombstoneRaceStillResolves(t *testing.T) {
	cols := []string{"name", "description", "updated_at", "deleted_at"}
	c, _, keepLocal, unresolved := resolve(t, "roles", cols,
		[]interface{}{"admin", "cfg", "T", ""},                     // local: live
		[]interface{}{"admin", "cfg", "T", "2026-01-01T00:00:00Z"}) // incoming: tombstoned
	if unresolved || c.UnresolvedTieCount() != 0 {
		t.Fatalf("a tombstone race must resolve, not be tracked as unresolved: unresolved=%v count=%d",
			unresolved, c.UnresolvedTieCount())
	}
	if keepLocal {
		t.Fatalf("the incoming tombstone must win (take incoming), got keepLocal=true")
	}
}
