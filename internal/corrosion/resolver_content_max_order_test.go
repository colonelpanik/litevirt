package corrosion

import "testing"

// TestRuleContentMax_IsOrderInvariant is the #214 regression.
//
// ruleContentMax compared rows with the POSITIONAL encodeRowCells, while the
// rows it compares are aligned to the INCOMING dump's declared column order
// (fetchLocalRowCells re-reads the local row against table.Columns). Two nodes
// resolving the same pair therefore encode it in two different orders — the
// sender's — and the "lexically greater" winner can differ between them.
//
// When it does, each node keeps its own row and BOTH record a resolved
// content_max tie-break, so lww_tie_unresolved never fires and the permanent
// digest mismatch has nothing pointing at it. ~38 tables end on this chain.
//
// The values below are chosen so the positional comparison flips: under [a, b]
// the local row sorts higher, under [b, a] the incoming one does.
func TestRuleContentMax_IsOrderInvariant(t *testing.T) {
	rule := ruleContentMax()

	// One logical pair of rows: local{a:"9", b:"1"} vs incoming{a:"1", b:"9"}.
	underAB := rule(newRowView(
		[]string{"a", "b"},
		[]interface{}{"9", "1"},
		[]interface{}{"1", "9"},
	))
	// The SAME pair, expressed in the other physical column order.
	underBA := rule(newRowView(
		[]string{"b", "a"},
		[]interface{}{"1", "9"},
		[]interface{}{"9", "1"},
	))

	if !underAB.decided || !underBA.decided {
		t.Fatalf("content_max must decide: ab=%+v ba=%+v", underAB, underBA)
	}
	if underAB.unresolved || underBA.unresolved {
		t.Fatalf("a well-formed row pair must not be unresolved: ab=%+v ba=%+v", underAB, underBA)
	}
	if underAB.keepLocal != underBA.keepLocal {
		t.Fatalf("content_max picked a different winner for the same rows under a different "+
			"column order: [a b] keepLocal=%v, [b a] keepLocal=%v — the two nodes each keep "+
			"their own row and never converge", underAB.keepLocal, underBA.keepLocal)
	}
}

// The winner must also be symmetric: whichever row wins, the node holding the
// other one must agree. Swapping local and incoming has to flip keepLocal, or
// both nodes keep local and the pair is stuck exactly as in #214.
func TestRuleContentMax_IsSymmetric(t *testing.T) {
	rule := ruleContentMax()
	cols := []string{"a", "b"}
	rowHi := []interface{}{"9", "1"}
	rowLo := []interface{}{"1", "9"}

	// Node holding rowHi sees incoming rowLo.
	onHi := rule(newRowView(cols, rowHi, rowLo))
	// Node holding rowLo sees incoming rowHi.
	onLo := rule(newRowView(cols, rowLo, rowHi))

	if onHi.keepLocal == onLo.keepLocal {
		t.Fatalf("both nodes made the same keepLocal=%v decision — the same row must win "+
			"on both sides, or neither converges", onHi.keepLocal)
	}
}

// Order invariance must not come at the cost of deciding: a real difference
// still has to produce a winner, not an unresolved tie.
func TestRuleContentMax_StillDecidesARealDifference(t *testing.T) {
	rule := ruleContentMax()
	d := rule(newRowView(
		[]string{"name", "value"},
		[]interface{}{"host-a", "2"},
		[]interface{}{"host-a", "1"},
	))
	if !d.decided || d.unresolved {
		t.Fatalf("a plain content difference must resolve, got %+v", d)
	}
	if !d.keepLocal {
		t.Errorf("local value %q sorts above incoming %q, so local should win", "2", "1")
	}
	if d.resolver != "content_max" {
		t.Errorf("resolver = %q, want content_max", d.resolver)
	}
}

// A row image the order-invariant encoder cannot encode (duplicate column
// names — ErrDupColumn, which the encoder treats as corruption) must NOT fall
// back to the positional comparison that cannot converge. There is no
// deterministic winner to pick, so it is a fail-to-human.
func TestRuleContentMax_UnencodableRowIsUnresolved(t *testing.T) {
	rule := ruleContentMax()
	d := rule(newRowView(
		[]string{"dup", "dup"},
		[]interface{}{"1", "2"},
		[]interface{}{"2", "1"},
	))
	if !d.unresolved {
		t.Fatalf("a row with duplicate column names has no order-invariant encoding, so it "+
			"must be reported unresolved rather than silently compared positionally; got %+v", d)
	}
}

// authorityJoinKeepLocal has the same defect ruleContentMax had, in a second
// place: it is a cross-node winner selection over the POSITIONAL encoding, on
// rows aligned to the incoming dump's column order. authorityMergeRow's own doc
// comment states the property this breaks — "a total order over the row's
// canonical bytes ... Every node computes it from row content alone, so the
// result is independent of who merged first".
//
// Non-convergence is worse here than for a content table: two nodes each
// believing they hold a project's authority both admit against its quota, which
// is the double-decider split the immutable merge exists to prevent.
func TestAuthorityJoin_IsOrderInvariant(t *testing.T) {
	underAB, okAB := authorityJoinKeepLocal(
		[]string{"a", "b"},
		[]interface{}{"9", "1"},
		[]interface{}{"1", "9"},
	)
	underBA, okBA := authorityJoinKeepLocal(
		[]string{"b", "a"},
		[]interface{}{"1", "9"},
		[]interface{}{"9", "1"},
	)
	if !okAB || !okBA {
		t.Fatalf("a well-formed row pair must yield an order: ab=%v ba=%v", okAB, okBA)
	}
	if underAB != underBA {
		t.Fatalf("the authority join picked a different winner for the same rows under a "+
			"different column order: [a b] keepLocal=%v, [b a] keepLocal=%v — both nodes keep "+
			"their own authority row and both keep admitting against the project's quota",
			underAB, underBA)
	}
}

// Symmetry, for the same reason as content_max: the same row must win on both
// sides or neither node moves.
func TestAuthorityJoin_IsSymmetric(t *testing.T) {
	cols := []string{"a", "b"}
	hi := []interface{}{"9", "1"}
	lo := []interface{}{"1", "9"}

	onHi, _ := authorityJoinKeepLocal(cols, hi, lo)
	onLo, _ := authorityJoinKeepLocal(cols, lo, hi)
	if onHi == onLo {
		t.Fatalf("both sides decided keepLocal=%v — the join is not a total order", onHi)
	}
}

// With no order-invariant encoding available, the caller must be told rather
// than handed a non-convergent positional answer.
func TestAuthorityJoin_UnencodableRowIsNotOK(t *testing.T) {
	_, ok := authorityJoinKeepLocal(
		[]string{"dup", "dup"},
		[]interface{}{"1", "2"},
		[]interface{}{"2", "1"},
	)
	if ok {
		t.Fatal("duplicate column names have no order-invariant encoding; ok must be false")
	}
}
