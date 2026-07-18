package corrosion

import "testing"

// idRow is a natural-key group member for the resolver property tests.
type idRow struct{ updatedAt, id string }

// beats reports whether a wins over b under identityWinner.
func (a idRow) beats(b idRow) bool { return identityWinner(a.updatedAt, a.id, b.updatedAt, b.id) == 1 }

// sampleRows spans the axes the winner orders on: instant (newer/older, mixed RFC3339/HLC/
// fractional), and id (lexical order), including duplicates and an exact-instant tie.
var sampleRows = []idRow{
	{"2026-01-01T00:00:00Z", "id-a"},
	{"2026-01-01T00:00:00Z", "id-b"}, // same instant as id-a → id tiebreak
	{"2026-01-01T00:00:00.5Z", "id-c"}, // fractional: later instant, sorts lexically earlier
	{"2026-02-01T00:00:00Z", "id-a"},   // newer instant, small id
	{"2000000000000-0000-n1", "id-z"},  // HLC form
	{"2026-01-01T00:00:00Z", "id-a"},   // duplicate of the first (idempotence)
}

// TestIdentityWinner_Determinism pins the ordering rules.
func TestIdentityWinner_Determinism(t *testing.T) {
	// Newer instant wins regardless of id.
	if identityWinner("2026-02-01T00:00:00Z", "id-z", "2026-01-01T00:00:00Z", "id-a") != 1 {
		t.Error("newer instant must win even with a larger id")
	}
	// Fractional second is a later instant though it sorts lexically earlier.
	if identityWinner("2026-01-01T00:00:00.5Z", "id-a", "2026-01-01T00:00:00Z", "id-a") != 1 {
		t.Error("fractional-second instant must win (instant, not lexical)")
	}
	// Exact-instant tie → smaller id wins.
	if identityWinner("2026-01-01T00:00:00Z", "id-a", "2026-01-01T00:00:00Z", "id-b") != 1 {
		t.Error("on an instant tie the smaller id must win")
	}
	if identityWinner("2026-01-01T00:00:00Z", "id-b", "2026-01-01T00:00:00Z", "id-a") != -1 {
		t.Error("on an instant tie the larger id must lose")
	}
}

// TestIdentityWinner_Commutative: for distinct rows, swapping the arguments flips the sign
// (antisymmetry) — so the winner never depends on which side is "local".
func TestIdentityWinner_Commutative(t *testing.T) {
	for _, a := range sampleRows {
		for _, b := range sampleRows {
			ab := identityWinner(a.updatedAt, a.id, b.updatedAt, b.id)
			ba := identityWinner(b.updatedAt, b.id, a.updatedAt, a.id)
			if a == b {
				if ab != 1 || ba != 1 {
					t.Errorf("idempotent self-compare must be stable: %+v", a)
				}
				continue
			}
			if ab != -ba {
				t.Errorf("not antisymmetric for %+v vs %+v: ab=%d ba=%d", a, b, ab, ba)
			}
		}
	}
}

// TestIdentityWinner_Transitive: a beats b and b beats c ⇒ a beats c. Together with
// antisymmetry and totality this makes identityWinner a strict total order, so reducing a
// natural-key group is associative/commutative/idempotent (order- and topology-independent).
func TestIdentityWinner_Transitive(t *testing.T) {
	for _, a := range sampleRows {
		for _, b := range sampleRows {
			for _, c := range sampleRows {
				if a.beats(b) && b.beats(c) && !a.beats(c) {
					t.Errorf("not transitive: %+v > %+v > %+v but not %+v > %+v", a, b, c, a, c)
				}
			}
		}
	}
}

// reduceWinner folds a group to its single winner via pairwise identityWinner.
func reduceWinner(rows []idRow) idRow {
	w := rows[0]
	for _, r := range rows[1:] {
		if r.beats(w) {
			w = r
		}
	}
	return w
}

// TestIdentityWinner_OrderInvariant: the group winner is the SAME under every permutation of
// arrival order (the associativity/commutativity the three-node interleaving relies on).
func TestIdentityWinner_OrderInvariant(t *testing.T) {
	group := []idRow{
		{"2026-01-01T00:00:00Z", "id-b"},
		{"2026-01-01T00:00:00.5Z", "id-c"}, // latest instant → should always win
		{"2026-01-01T00:00:00Z", "id-a"},
		{"2025-12-01T00:00:00Z", "id-z"},
	}
	want := reduceWinner(group)
	var perms func([]idRow, int)
	seen := 0
	perms = func(a []idRow, k int) {
		if k == len(a) {
			seen++
			if got := reduceWinner(a); got != want {
				t.Errorf("permutation winner %+v != %+v", got, want)
			}
			return
		}
		for i := k; i < len(a); i++ {
			a[k], a[i] = a[i], a[k]
			perms(a, k+1)
			a[k], a[i] = a[i], a[k]
		}
	}
	perms(append([]idRow(nil), group...), 0)
	if want.id != "id-c" {
		t.Errorf("expected the latest-instant row (id-c) to win, got %+v", want)
	}
	if seen != 24 {
		t.Errorf("expected 24 permutations, ran %d", seen)
	}
}
