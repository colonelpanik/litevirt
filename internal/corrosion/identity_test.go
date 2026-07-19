package corrosion

import "testing"

// idRow is a natural-key group member for the resolver tests: an update instant, an id, and the
// non-id content that decides an exact-instant tie.
type idRow struct{ updatedAt, id, content string }

// decide runs resolveIdentity for `in` arriving at a slot holding `local` (or empty when absent),
// with content equality driven by the rows' content field.
func decide(haveLocal bool, local, in idRow) identityDisposition {
	d, err := resolveIdentity(haveLocal, local.updatedAt, local.id, in.updatedAt, in.id, func() (bool, error) {
		return local.content == in.content, nil
	})
	if err != nil {
		panic(err)
	}
	return d
}

// TestResolveIdentity_DecisionMatrix pins every branch of the resolver.
func TestResolveIdentity_DecisionMatrix(t *testing.T) {
	const older, newer = "1000000000000-0000-a", "2000000000000-0000-b"
	cases := []struct {
		name      string
		have      bool
		local, in idRow
		want      identityDisposition
	}{
		{"first-seen", false, idRow{}, idRow{newer, "id-x", "c"}, idApplyNew},
		{"local-newer", true, idRow{newer, "id-a", "c"}, idRow{older, "id-b", "c"}, idKeepLocal},
		{"incoming-newer-same-id", true, idRow{older, "id-a", "c"}, idRow{newer, "id-a", "c2"}, idAdoptSameID},
		{"incoming-newer-diff-id", true, idRow{older, "id-a", "c"}, idRow{newer, "id-b", "c2"}, idCollapse},
		{"tie-equal-content-incoming-smaller", true, idRow{older, "id-b", "same"}, idRow{older, "id-a", "same"}, idCollapse},
		{"tie-equal-content-local-smaller", true, idRow{older, "id-a", "same"}, idRow{older, "id-b", "same"}, idKeepLocal},
		{"tie-different-content", true, idRow{older, "id-a", "x"}, idRow{older, "id-b", "y"}, idContentFault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(tc.have, tc.local, tc.in); got != tc.want {
				t.Errorf("resolveIdentity = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveIdentity_ContentErrorPropagates: a failed content read on a tie must surface (fail
// closed), never be treated as "equal" and silently collapse.
func TestResolveIdentity_ContentErrorPropagates(t *testing.T) {
	_, err := resolveIdentity(true, "1000000000000-0000-a", "id-a", "1000000000000-0000-a", "id-b",
		func() (bool, error) { return false, errTest })
	if err == nil {
		t.Fatal("a content-read error on a tie must propagate")
	}
}

var errTest = errTestType("boom")

type errTestType string

func (e errTestType) Error() string { return string(e) }

// TestIdentityCellEqual: NULL is DISTINCT from empty string (finding 1); int/float of the same
// value are equal (JSON round-trip normalization).
func TestIdentityCellEqual(t *testing.T) {
	if !identityCellEqual(nil, nil) {
		t.Error("nil must equal nil")
	}
	if identityCellEqual(nil, "") || identityCellEqual("", nil) {
		t.Error("NULL must be DISTINCT from empty string")
	}
	if !identityCellEqual(int64(5), float64(5)) {
		t.Error("int64(5) and float64(5) must compare equal")
	}
	if identityCellEqual("a", "b") {
		t.Error("distinct present values must be unequal")
	}
}

// TestIdentityContentEquivalent: proves equivalence only over a COMPLETE local image (finding 2),
// with NULL distinct from "" (finding 1).
func TestIdentityContentEquivalent(t *testing.T) {
	localCols := []string{"id", "vm_name", "name", "deleted_at"}
	local := []interface{}{"id-a", "vm1", "snap1", nil} // deleted_at NULL = live

	// Complete image, equal except id ⇒ equivalent.
	if !identityContentEquivalent(localCols, local, []string{"id", "vm_name", "name", "deleted_at"},
		[]interface{}{"id-b", "vm1", "snap1", nil}) {
		t.Error("complete, equal-except-id image must be equivalent")
	}
	// Incomplete image (deleted_at omitted) ⇒ NOT proven equivalent (schema skew).
	if identityContentEquivalent(localCols, local, []string{"id", "vm_name", "name"},
		[]interface{}{"id-b", "vm1", "snap1"}) {
		t.Error("an incomplete image must NOT be declared equivalent")
	}
	// NULL vs "" on deleted_at ⇒ NOT equivalent (live vs the SQL-predicate-breaking empty string).
	if identityContentEquivalent(localCols, local, localCols,
		[]interface{}{"id-b", "vm1", "snap1", ""}) {
		t.Error("NULL deleted_at must differ from empty-string deleted_at")
	}
	// A differing non-id column ⇒ not equivalent.
	if identityContentEquivalent(localCols, local, localCols,
		[]interface{}{"id-b", "vm1", "snap2", nil}) {
		t.Error("a differing non-id column must be unequal")
	}
	// An EXTRA incoming column the receiver lacks is ignored (newer sender schema).
	if !identityContentEquivalent(localCols, local, []string{"id", "vm_name", "name", "deleted_at", "extra"},
		[]interface{}{"id-b", "vm1", "snap1", nil, "x"}) {
		t.Error("an extra incoming column must not defeat equivalence")
	}
}

// reduceIdentity folds a group by feeding rows one at a time into a single local slot (the
// receive model). It returns the surviving id and whether any exact-instant/different-content
// fault occurred (which leaves the group intentionally divergent, not convergent).
func reduceIdentity(rows []idRow) (survivingID string, faulted bool) {
	local, have := idRow{}, false
	for _, in := range rows {
		if !have {
			local, have = in, true
			continue
		}
		switch decide(true, local, in) {
		case idKeepLocal:
		case idContentFault:
			faulted = true
		default: // idAdoptSameID / idCollapse / idApplyNew
			local = in
		}
	}
	return local.id, faulted
}

// TestResolveIdentity_OrderInvariantForEquivalentContent: for a content-EQUIVALENT group (the
// only case the resolver is allowed to collapse), the surviving id is the same under every arrival
// permutation — the max-instant row, ties broken by the smaller id — with no fault. This is the
// associativity/commutativity the three-node interleaving relies on.
func TestResolveIdentity_OrderInvariantForEquivalentContent(t *testing.T) {
	group := []idRow{
		{"1000000000000-0000-a", "id-b", "same"},
		{"1000000000000-0000-a", "id-a", "same"}, // same instant, smaller id
		{"2000000000000-0000-c", "id-z", "same"}, // latest instant ⇒ wins outright
		{"1000000000000-0000-a", "id-c", "same"},
	}
	wantID, wantFault := reduceIdentity(group)
	if wantFault || wantID != "id-z" {
		t.Fatalf("baseline: id=%q fault=%v, want id-z / no fault", wantID, wantFault)
	}
	seen := 0
	var perms func([]idRow, int)
	perms = func(a []idRow, k int) {
		if k == len(a) {
			seen++
			if got, fault := reduceIdentity(a); got != wantID || fault {
				t.Errorf("permutation winner %q fault=%v != %q", got, fault, wantID)
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
	if seen != 24 {
		t.Errorf("expected 24 permutations, ran %d", seen)
	}
}

// TestResolveIdentity_TieDifferentContentIsFault: a group whose latest instant is a tie between
// DIFFERENT-content rows must report a fault (stay divergent), never silently collapse.
func TestResolveIdentity_TieDifferentContentIsFault(t *testing.T) {
	const sameTS = "2000000000000-0000-x" // identical conflict key ⇒ an exact lwwOrder tie
	group := []idRow{
		{sameTS, "id-a", "content-A"},
		{sameTS, "id-b", "content-B"}, // same instant, different content
	}
	if _, fault := reduceIdentity(group); !fault {
		t.Fatal("an equal-instant, different-content tie must fault")
	}
}
