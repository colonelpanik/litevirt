package corrosion

import (
	"strings"
	"testing"
)

// TestUnresolvedTieCategories_KeyedByWhatTheTieIsAbout: the tracker already
// receives each tie's category and used to discard it, which forced consumers to
// re-derive "is this about ownership" from a table name in another package.
func TestUnresolvedTieCategories_KeyedByWhatTheTieIsAbout(t *testing.T) {
	c := testClient(t)
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")
	c.trackUnresolvedPair("containers", "c1", "pair-b", pathAE, "runtime_owned")
	c.trackUnresolvedPair("hosts", "h1", "pair-c", pathAE, "control_plane")

	got := c.UnresolvedTieCategories()
	if got["runtime_owned"] != 2 {
		t.Errorf("runtime_owned = %d, want 2", got["runtime_owned"])
	}
	if got["control_plane"] != 1 {
		t.Errorf("control_plane = %d, want 1", got["control_plane"])
	}
	// The fleet-wide count is unchanged — the state digest and the cross-node
	// divergence finding both still want every tie, however categorised.
	if n := c.UnresolvedTieCount(); n != 3 {
		t.Errorf("fleet-wide count = %d, want 3 — narrowing a readiness predicate must not "+
			"narrow the digest", n)
	}
}

// TestUnresolvedTieCategories_ClearRemovesFromItsCategory: a remediating write
// must decrement the category too, or a consumer withholds forever after repair.
func TestUnresolvedTieCategories_ClearRemovesFromItsCategory(t *testing.T) {
	c := testClient(t)
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")
	c.clearUnresolved("vms", "vm1")
	if n := c.UnresolvedTieCategories()["runtime_owned"]; n != 0 {
		t.Errorf("runtime_owned = %d after the repair, want 0", n)
	}
}

// TestImmutableConflict_SeparatesOwnershipFromTheLeaseLedger is the correction
// that made this task's original design work at all.
//
// immutableMergeKeepLocalRow serves operations, operation_steps AND
// leader_lease_terms, and emitted ONE category, "immutable_conflict", for all
// three. But a contested lease term must NOT withhold owner_epoch_v1 (it is not
// evidence about any workload's owner epoch) while an operation_steps conflict
// MUST (owner_epoch is part of that table's primary key, so a conflict there is
// by construction a conflict about an owner epoch). One category cannot express
// both answers, so the split happens HERE, in the package that owns the schema,
// and consumers filter on the category alone.
func TestImmutableConflict_SeparatesOwnershipFromTheLeaseLedger(t *testing.T) {
	for _, tc := range []struct{ table, wantCategory string }{
		{"operation_steps", tieCategoryImmutableOwnership},
		{"operations", tieCategoryImmutableOwnership},
		{"leader_lease_terms", tieCategoryImmutableLedger},
	} {
		if got := immutableTieCategory(tc.table); got != tc.wantCategory {
			t.Errorf("immutableTieCategory(%q) = %q, want %q", tc.table, got, tc.wantCategory)
		}
	}
}

// TestOwnershipBearingTables_CoverEveryOwnerEpochColumn makes it impossible to
// add an owner-epoch-bearing table without classifying it.
//
// This is the test the original design COULD NOT have: the classification lived
// in internal/grpcapi while schemaDDL lives here, so nothing could compare them.
// Moving the classification into this package is what makes the completeness of
// a fail-closed, monotone, irreversible predicate checkable rather than a
// promise in a comment.
func TestOwnershipBearingTables_CoverEveryOwnerEpochColumn(t *testing.T) {
	found := tablesWithOwnerEpochColumn()
	if len(found) < 4 {
		t.Fatalf("scanned schemaDDL and found only %v owner-epoch tables; the scan itself is "+
			"broken, so this test would pass vacuously", found)
	}
	for _, table := range found {
		if !ownershipBearingTables[table] {
			t.Errorf("%s carries an owner-epoch column but is not in ownershipBearingTables, so "+
				"an unresolved tie there would let owner_epoch_v1 latch over a live ownership "+
				"dispute — and the latch is monotone and never re-opens", table)
		}
	}
}

// tablesWithOwnerEpochColumn derives, from schemaDDL, every table declaring a
// column that IS an owner epoch. Derived rather than hand-written so
// ownershipBearingTables cannot silently fall behind the schema — the failure
// mode the previous grpcapi-side table map could not be protected from.
func tablesWithOwnerEpochColumn() []string {
	var out []string
	for _, stmt := range schemaDDL {
		m := createTableRe.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		for _, col := range []string{"owner_epoch", "vm_owner_epoch", "authority_epoch"} {
			// Match a column DECLARATION: the name at the start of a line in the
			// column list, not a mention inside a comment or another identifier.
			for _, line := range strings.Split(stmt, "\n") {
				f := strings.Fields(strings.TrimSpace(line))
				if len(f) >= 2 && f[0] == col {
					out = append(out, m[1])
					break
				}
			}
			if len(out) > 0 && out[len(out)-1] == m[1] {
				break
			}
		}
	}
	return out
}
