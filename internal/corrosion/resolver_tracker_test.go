package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
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

// contestedTermFixture builds a REAL contested-term tie the way a partition
// does: two nodes each mint term 1 for one lease key from an empty ledger, then
// the partition heals and local repairs from the peer.
//
// Built through the merge, never by hand-inserting a register entry, because the
// acknowledgement is keyed on the PK string pkKeyAt produced and on the content
// pair contentPair produced. A test that spelled either itself would prove only
// that this test and its fixture agree.
func contestedTermFixture(t *testing.T) (local, peer *Client) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	local, peer = testClient(t), testClient(t)

	if held, term, err := AcquireLeaseWithTerm(ctx, local, LeaseKeyFailover, "host-a", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	if held, term, err := AcquireLeaseWithTerm(ctx, peer, LeaseKeyFailover, "host-b", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("peer acquire: held=%v term=%d err=%v", held, term, err)
	}
	if err := local.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy peer→local: %v", err)
	}
	if n := local.UnresolvedTieTables()["leader_lease_terms"]; n != 1 {
		t.Fatalf("fixture produced %d contested-term ties, want 1 (tables=%v); every assertion "+
			"below would be vacuous", n, local.UnresolvedTieTables())
	}
	return local, peer
}

// TestAcknowledgeLeaseTermTie_SurvivesTheNextAntiEntropySweep is the property
// the whole task turns on, and the one a delete-from-the-map implementation
// fails.
//
// The two rows still disagree after acknowledgement — that is the point, the
// evidence stays — so the next sweep re-compares them, rowFactsEqual is still
// false, and a non-sticky acknowledgement is undone within seconds. Verified
// empirically before the implementation was written: clearing the register by
// hand and re-merging the same dump brought the tie straight back.
//
// It also means a daemon restart is NOT a remedy, contrary to what the review
// that prompted this task assumed: the register is in-memory, so a restart
// clears it and the next sweep re-registers. Before this there was no remedy at
// all.
func TestAcknowledgeLeaseTermTie_SurvivesTheNextAntiEntropySweep(t *testing.T) {
	local, peer := contestedTermFixture(t)

	if !local.AcknowledgeLeaseTermTie(LeaseKeyFailover, 1) {
		t.Fatal("acknowledging a tracked contested term reported no such tie; the PK spelling " +
			"must match what the merge produced")
	}
	if n := local.UnresolvedTieCount(); n != 0 {
		t.Fatalf("register still holds %d tie(s) immediately after acknowledgement", n)
	}

	// Three more sweeps of the same divergence.
	for i := 0; i < 3; i++ {
		if err := local.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
			t.Fatalf("sweep %d: %v", i+1, err)
		}
		if n := local.UnresolvedTieCount(); n != 0 {
			t.Fatalf("anti-entropy sweep %d re-registered the acknowledged tie (count=%d). "+
				"The rows still disagree by design, so an acknowledgement that only deletes the "+
				"register entry is undone on the next sweep and buys nothing", i+1, n)
		}
	}
}

// TestAcknowledgeLeaseTermTie_LeavesBothClaimsInTheLedger: acknowledging is a
// statement about EVIDENCE, never a merge decision. A "resolution" that removed
// a claim would fabricate a winner for a question the cluster never agreed on.
func TestAcknowledgeLeaseTermTie_LeavesBothClaimsInTheLedger(t *testing.T) {
	ctx := context.Background()
	local, _ := contestedTermFixture(t)

	before, err := local.Query(ctx,
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = 1`, LeaseKeyFailover)
	if err != nil || len(before) != 1 {
		t.Fatalf("read term 1 before: rows=%d err=%v", len(before), err)
	}
	local.AcknowledgeLeaseTermTie(LeaseKeyFailover, 1)

	after, err := local.Query(ctx,
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = 1`, LeaseKeyFailover)
	if err != nil || len(after) != 1 {
		t.Fatalf("read term 1 after: rows=%d err=%v", len(after), err)
	}
	if after[0].String("holder") != before[0].String("holder") {
		t.Errorf("acknowledgement changed the recorded holder %q → %q; it must clear the "+
			"REGISTER only", before[0].String("holder"), after[0].String("holder"))
	}
}

// TestAcknowledgeLeaseTermTie_UnknownTieIsNotAnError: idempotent. A second
// acknowledgement, or one racing a restart that already dropped the register,
// reports false rather than failing an operator's command.
func TestAcknowledgeLeaseTermTie_UnknownTieIsNotAnError(t *testing.T) {
	c := testClient(t)
	if c.AcknowledgeLeaseTermTie(LeaseKeyFailover, 99) {
		t.Error("reported acknowledging a tie that was never tracked")
	}
}

// TestAcknowledgeUnresolvedTie_DoesNotSuppressADifferentDivergence: the
// acknowledgement covers ONE observed divergence, keyed on its content pair. A
// different conflict on the same row must still surface, or one acknowledgement
// becomes a standing mute on that row for the life of the daemon.
func TestAcknowledgeUnresolvedTie_DoesNotSuppressADifferentDivergence(t *testing.T) {
	c := testClient(t)
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")
	if !c.AcknowledgeUnresolvedTie("vms", "vm1") {
		t.Fatal("acknowledging a tracked tie reported none")
	}
	// The same divergence stays quiet...
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")
	if n := c.UnresolvedTieCount(); n != 0 {
		t.Errorf("the acknowledged divergence re-registered (%d)", n)
	}
	// ...a different one does not.
	c.trackUnresolvedPair("vms", "vm1", "pair-B-different", pathAE, "runtime_owned")
	if n := c.UnresolvedTieCount(); n != 1 {
		t.Errorf("a DIFFERENT divergence on the same row did not register (%d); an "+
			"acknowledgement must describe one observation, not mute the row", n)
	}
}
