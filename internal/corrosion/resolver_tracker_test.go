package corrosion

import (
	"bytes"
	"context"
	"fmt"
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
	ctx := context.Background()
	local, peer := contestedTermFixture(t)

	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "op"); err != nil || !ok {
		t.Fatalf("acknowledging a tracked contested term failed (ok=%v err=%v); the PK spelling "+
			"must match what the merge produced", ok, err)
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
	if _, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "op"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}

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
	if ok, err := c.AcknowledgeLeaseTermTie(context.Background(), LeaseKeyFailover, 99, "op"); err != nil || ok {
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
	if ok, err := c.AcknowledgeUnresolvedTie(context.Background(), "vms", "vm1", "op"); err != nil || !ok {
		t.Fatalf("acknowledging a tracked tie: ok=%v err=%v", ok, err)
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

// TestAcknowledgeLeaseTermTie_SurvivesADaemonRestart is the property the
// durable table exists for, and the one the in-memory-only version failed.
//
// A restart empties the register, so the tie looks gone — and then the next
// anti-entropy sweep re-registers it, because the two rows still disagree by
// design. Without durability an operator re-acknowledges the same historical
// partition after every restart, forever.
//
// The "restart" is a second Client over the SAME database, which is what
// actually exercises the mechanism: a fresh process reads acknowledged_ties in
// InitSchema and primes its register from it. (A literal process restart is a
// fleet-test concern; this pins the load path, which is where the logic is.)
func TestAcknowledgeLeaseTermTie_SurvivesADaemonRestart(t *testing.T) {
	ctx := context.Background()
	dsn := fmt.Sprintf("ackrestart%d", testDBCounter.Add(1))

	before, err := NewSharedTestClient(dsn, "host-a")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer before.Close()
	if err := InitSchema(ctx, before); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// A real contested term, tracked through the merge.
	peer := testClient(t)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if held, term, err := AcquireLeaseWithTerm(ctx, before, LeaseKeyFailover, "host-a", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	if held, term, err := AcquireLeaseWithTerm(ctx, peer, LeaseKeyFailover, "host-b", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("peer acquire: held=%v term=%d err=%v", held, term, err)
	}
	if err := before.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy: %v", err)
	}
	if n := before.UnresolvedTieCount(); n != 1 {
		t.Fatalf("fixture produced %d ties, want 1", n)
	}

	if ok, err := before.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	// The restarted daemon: a new Client over the same DB, running InitSchema
	// exactly as startup does.
	after, err := NewSharedTestClient(dsn, "host-a")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer after.Close()
	if err := InitSchema(ctx, after); err != nil {
		t.Fatalf("InitSchema after restart: %v", err)
	}
	if n := after.UnresolvedTieCount(); n != 0 {
		t.Fatalf("the restarted node starts with %d tracked tie(s); it should start clean", n)
	}

	// The sweep that used to undo everything.
	if err := after.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("post-restart anti-entropy: %v", err)
	}
	if n := after.UnresolvedTieCount(); n != 0 {
		t.Errorf("the acknowledged tie re-registered after a restart (count=%d). The rows still "+
			"disagree by design, so without a durable acknowledgement the operator has to "+
			"re-acknowledge the same historical partition after every restart", n)
	}

	// And the record says who.
	rows, err := after.Query(ctx, `SELECT acknowledged_by FROM acknowledged_ties`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("acknowledged_ties rows = %d (err=%v), want 1", len(rows), err)
	}
	if got := rows[0].String("acknowledged_by"); got != "tim" {
		t.Errorf("acknowledged_by = %q, want %q", got, "tim")
	}
}

// TestAcknowledgedTies_IsNotReplicated: the table is local-only, so an
// acknowledgement on one node must never silence the same conflict on a node
// whose operator never looked at it.
func TestAcknowledgedTies_IsNotReplicated(t *testing.T) {
	ctx := context.Background()
	local, _ := contestedTermFixture(t)
	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	// Nothing about the acknowledgement may appear in the replication log...
	rows, err := local.Query(ctx,
		`SELECT COUNT(*) AS n FROM mutation_log WHERE stmts LIKE '%acknowledged_ties%'`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("%d acknowledgement write(s) reached mutation_log; the table is local-only and "+
			"replicating it would suppress a conflict on a node nobody inspected", n)
	}
	// ...nor in the state dump peers merge from.
	if bytes.Contains(local.DumpStateBytes(), []byte("acknowledged_ties")) {
		t.Error("acknowledged_ties appears in the anti-entropy state dump; it must be absent " +
			"from the sync table list")
	}
}

// TestAcknowledgeUnresolvedTie_DoesNotClearAPairThatChangedMidWrite closes the
// window between the durable write and the register update.
//
// tieMu is deliberately released for the write — holding it across disk I/O
// would block every merge — so a merge can replace the register entry with a
// DIFFERENT divergence in that window. Deleting whatever is present on return
// clears a conflict the operator never saw and reports it acknowledged: the
// register reads clean until the next sweep puts it back, and the audit row
// names a pair nobody inspected.
//
// Driven through ackPersistedHook rather than goroutines because the bug is a
// specific interleaving of two locks; a scheduling race would reproduce it
// once in a thousand runs and pass the rest.
func TestAcknowledgeUnresolvedTie_DoesNotClearAPairThatChangedMidWrite(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")

	ackPersistedHook = func() {
		// The merge that lands mid-write. Not the acknowledged pair.
		c.trackUnresolvedPair("vms", "vm1", "pair-B-different", pathAE, "runtime_owned")
	}
	defer func() { ackPersistedHook = nil }()

	ok, err := c.AcknowledgeUnresolvedTie(ctx, "vms", "vm1", "tim")
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if !ok {
		t.Error("reported nothing acknowledged; the operator's acknowledgement of pair-a was " +
			"recorded and stands")
	}
	if n := c.UnresolvedTieCount(); n != 1 {
		t.Errorf("register holds %d tie(s), want 1: an acknowledgement of pair-a cleared the "+
			"newer pair-B divergence, so an operator sees a clean register for a conflict "+
			"nobody has looked at", n)
	}

	// And the durable row names what the operator actually saw, not what
	// arrived afterwards.
	rows, err := c.Query(ctx, `SELECT content_pair FROM acknowledged_ties`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("acknowledged_ties rows = %d (err=%v), want 1", len(rows), err)
	}
	if got := rows[0].String("content_pair"); got != "pair-a" {
		t.Errorf("content_pair = %q, want %q", got, "pair-a")
	}
}

// TestAcknowledgedTie_ANewDivergenceDoesNotDeadlockTheMerge pins a
// self-deadlock, not a logic error, which is why it drives the REAL merge path
// instead of calling trackUnresolvedPair directly the way its neighbours do.
//
// trackUnresolvedPair runs inside mergeChunk, which holds c.mu for the whole
// chunk. Every local write path takes c.mu — execLocal does — and sync.RWMutex
// is not reentrant. So issuing any database write from the tracker deadlocks
// the merge permanently, and does it while still holding tieMu, taking out
// every tie read with it: UnresolvedTieCategories, the inventory collector
// behind readiness, the lot.
//
// The trigger is a third distinct version of an ALREADY-ACKNOWLEDGED row, so
// nothing in the direct-call tests could reach it: they never enter the merge,
// where the lock is held.
func TestAcknowledgedTie_ANewDivergenceDoesNotDeadlockTheMerge(t *testing.T) {
	ctx := context.Background()
	local, _ := contestedTermFixture(t)
	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	// A THIRD claimant for the same term. Its row differs from both
	// acknowledged versions, so the pair the merge observes no longer equals
	// the acknowledged one — the case that used to attempt a delete.
	third := testClient(t)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if held, term, err := AcquireLeaseWithTerm(ctx, third, LeaseKeyFailover, "host-c", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("third acquire: held=%v term=%d err=%v", held, term, err)
	}

	// Merged off the test goroutine so a deadlock FAILS rather than hanging the
	// package: a hung merge holds c.mu and tieMu, so no assertion below could
	// run either.
	done := make(chan error, 1)
	go func() { done <- local.MergeStateBytesLWW(third.DumpStateBytes()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("anti-entropy third→local: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("anti-entropy did not return within 15s: the merge deadlocked. A database " +
			"write issued from the tie tracker re-enters c.mu, which mergeChunk already " +
			"holds, and takes tieMu down with it")
	}

	if n := local.UnresolvedTieCount(); n != 1 {
		t.Errorf("register holds %d tie(s), want 1: a divergence the operator never "+
			"acknowledged must surface", n)
	}
}

// TestAcknowledgeUnresolvedTie_ADurableWriteFailureIsNotSuccess: if the
// acknowledgement cannot be recorded, it has not happened.
//
// Clearing the register on a failed write would be the worst of both worlds —
// the operator sees the tie disappear, believes it is handled, and it returns
// on the next restart with no record of anyone having looked at it.
func TestAcknowledgeUnresolvedTie_ADurableWriteFailureIsNotSuccess(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, "runtime_owned")

	// Take the store away underneath it.
	if err := c.execLocal(ctx, `DROP TABLE acknowledged_ties`); err != nil {
		t.Fatalf("drop: %v", err)
	}

	ok, err := c.AcknowledgeUnresolvedTie(ctx, "vms", "vm1", "tim")
	if err == nil {
		t.Error("a failed durable write reported no error; the operator would believe the " +
			"acknowledgement stuck")
	}
	if ok {
		t.Error("a failed durable write reported success")
	}
	if n := c.UnresolvedTieCount(); n != 1 {
		t.Errorf("the tie was cleared from the register (%d left) despite the acknowledgement "+
			"not being recorded; it must stay visible", n)
	}
}
