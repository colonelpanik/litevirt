package corrosion

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
		{"operation_steps", TieCategoryImmutableOwnership},
		{"operations", TieCategoryImmutableOwnership},
		{"leader_lease_terms", TieCategoryImmutableLedger},
	} {
		if got := immutableTieCategory(tc.table); got != tc.wantCategory {
			t.Errorf("immutableTieCategory(%q) = %q, want %q", tc.table, got, tc.wantCategory)
		}
	}
}

// TestImmutableMergeTables_AreAllClassified replaces a test that tested nothing.
//
// The old one derived every owner-epoch-bearing table from schemaDDL and
// asserted each appeared in ownershipBearingTables. But immutableTieCategory
// consulted that map and then returned the SAME category whether the lookup hit
// or missed, so the assertion could not fail for any reason a caller cared
// about — and the map was wrong anyway about project_authority_epochs, which
// merges through authorityMergeRow: that converges deterministically and calls
// observeTieBreak, never trackUnresolved, so it contributes no ties at all.
//
// What actually needs guarding is the real input to the classification: the set
// of tables whose merge IS immutableMergeKeepLocalRow. Derived from
// customMergeTables by function identity, so adding a fourth immutable table
// fails here until someone classifies it deliberately.
func TestImmutableMergeTables_AreAllClassified(t *testing.T) {
	want := map[string]string{
		"operations":         TieCategoryImmutableOwnership,
		"operation_steps":    TieCategoryImmutableOwnership,
		"leader_lease_terms": TieCategoryImmutableLedger,
	}

	immutable := reflect.ValueOf((*Client).immutableMergeKeepLocalRow).Pointer()
	got := map[string]string{}
	for table, fn := range customMergeTables {
		if reflect.ValueOf(fn).Pointer() == immutable {
			got[table] = immutableTieCategory(table)
		}
	}
	if len(got) == 0 {
		t.Fatal("found no tables merging through immutableMergeKeepLocalRow; the function-identity " +
			"comparison is broken and this test would pass vacuously")
	}
	for table, wantCat := range want {
		gotCat, ok := got[table]
		if !ok {
			t.Errorf("%s no longer merges through immutableMergeKeepLocalRow; this test's "+
				"expectations are stale", table)
			continue
		}
		if gotCat != wantCat {
			t.Errorf("immutableTieCategory(%q) = %q, want %q", table, gotCat, wantCat)
		}
	}
	for table := range got {
		if _, expected := want[table]; !expected {
			t.Errorf("%s newly merges through immutableMergeKeepLocalRow and inherits the "+
				"fail-closed ownership category by default. Decide deliberately: does a "+
				"conflict on that table hide an ownership decision? Then add it here", table)
		}
	}
}

// TestKnownTieCategories_CoverEveryEmissionSite scans this package's own source
// for the categories the emission sites actually name, and fails if one is
// missing from KnownTieCategories.
//
// A source scan rather than a hand-written list because that list was the bug:
// the grpcapi-side classification shipped missing auth_factor, auth_pointer and
// lb_token, all three emitted here, while its comment claimed "a new category
// cannot be silently absent from both" maps. The consumer is a monotone latch
// that never re-opens, so a category nobody classified must be a build failure.
func TestKnownTieCategories_CoverEveryEmissionSite(t *testing.T) {
	known := map[string]bool{}
	for _, c := range KnownTieCategories {
		known[c] = true
	}

	// A bare string literal in a category position is exactly what this
	// enumeration exists to prevent, so the scan looks for the constant NAMES
	// and reports any emitter argument that is not one.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	emitter := regexp.MustCompile(
		`(?:ruleUnresolved|ruleColUnresolved|ruleAnyColUnresolved|decideUnresolved|trackUnresolved|trackUnresolvedPair)\(`)
	literal := regexp.MustCompile(`"([a-z][a-z_]{2,})"\s*\)`)

	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			if !emitter.MatchString(line) {
				continue
			}
			scanned++
			// The category is the last argument. A literal there must still be
			// a known category — this catches a new emitter added with a raw
			// string instead of a constant.
			if m := literal.FindStringSubmatch(line); m != nil && !known[m[1]] {
				t.Errorf("%s names tie category %q, which is not in KnownTieCategories:\n  %s\n"+
					"add a TieCategory constant and classify it in grpcapi, or the owner-epoch "+
					"latch decides it by a fail-closed default nobody chose", f, m[1], strings.TrimSpace(line))
			}
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned only %d emitter call site(s); the scan is broken and this test would "+
			"pass vacuously", scanned)
	}
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
	// arrived afterwards — as a fingerprint, so this compares against the
	// fingerprint of pair-a rather than the string.
	rows, err := c.Query(ctx, `SELECT content_pair FROM acknowledged_ties`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("acknowledged_ties rows = %d (err=%v), want 1", len(rows), err)
	}
	if got, want := rows[0].String("content_pair"), pairFingerprint("pair-a"); got != want {
		t.Errorf("content_pair = %q, want the fingerprint of pair-a (%q)", got, want)
	}
}

// TestAcknowledgedTies_StoresNoRowContent is a confidentiality property, and it
// only became one when acknowledgements became durable.
//
// The pair is built by encodeRowCells / encodeRowCellsV2, which are
// length-prefixed concatenations of RAW CELL VALUES — not hashes, whatever the
// surrounding comments used to say. Secret-bearing rows reach this tracker:
// user_2fa and recovery_codes end their resolver chains in
// ruleUnresolved("auth_factor"), lb_token in decideUnresolved("lb_token"). And
// AcknowledgeUnresolvedTie is exported and takes an arbitrary (table, pk). So
// acknowledging one of those ties wrote the secret, in cleartext, into a local
// table with no redaction, no GC path, a wholesale re-read at every startup,
// and a place in every copy of the database file and every support bundle.
func TestAcknowledgedTies_StoresNoRowContent(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	const secret = "JBSWY3DPEHPK3PXP" // shaped like a TOTP seed
	c.trackUnresolvedPair("user_2fa", "tim", contentPair(
		[]interface{}{"tim", secret, int64(1)},
		[]interface{}{"tim", "ORSXG5BNMRQXIYI", int64(1)},
	), pathAE, "auth_factor")
	if _, err := c.AcknowledgeUnresolvedTie(ctx, "user_2fa", "tim", "tim"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT content_pair FROM acknowledged_ties`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("acknowledged_ties rows = %d (err=%v), want 1", len(rows), err)
	}
	stored := rows[0].String("content_pair")
	if strings.Contains(stored, secret) {
		t.Errorf("the acknowledgement persisted a row's cleartext content: %q contains the "+
			"secret. Rows reaching this tracker can hold TOTP seeds, recovery material and "+
			"bearer tokens", stored)
	}
	if len(stored) != 64 {
		t.Errorf("content_pair = %q (%d chars), want a 64-char SHA-256 fingerprint",
			stored, len(stored))
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

// TestAcknowledgeLeaseTermTie_WorksAtALargeTermNumber: the acknowledgement key
// must be spelled the same way the merge spelled it, whatever Go type the term
// arrived as.
//
// The merge sees a term decoded from a JSON state dump, so json.Unmarshal
// (no UseNumber) hands it over as a float64; the RPC passes an int64. Both go
// through coerceString, which was fmt.Sprintf("%v") — and %v on a float64
// switches to exponent form at 1e6, so the merge registered
// ["failover","1e+06"] while the operator's command looked up
// ["failover","1000000"]. The lookup missed, the handler answered
// Acknowledged:false with no error and no audit row — indistinguishable from
// "no such tie" — and the contested term became permanently unacknowledgeable:
// exactly the failure this feature exists to prevent. Every other test here
// uses term 1 or 99, where the two encodings coincide.
func TestAcknowledgeLeaseTermTie_WorksAtALargeTermNumber(t *testing.T) {
	ctx := context.Background()
	local, peer := testClient(t), testClient(t)

	// A term past the point where %v on a float64 goes exponential. Reachable
	// on a flapping lease: a term is minted per acquisition.
	const term = int64(1000000)
	seedTerm(t, local, LeaseKeyFailover, term, "host-a")
	seedTerm(t, peer, LeaseKeyFailover, term, "host-b")

	if err := local.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy peer→local: %v", err)
	}
	if n := local.UnresolvedTieTables()["leader_lease_terms"]; n != 1 {
		t.Fatalf("fixture produced %d contested-term ties, want 1 (tables=%v)",
			n, local.UnresolvedTieTables())
	}

	ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, term, "tim")
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if !ok {
		t.Fatal("acknowledging term 1000000 found nothing to acknowledge, though the merge just " +
			"registered a tie for it: the register key is not type-stable across read paths, so " +
			"a contested term above 1e6 can never be acknowledged")
	}
	if n := local.UnresolvedTieCount(); n != 0 {
		t.Errorf("register still holds %d tie(s)", n)
	}
}

// TestAcknowledgedTie_StaysVisibleToTheStateDigest: an acknowledgement clears
// DECISIONS, not the record that this row is divergent.
//
// Acknowledging does not converge anything — both claims stay in the ledger by
// design — so this node's state digest still mismatches every peer afterwards.
// UnresolvedTieTables is what a divergence report uses to attribute that
// mismatch to a deliberate, operator-reviewed safety fault rather than to real
// drift (grpcapi/sync.go feeds it into every digest response). Deleting the
// entry on acknowledgement made the mismatch unattributable, which is a worse
// answer than the permanently-dirty condition the acknowledgement exists to
// clear.
func TestAcknowledgedTie_StaysVisibleToTheStateDigest(t *testing.T) {
	ctx := context.Background()
	local, _ := contestedTermFixture(t)

	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	// The decision-driving views are clear...
	if n := local.UnresolvedTieCount(); n != 0 {
		t.Errorf("UnresolvedTieCount = %d after acknowledgement, want 0: this count drives "+
			"ha.lww.unresolved and the owner-epoch latch, which is what the operator cleared", n)
	}
	if n := local.UnresolvedTieCategories()[TieCategoryImmutableLedger]; n != 0 {
		t.Errorf("the ledger category still counts %d tie(s); readiness would keep withholding", n)
	}

	// ...and the attribution view is not.
	if n := local.UnresolvedTieTables()["leader_lease_terms"]; n != 1 {
		t.Errorf("UnresolvedTieTables reports %d tie(s) on leader_lease_terms, want 1. The two "+
			"rows still disagree, so this node's digest still mismatches its peers — and this "+
			"map is the only thing that says the mismatch is a reviewed safety fault rather "+
			"than drift", n)
	}
	if n := local.TrackedTieCount(); n != 1 {
		t.Errorf("TrackedTieCount = %d, want 1", n)
	}
}

// TestTrackUnresolvedPair_AnAckedPairDoesNotEraseALiveOne: re-observing an
// already-answered divergence must not remove a different, unanswered one.
//
// The register holds one entry per (table, PK), and a plain overwrite meant an
// ordinary merge could erase a live conflict. Three versions of a row are
// enough: the operator acknowledges A–B, a merge from C registers the
// unacknowledged A–C, and the next routine merge from B puts the acknowledged
// A–B back in its place. The unanswered divergence then disappears from
// UnresolvedTieCount, from UnresolvedTieCategories, and so from the owner-epoch
// latch and ha.lww.unresolved — with no repair and nobody having answered for
// it.
//
// trackUnresolvedPair's own comment asserts this cannot happen: "a stale
// acknowledgement is inert — it cannot mask the live divergence". It is inert on
// the SUPPRESSION path, which demands an exact pair match. Masking arrived
// through the overwrite instead.
func TestTrackUnresolvedPair_AnAckedPairDoesNotEraseALiveOne(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// A–B is observed and the operator answers for it.
	c.trackUnresolvedPair("vms", "vm1", "pair-ab", pathAE, TieCategoryRuntimeOwned)
	if ok, err := c.AcknowledgeUnresolvedTie(ctx, "vms", "vm1", "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}
	if n := c.UnresolvedTieCount(); n != 0 {
		t.Fatalf("live count = %d right after the acknowledgement, want 0", n)
	}

	// A third node's version arrives: a DIFFERENT divergence, unanswered.
	c.trackUnresolvedPair("vms", "vm1", "pair-ac", pathAE, TieCategoryRuntimeOwned)
	if n := c.UnresolvedTieCount(); n != 1 {
		t.Fatalf("live count = %d after a new unacknowledged pair, want 1; the rest of this "+
			"test is vacuous", n)
	}

	// An ordinary re-merge from B re-observes the pair that WAS acknowledged.
	c.trackUnresolvedPair("vms", "vm1", "pair-ab", pathAE, TieCategoryRuntimeOwned)

	if n := c.UnresolvedTieCount(); n != 1 {
		t.Errorf("live count = %d after re-observing the acknowledged pair, want 1. The "+
			"unanswered A–C conflict was overwritten by an answered one, so the "+
			"owner-epoch latch and ha.lww.unresolved both go clean on a row that is "+
			"still divergent and still unreviewed", n)
	}
	if n := c.UnresolvedTieCategories()[TieCategoryRuntimeOwned]; n != 1 {
		t.Errorf("category count = %d, want 1 — this map is what readiness and the "+
			"owner-epoch latch consult", n)
	}
}

// TestTrackUnresolvedPair_TheGaugeFollowsAReturnToUnresolved: the exported
// gauge must move when an entry's live state changes, not only when a key first
// appears.
//
// The re-export was gated on !existed, which left the gauge stale in exactly
// the direction that matters. An acknowledgement drops it to zero; a fresh
// unacknowledged pair on that same row makes the register live again, but the
// gauge kept reading zero until some unrelated operation happened to refresh
// it. Metric-based alerting therefore missed the new contest entirely, which is
// the whole purpose of the gauge.
func TestTrackUnresolvedPair_TheGaugeFollowsAReturnToUnresolved(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	m := &fakeSyncMetrics{}
	c.SetSyncMetrics(m)

	c.trackUnresolvedPair("vms", "vm1", "pair-ab", pathAE, TieCategoryRuntimeOwned)
	if ok, err := c.AcknowledgeUnresolvedTie(ctx, "vms", "vm1", "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	m.mu.Lock()
	afterAck := m.unresolvedCurrent
	m.mu.Unlock()
	if afterAck != 0 {
		t.Fatalf("gauge = %d after acknowledgement, want 0; the rest of this test is vacuous", afterAck)
	}

	// The operator's answer is then superseded by a genuinely new divergence.
	c.trackUnresolvedPair("vms", "vm1", "pair-ac", pathAE, TieCategoryRuntimeOwned)

	m.mu.Lock()
	afterNew := m.unresolvedCurrent
	m.mu.Unlock()
	if afterNew != 1 {
		t.Errorf("gauge = %d after a new unacknowledged pair on an acknowledged row, want 1. "+
			"The register knows it is live again (UnresolvedTieCount = %d) but the "+
			"exported value stayed put, so nothing alerts on the new contest",
			afterNew, c.UnresolvedTieCount())
	}
}

// TestAcknowledgedTie_StopsBeingAttributedOnceTheRowConverges is the other half:
// a stale acknowledgement must not keep attributing a tie to a table that is
// now clean, or the digest annotation starts masking real drift.
func TestAcknowledgedTie_StopsBeingAttributedOnceTheRowConverges(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.trackUnresolvedPair("vms", "vm1", "pair-a", pathAE, TieCategoryRuntimeOwned)
	if ok, err := c.AcknowledgeUnresolvedTie(ctx, "vms", "vm1", "tim"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}
	if n := c.UnresolvedTieTables()["vms"]; n != 1 {
		t.Fatalf("attribution lost the acknowledged tie (%d); the rest of this test is vacuous", n)
	}

	// A remediating write lands and the row converges.
	c.clearUnresolved("vms", "vm1")

	if n := c.UnresolvedTieTables()["vms"]; n != 0 {
		t.Errorf("UnresolvedTieTables still attributes %d tie(s) to vms after the row converged; "+
			"a stale attribution masks real drift", n)
	}
	if n := c.TrackedTieCount(); n != 0 {
		t.Errorf("TrackedTieCount = %d after the repair, want 0", n)
	}
}
