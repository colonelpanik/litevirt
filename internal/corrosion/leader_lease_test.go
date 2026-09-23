package corrosion

import (
	"context"
	"testing"
	"time"
)

var leaseTestNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// mutationRows counts replicated mutations, for tests asserting that a path
// writes nothing to a peer's replication stream.
func mutationRows(t *testing.T, c *Client) int {
	t.Helper()
	var n int
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM mutation_log`).Scan(&n); err != nil {
		t.Fatalf("count mutation_log: %v", err)
	}
	return n
}

// seedTerm writes one term row directly, for tests that need a specific ledger
// state without going through acquisition.
func seedTerm(t *testing.T, c *Client, key string, term int64, holder string) {
	t.Helper()
	ts := leaseTestNow.UTC().Format(time.RFC3339)
	if _, err := c.db.Exec(
		`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, key, term, holder, ts, ts, c.NowTS()); err != nil {
		t.Fatalf("seed term %s/%d: %v", key, term, err)
	}
}

// TestNewestLeaseTerm_ReportsWhoseTermItIs: the read that classification depends
// on must name the holder of the NEWEST term, not the newest term belonging to
// some particular holder.
//
// The distinction is the whole point. An earlier version asked for
// MAX(term) WHERE holder = ?, which excluded other nodes' terms but NOT this
// node's terms from tenures it no longer held — so a host that once held term 6
// got 6 back on a tenure it had just acquired as term 1, and a reimaged host
// reusing a hostname inherited its predecessor's highest term.
func TestNewestLeaseTerm_ReportsWhoseTermItIs(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	got, err := newestLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("empty ledger: %v", err)
	}
	if got.Term != 0 || got.Holder != "" {
		t.Fatalf("empty ledger gave %+v, want zero", got)
	}

	seedTerm(t, c, "failover", 1, "host-a")
	seedTerm(t, c, "failover", 2, "host-b")

	got, err = newestLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Term != 2 || got.Holder != "host-b" {
		t.Errorf("newest = %+v, want term 2 held by host-b — reading a per-holder "+
			"maximum here is what let a displaced node report a term it never acquired", got)
	}

	// A different key is a different lease entirely.
	other, err := newestLeaseTerm(ctx, c, "rebalancer")
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	if other.Term != 0 {
		t.Errorf("terms leaked across keys: %+v", other)
	}
}

// TestNextLeaseTerm_AllocatesAboveTombstones: allocation counts tombstoned terms;
// the live reads do not.
//
// That asymmetry was a bug when it was absent. Allocating from the
// tombstone-filtered maximum meant a tombstoned term left a GAP that allocation
// walked into: with term 1 live and term 2 tombstoned the next term computed as
// 2, collided, and was dropped — every time, forever.
func TestNextLeaseTerm_AllocatesAboveTombstones(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	next, err := nextLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if next != 1 {
		t.Fatalf("first term = %d, want 1 — term 0 is the column default and must stay "+
			"distinguishable from a real acquisition", next)
	}

	seedTerm(t, c, "failover", 1, "host-a")
	seedTerm(t, c, "failover", 2, "host-a")
	if _, err := c.db.Exec(
		`UPDATE leader_lease_terms SET deleted_at = ? WHERE key = 'failover' AND term = 2`,
		leaseTestNow.Format(time.RFC3339)); err != nil {
		t.Fatalf("tombstone term 2: %v", err)
	}

	// Live reads skip the tombstone...
	newest, err := newestLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("newest: %v", err)
	}
	if newest.Term != 1 {
		t.Errorf("newest live term = %d, want 1", newest.Term)
	}
	// ...but allocation must not, or it hands out 2 again.
	next, err = nextLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if next != 3 {
		t.Errorf("next term = %d, want 3 — a term number must never be reused, even "+
			"after its row is tombstoned", next)
	}
}

// TestCurrentLeaseTerm_IsTheRejectionThreshold pins that the exported threshold
// is the cluster maximum, independent of who holds it.
func TestCurrentLeaseTerm_IsTheRejectionThreshold(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	seedTerm(t, c, "failover", 1, "host-a")
	seedTerm(t, c, "failover", 5, "host-b")

	got, err := CurrentLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != 5 {
		t.Errorf("threshold = %d, want 5", got)
	}
}

// TestLeaseTermWAL_ReplayCannotRewriteAHoldersTerm proves the WAL apply path
// refuses to rewrite an existing term row.
//
// A term's holder must not change once written on this path: the executor's
// (term, holder) check is the mechanism for refusing a concurrent claimant, and
// if a stale peer's replayed INSERT could rewrite term 1's holder, the check
// would refuse whichever node replayed last. Plain LWW would apply the replay
// because its updated_at is later; INSERT OR IGNORE refuses it.
//
// The replay is stamped only a few seconds ahead. An earlier version used
// 2999-01-01, which production's future-skew quarantine refuses outright once
// LWWSkewGuardV1 is latched — so it proved the behaviour only for the
// configurations that have that guard OFF. The mechanism does not depend on the
// magnitude, so a realistic delta tests it under both.
func TestLeaseTermWAL_ReplayCannotRewriteAHoldersTerm(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	seedTerm(t, c, "failover", 1, "host-a")

	newer := leaseTestNow.Add(5 * time.Second).UTC().Format(time.RFC3339Nano)
	acquired := leaseTestNow.Add(5 * time.Second).UTC().Format(time.RFC3339)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.applyStatementLWW(ctx, tx,
		mintLeaseTermStmt("failover", 1, "host-b", acquired, newer), newer); err != nil {
		tx.Rollback()
		t.Fatalf("apply replayed insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rows, err := c.Query(ctx,
		`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read term 1: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("holder"); got != "host-a" {
		t.Fatalf("a replayed INSERT with a later updated_at rewrote term 1's holder to %q. A "+
			"term's holder must be immutable on this path, or the executor refuses whichever "+
			"node replayed last instead of the node that actually lost the term", got)
	}
}

// TestLeaseTermHolder_ReadsTheHolderRecordedAtThatTerm is the equal-term arm's
// only input. CurrentLeaseTerm answers "what is the newest term"; this answers
// "whose was term N", which is a different question and the one the executor
// asks when a proof's term EQUALS the threshold.
func TestLeaseTermHolder_ReadsTheHolderRecordedAtThatTerm(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedTerm(t, c, LeaseKeyFailover, 1, "node-a")
	seedTerm(t, c, LeaseKeyFailover, 2, "node-b")

	for _, tc := range []struct {
		term       int64
		wantHolder string
		wantFound  bool
	}{
		{1, "node-a", true},
		{2, "node-b", true},
		{3, "", false}, // never minted here
	} {
		holder, found, err := LeaseTermHolder(ctx, c, LeaseKeyFailover, tc.term)
		if err != nil {
			t.Fatalf("term %d: %v", tc.term, err)
		}
		if found != tc.wantFound || holder != tc.wantHolder {
			t.Errorf("term %d = (%q, %v), want (%q, %v)",
				tc.term, holder, found, tc.wantHolder, tc.wantFound)
		}
	}
}

// TestLeaseTermHolder_IsScopedToItsKey: the three consumers share one table, so
// a lookup that ignored `key` would let the rebalancer's term 4 answer for the
// failover key's term 4 — silently authorizing a proof under another
// subsystem's ledger.
//
// BOTH keys are asserted, and that is what makes the test mean anything. An
// earlier version checked only the failover key and passed with `AND key = ?`
// deleted: the unfiltered query returns both rows for term 4 and rows[0]
// happened to be the failover one, so the assertion was riding on insertion
// order. Querying both directions cannot be satisfied by whichever row sorts
// first — one of the two answers is then wrong however the rows come back.
func TestLeaseTermHolder_IsScopedToItsKey(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedTerm(t, c, LeaseKeyFailover, 4, "node-a")
	seedTerm(t, c, "rebalancer", 4, "node-z")

	for key, want := range map[string]string{LeaseKeyFailover: "node-a", "rebalancer": "node-z"} {
		holder, found, err := LeaseTermHolder(ctx, c, key, 4)
		if err != nil || !found {
			t.Fatalf("%s term 4: holder=%q found=%v err=%v", key, holder, found, err)
		}
		if holder != want {
			t.Errorf("%s term 4 holder = %q, want %q — the lookup must filter on key, or one "+
				"subsystem's ledger answers for another's", key, holder, want)
		}
	}
}

// TestLeaseTermHolder_IgnoresTombstonedRows: a tombstoned term is not a tenure
// anyone holds. Returning its holder would let a deleted incarnation keep
// authorizing proofs. (nextLeaseTerm deliberately counts tombstones, because
// ALLOCATION must not reuse a number; this read must not.)
func TestLeaseTermHolder_IgnoresTombstonedRows(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedTerm(t, c, LeaseKeyFailover, 1, "node-a")
	if err := c.Execute(ctx,
		`UPDATE leader_lease_terms SET deleted_at = ?, updated_at = ?
		  WHERE key = ? AND term = ?`,
		c.NowTS(), c.NowTS(), LeaseKeyFailover, int64(1)); err != nil {
		t.Fatalf("tombstone term 1: %v", err)
	}

	holder, found, err := LeaseTermHolder(ctx, c, LeaseKeyFailover, 1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if found || holder != "" {
		t.Errorf("tombstoned term 1 = (%q, %v), want (\"\", false)", holder, found)
	}
}

// TestValidLeaseKey_RejectsAnythingNotALease is why accepting a lease key from a
// caller can be safe: it may name which of the three real ledgers it means, and
// nothing else. An unknown key would read an empty ledger, find MAX(term) = 0,
// and make anything naming it look current.
func TestValidLeaseKey_RejectsAnythingNotALease(t *testing.T) {
	for _, k := range []string{LeaseKeyFailover, LeaseKeyRebalancer, LeaseKeyDualRun} {
		if !ValidLeaseKey(k) {
			t.Errorf("%q is a real lease key and must validate", k)
		}
	}
	// Near-misses must NOT be normalised into a match: each is a bug or an
	// attack, and accepting it would hide which.
	for _, k := range []string{"", " failover", "failover ", "FAILOVER", "Failover", "'; DROP", "unknown"} {
		if ValidLeaseKey(k) {
			t.Errorf("%q must not validate as a lease key", k)
		}
	}
}

// TestLeaseTermHolder_AQueryFailureIsNotAnUnseenTerm pins the contract the doc
// block states, by reading err FIRST — which is the whole point.
//
// The two answers are otherwise identical: a failed query and a genuinely
// unseen term both return ("", false, ...). The doc above tells an enforcement
// path that found == false is a normal answer it may proceed on, so a caller
// written as `holder, found, _ :=` or one that checks !found before err would
// treat a broken database as "nobody holds that term" and proceed. Fixed while
// the function still has no caller.
func TestLeaseTermHolder_AQueryFailureIsNotAnUnseenTerm(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Take the ledger away underneath it.
	if err := c.execLocal(ctx, `DROP TABLE leader_lease_terms`); err != nil {
		t.Fatalf("drop: %v", err)
	}

	holder, found, err := LeaseTermHolder(ctx, c, LeaseKeyFailover, 1)
	if err == nil {
		t.Fatal("a failed ledger read reported no error; an enforcement path cannot then tell " +
			"'this node has not seen that term' (proceed) from 'the database failed' (fail closed)")
	}
	if holder != "" {
		t.Errorf("holder = %q on an error, want the zero value", holder)
	}
	if found {
		t.Error("found = true alongside an error")
	}
}

// TestAcquireLeaseWithTerm_LedgerGateClosed_TakesLeaseButMintsNothing is the
// rolling-upgrade contract: while lease_term_ledger_v1 has not durably latched,
// a peer on the previous release cannot resolve the mint's statement shape, and
// an unregistered shape back-pressures its whole replication stream rather than
// degrading. So the mint waits — but the LEASE must still transfer, because
// failover, rebalancing and dual-run detection all depend on it and predate
// terms entirely.
//
// Asserting "no row was written" is the load-bearing half. A version that
// returned term 0 to the caller while still writing the row would pass any test
// that only checked the returned term, and would still stall the peer.
func TestAcquireLeaseWithTerm_LedgerGateClosed_TakesLeaseButMintsNothing(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.SetLeaseTermLedgerGate(func() bool { return false })

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "node-a", time.Minute, leaseTestNow)
	if err != nil {
		t.Fatalf("AcquireLeaseWithTerm: %v", err)
	}
	if !held {
		t.Fatal("lease not held with the ledger gate closed; the gate withholds the TERM, " +
			"not the lease — failover predates terms and must keep working mid-roll")
	}
	if term != 0 {
		t.Errorf("term = %d with the ledger gate closed, want 0 (the "+
			"minted-without-a-term sentinel the executor refuses on)", term)
	}

	rows, err := c.Query(ctx, `SELECT term FROM leader_lease_terms WHERE key = ?`, LeaseKeyFailover)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("%d term row(s) written with the ledger gate closed; the mint's statement "+
			"shape would have replicated to a peer that cannot resolve it", len(rows))
	}

	// And the lease itself is really recorded, not merely reported.
	holder, _, err := leaseRow(ctx, c, LeaseKeyFailover)
	if err != nil {
		t.Fatalf("leaseRow: %v", err)
	}
	if holder != "node-a" {
		t.Errorf("leader_election holder = %q, want node-a", holder)
	}
}

// TestAcquireLeaseWithTerm_UnwiredGateFailsClosed: the gate is nil-safe, and its
// nil answer is NO MINT. Unlike every other injected predicate on Client — which
// default to the legacy path in the permissive direction — a wiring omission
// here must cost terms, not cost the fleet its replication.
func TestAcquireLeaseWithTerm_UnwiredGateFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.SetLeaseTermLedgerGate(nil)

	if c.MayMintLeaseTerm() {
		t.Fatal("MayMintLeaseTerm() = true with no gate wired; an unwired daemon would emit " +
			"a shape a previous-release peer stalls on")
	}

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyRebalancer, "node-a", time.Minute, leaseTestNow)
	if err != nil {
		t.Fatalf("AcquireLeaseWithTerm: %v", err)
	}
	if !held || term != 0 {
		t.Errorf("held=%v term=%d, want held=true term=0", held, term)
	}
	rows, err := c.Query(ctx, `SELECT term FROM leader_lease_terms WHERE key = ?`, LeaseKeyRebalancer)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("%d term row(s) written with no gate wired", len(rows))
	}
}

// TestAcquireLeaseWithTerm_GateClosedKeepsRenewingOverAForeignTerm: a node that
// cannot mint must keep renewing a lease it holds even when the ledger's newest
// term belongs to somebody else.
//
// This is the state a gate-closed takeover LANDS IN, so it is not an edge case:
// the previous holder minted a term while the gate was open for it, its lease
// then lapsed, and this node — a fresh host, a wiped dataDir, a failed marker
// write, or simply a node whose per-node latch has not formed yet — took the
// lease over without a term.
//
// The classification arm for "a peer's term is newer than ours" fails closed,
// which is correct when we can mint: minting there would promote the loser of
// the term race above its winner and invert fencing. But a node that mints
// nothing has no escalation to prevent, and refusing there reported held=false
// while our own leader_election row still named us — so the lease was neither
// renewed nor transferable, and the guarded upsert locked every peer out until
// it expired. All three consumers stood down for most of every TTL, on the one
// path whose stated contract is that availability is unaffected.
func TestAcquireLeaseWithTerm_GateClosedKeepsRenewingOverAForeignTerm(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.SetLeaseTermLedgerGate(func() bool { return false })

	// node-b held this lease, minted term 1, and let it lapse.
	seedTerm(t, c, LeaseKeyFailover, 1, "node-b")
	seedLease(t, c, LeaseKeyFailover, "node-b", leaseTestNow.Add(-time.Minute))

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "node-a", time.Minute, leaseTestNow)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if !held || term != 0 {
		t.Fatalf("takeover gave held=%v term=%d, want held=true term=0", held, term)
	}

	// The renewals are the actual regression: the takeover always worked.
	for i, at := range []time.Time{
		leaseTestNow.Add(time.Second),
		leaseTestNow.Add(2 * time.Second),
		leaseTestNow.Add(3 * time.Second),
	} {
		held, term, err = AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "node-a", time.Minute, at)
		if err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
		if !held {
			t.Fatalf("renewal %d reported the lease lost while node-a still holds the row; "+
				"nothing can take it either (the upsert needs it expired or its own), so "+
				"failover, rebalancing and dual-run detection all stop until it lapses", i+1)
		}
		if term != 0 {
			t.Errorf("renewal %d gave term %d, want 0 — node-b's term is not ours to report", i+1, term)
		}
	}

	// node-b's ledger row is untouched: we never had permission to write here.
	newest, err := newestLeaseTerm(ctx, c, LeaseKeyFailover)
	if err != nil {
		t.Fatalf("newestLeaseTerm: %v", err)
	}
	if newest.Term != 1 || newest.Holder != "node-b" {
		t.Errorf("ledger newest = %+v, want term 1 held by node-b", newest)
	}
}

// TestAcquireLeaseWithTerm_GateClosedReportsNoTermAcrossALapse: once the gate
// closes, this node's OWN surviving ledger row stops being a description of its
// current tenure, and must not be reported as one.
//
// A term is a claim about one unbroken tenure. With the gate open that
// correspondence is maintained by the mint: a lease that fully lapsed and was
// re-taken by its own prior holder classifies as a NEW tenure and gets a fresh
// term, because the lapse is exactly the window in which other nodes were
// entitled to act. A node that cannot mint cannot re-establish it — so after a
// lapse its row says only "this node held some earlier tenure", and handing back
// that number stamps work done after the lapse with the term from before it.
func TestAcquireLeaseWithTerm_GateClosedReportsNoTermAcrossALapse(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	open := true
	c.SetLeaseTermLedgerGate(func() bool { return open })

	if _, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyRebalancer, "node-a", time.Minute, leaseTestNow); err != nil || term != 1 {
		t.Fatalf("gate-open acquire: term=%d err=%v, want term 1", term, err)
	}

	// The latch is gone — a restart before it re-forms, or a failed marker
	// write — and the lease lapses while it is down.
	open = false
	lapsed := leaseTestNow.Add(2 * time.Minute)

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyRebalancer, "node-a", time.Minute, lapsed)
	if err != nil {
		t.Fatalf("re-take after lapse: %v", err)
	}
	if !held {
		t.Fatal("could not re-take our own expired lease with the gate closed")
	}
	if term != 0 {
		t.Errorf("re-take after lapse gave term %d, want 0", term)
	}

	// The poll after the re-take is where the stale number surfaced: the row is
	// live and names us again, and the ledger still holds our pre-lapse term.
	held, term, err = AcquireLeaseWithTerm(ctx, c, LeaseKeyRebalancer, "node-a", time.Minute, lapsed.Add(time.Second))
	if err != nil {
		t.Fatalf("poll after re-take: %v", err)
	}
	if !held {
		t.Fatal("lost the lease on the poll after re-taking it")
	}
	if term != 0 {
		t.Errorf("poll after re-take gave term %d — that is the PRE-LAPSE term, reported for a "+
			"tenure this node could not record; every proof it stamps claims a fencing "+
			"position it no longer holds", term)
	}
}

// TestAcquireLeaseWithTerm_GateClosedNonHolderWritesNothing: a losing poll must
// not write.
//
// The upsert is a zero-row no-op when another node holds a live lease — its
// ON CONFLICT ... WHERE takes the row only when the lease is expired or already
// ours — but both write paths log the statements they were GIVEN rather than the
// ones that changed anything, so a no-op still appends to mutation_log and wakes
// the replicator. Before the gate existed the non-holder never reached the
// statement at all: its guard declined inside the transaction and nothing was
// written. Routing that case through the bare upsert turned every non-holder into
// a steady source of replicated no-ops — (N-1) nodes x 3 lease keys x every poll
// tick — onto the exact stream the gate exists to keep quiet, for as long as the
// gate stays closed.
func TestAcquireLeaseWithTerm_GateClosedNonHolderWritesNothing(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	c.SetLeaseTermLedgerGate(func() bool { return false })

	seedLease(t, c, LeaseKeyDualRun, "node-b", leaseTestNow.Add(time.Minute))

	before := mutationRows(t, c)
	for i := 0; i < 3; i++ {
		held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyDualRun, "node-a",
			time.Minute, leaseTestNow.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("losing poll %d: %v", i+1, err)
		}
		if held || term != 0 {
			t.Fatalf("losing poll %d gave held=%v term=%d against node-b's live lease", i+1, held, term)
		}
	}
	if after := mutationRows(t, c); after != before {
		t.Errorf("%d replicated mutation(s) written by %d losing polls, want 0; a no-op upsert "+
			"still logs and notifies, so every non-holder feeds the stream the gate is "+
			"meant to keep quiet", after-before, 3)
	}
}

// TestAcquireLeaseWithTerm_GateOpensAfterALeaselessTenure: the fleet finishes
// rolling while a node already holds a lease it took without a term. The next
// acquisition pass must mint one rather than wait for the lease to lapse —
// otherwise enforcement latches onto a ledger with no row for the current
// holder, and every reschedule that holder coordinates is refused for the length
// of its tenure.
//
// This exercises the ourTenure/newest.Term==0 fall-through, which is the branch
// the pre-existing comment calls "the rolling-upgrade case".
func TestAcquireLeaseWithTerm_GateOpensAfterALeaselessTenure(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	open := false
	c.SetLeaseTermLedgerGate(func() bool { return open })

	if _, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "node-a", time.Minute, leaseTestNow); err != nil || term != 0 {
		t.Fatalf("pre-latch acquire: term=%d err=%v, want term 0", term, err)
	}

	open = true // the roll completed and the latch formed
	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "node-a",
		time.Minute, leaseTestNow.Add(time.Second))
	if err != nil {
		t.Fatalf("post-latch acquire: %v", err)
	}
	if !held {
		t.Fatal("lost our own unexpired lease across the latch")
	}
	if term != 1 {
		t.Errorf("term = %d after the latch formed, want 1 minted on the SAME tenure; a "+
			"holder that waits for its lease to lapse has every reschedule refused until then", term)
	}
}
