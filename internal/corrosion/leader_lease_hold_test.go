package corrosion

import (
	"context"
	"sync"
	"testing"
	"time"
)

// termRowCount is the number of live term rows for a key. Several tests below
// assert on it rather than on the returned term, because the defect they guard
// is an EXTRA row for one tenure — which a caller-side term check cannot see.
func termRowCount(t *testing.T, c *Client, key string) int {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM leader_lease_terms WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil || len(rows) == 0 {
		t.Fatalf("count terms: err=%v rows=%d", err, len(rows))
	}
	return int(rows[0].Int64("n"))
}

func seedLease(t *testing.T, c *Client, key, holder string, expires time.Time) {
	t.Helper()
	exp := expires.UTC().Format(time.RFC3339)
	if _, err := c.db.Exec(
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		key, holder, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

func TestAcquireLeaseWithTerm_FirstAcquisitionMintsTermOne(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !held {
		t.Fatal("first acquisition of an unheld lease did not succeed")
	}
	if term != 1 {
		t.Errorf("term = %d, want 1", term)
	}
}

// TestAcquireLeaseWithTerm_RenewalKeepsTheSameTerm: a renewal must mint nothing.
// A renewal that bumped the term would make the holder invalidate its own
// in-flight work every renewal interval.
func TestAcquireLeaseWithTerm_RenewalKeepsTheSameTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, first, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	for i := 0; i < 3; i++ {
		at := leaseTestNow.Add(time.Duration(i+1) * time.Second)
		held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, at)
		if err != nil || !held {
			t.Fatalf("renewal %d: held=%v err=%v", i, held, err)
		}
		if term != first {
			t.Fatalf("renewal %d changed the term %d -> %d", i, first, term)
		}
	}
	if n := termRowCount(t, c, "failover"); n != 1 {
		t.Errorf("%d term rows after three renewals, want 1", n)
	}
}

// TestAcquireLeaseWithTerm_LapsedOwnLeaseIsANewTenure: holder identity alone
// does not prove an uninterrupted tenure.
//
// A lease that fully expired and was then re-taken by its own prior holder is a
// NEW tenure, because the TTL window is exactly the interval in which other
// nodes were entitled to act. Classifying it as a renewal kept the old term, so
// work the holder had in flight before a GC pause, SIGSTOP or IO stall was
// indistinguishable from work stamped after it — and term growth, the only
// alerting signal the docs offer, went blind to precisely those lapses.
func TestAcquireLeaseWithTerm_LapsedOwnLeaseIsANewTenure(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, first, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 10*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// An hour later: the lease lapsed 59m50s ago and nobody else took it.
	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 10*time.Second,
		leaseTestNow.Add(time.Hour))
	if err != nil || !held {
		t.Fatalf("re-take after lapse: held=%v err=%v", held, err)
	}
	if term == first {
		t.Errorf("re-taking a lapsed lease returned the old term %d. The lapse is the "+
			"window other nodes were entitled to act in, so this is a new tenure and "+
			"must mint", first)
	}
	if term <= first {
		t.Errorf("new tenure term %d must exceed the lapsed one %d", term, first)
	}
}

// TestAcquireLeaseWithTerm_SupersededHolderFailsClosed: a node whose term has
// been superseded by a peer's newer claim must return NO term, not mint a fresh
// higher one.
//
// leader_election is anti-entropy excluded while leader_lease_terms is
// replicated, so "our lease row still names us, but the newest term names
// someone else" is reachable in ordinary operation. Minting there would promote
// the node that LOST the term race above the winner — inverting fencing, which
// is worse than the problem the ledger exists to fix.
func TestAcquireLeaseWithTerm_SupersededHolderFailsClosed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if _, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// A peer's claim on a higher term arrives by replication. Our own
	// leader_election row is untouched — it still names host-a.
	seedTerm(t, c, "failover", 2, "host-b")

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second,
		leaseTestNow.Add(time.Second))
	if err != nil {
		t.Fatalf("renewal after being superseded: %v", err)
	}
	if held || term != 0 {
		t.Errorf("a superseded holder got held=%v term=%d, want false/0. Minting here "+
			"promotes the loser of the term race above the winner", held, term)
	}
	if n := termRowCount(t, c, "failover"); n != 2 {
		t.Errorf("%d term rows, want 2 — the superseded holder must not have minted", n)
	}
}

// TestAcquireLeaseWithTerm_HeldWithNoTermSelfHeals is the rolling-upgrade case:
// a node restarts still holding a lease minted by a binary with no term ledger.
// Nothing failed, so no write atomicity covers it; it must acquire a term.
func TestAcquireLeaseWithTerm_HeldWithNoTermSelfHeals(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	seedLease(t, c, "failover", "host-a", leaseTestNow.Add(30*time.Second))

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil || !held {
		t.Fatalf("self-heal: held=%v err=%v", held, err)
	}
	if term != 1 {
		t.Errorf("term = %d, want 1", term)
	}
}

// TestAcquireLeaseWithTerm_NeverRecordsBelowTheThreshold: an acquisition must
// not record a term below the cluster's rejection threshold.
//
// nextLeaseTerm runs outside the transaction, so a peer's replicated term N+5
// can land between the allocation read and the commit. Checking only that the
// allocated SLOT is free let the legitimate new holder record term N+1 while
// CurrentLeaseTerm had moved to N+5 — the same inversion as an orphan term,
// arriving on the success path.
func TestAcquireLeaseWithTerm_NeverRecordsBelowTheThreshold(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// A peer already holds a high term for this key; slot 1 is free.
	seedTerm(t, c, "failover", 5, "host-b")

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !held {
		t.Fatal("an unheld lease with existing peer terms must still be acquirable")
	}
	threshold, err := CurrentLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("threshold: %v", err)
	}
	if term < threshold {
		t.Errorf("acquired term %d is BELOW the rejection threshold %d — this holder "+
			"would be fenced by its own ledger", term, threshold)
	}
	if term != 6 {
		t.Errorf("term = %d, want 6 (above every retained term)", term)
	}
}

// TestAcquireLeaseWithTerm_AnotherHolderGetsNothing: losing to a live lease
// yields held=false and term 0, never a term.
func TestAcquireLeaseWithTerm_AnotherHolderGetsNothing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	seedLease(t, c, "failover", "host-b", leaseTestNow.Add(time.Hour))

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if held || term != 0 {
		t.Errorf("held=%v term=%d against a live foreign lease, want false/0", held, term)
	}
	if n := termRowCount(t, c, "failover"); n != 0 {
		t.Errorf("%d term rows after a failed acquisition, want 0", n)
	}
}

// TestAcquireLeaseWithTerm_ExpiryCompareSurvivesSameDay guards the
// RFC3339-vs-datetime('now') string-compare bug: same-day, 'T' > ' ' made a
// lease never look expired, so a dead leader's lease could not transfer until
// the UTC date rolled over.
func TestAcquireLeaseWithTerm_ExpiryCompareSurvivesSameDay(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	seedLease(t, c, "failover", "host-b", leaseTestNow.Add(-time.Minute))

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !held {
		t.Fatal("an expired same-day lease must be takeable")
	}
	if term != 1 {
		t.Errorf("term = %d, want 1", term)
	}
}

// TestAcquireLeaseWithTerm_ConcurrentSameHolderMintsOnce is finding 1's
// regression test, and it asserts the ROW COUNT rather than the returned term.
//
// Production runs three distinct *Rebalancer values against one lease key — the
// daemon's proposing loop, the executor loop, and the RunRebalance RPC — so two
// callers with the SAME holder race the first acquisition and every takeover.
// Both passed the unserialized pre-read, both allocated term 1; one committed,
// and the other's guard declined only on the slot, which the retry treated as
// contention and re-allocated as term 2. Two rows for one unbroken tenure, and
// the caller left holding term 1 was below the threshold — actively fenced by
// its own ledger.
//
// A term-only assertion cannot see this: both callers get a plausible non-zero
// term. Only the row count shows it.
func TestAcquireLeaseWithTerm_ConcurrentSameHolderMintsOnce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	const callers = 8
	var wg sync.WaitGroup
	terms := make([]int64, callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, term, err := AcquireLeaseWithTerm(ctx, c, "rebalancer", "host-a", 30*time.Second, leaseTestNow)
			terms[i], errs[i] = term, err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if n := termRowCount(t, c, "rebalancer"); n != 1 {
		t.Errorf("%d term rows for one unbroken tenure, want 1 — concurrent callers with "+
			"the same holder each minted, and whichever one kept the lower term is fenced "+
			"by its own ledger", n)
	}
	// Every caller that got a term must have got the same one.
	var seen int64
	for i, term := range terms {
		if term == 0 {
			continue
		}
		if seen == 0 {
			seen = term
			continue
		}
		if term != seen {
			t.Errorf("caller %d returned term %d but another returned %d — one tenure "+
				"must have one term", i, term, seen)
		}
	}
}

// TestAcquireLeaseWithTerm_ContentionIsNotAnError: heavy same-node contention
// must never surface as an error.
//
// Before this, exhausting the retry returned one. The failover coordinator maps
// an error onto slog.Error plus mAttempt(PhaseLease, ResultError, ErrDBError) —
// which is the paged `result="error"` alert, with a wrong cause since nothing
// was written — and holdLease renews through the same path, so a contention
// error immediately before a fence read as "lease lost" and abandoned the fence
// of a genuinely dead host.
func TestAcquireLeaseWithTerm_ContentionIsNotAnError(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d got error %v; contention must report not-held, because the "+
				"coordinator maps an error to a paged store-error metric and to aborting an "+
				"in-progress fence", i, err)
		}
	}
}

// TestAcquireLeaseWithTerm_UpdatedAtUsesNowTS: updated_at on both replicated
// writes is the LWW conflict key and must come from Client.NowTS(), which is
// monotonic, persisted across restart, and HLC-ready — not from the caller's
// bare-second clock.
//
// Bare seconds maximize ties on the one table whose ties operators are told to
// alert on, and an NTP step-back would emit a key older than this node already
// replicated.
func TestAcquireLeaseWithTerm_UpdatedAtUsesNowTS(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if _, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	bare := leaseTestNow.UTC().Format(time.RFC3339)
	for _, q := range []struct{ what, sql string }{
		{"term row", `SELECT updated_at, acquired_at FROM leader_lease_terms WHERE key = 'failover'`},
		{"lease row", `SELECT updated_at, expires_at FROM leader_election WHERE key = 'failover'`},
	} {
		rows, err := c.Query(ctx, q.sql)
		if err != nil || len(rows) == 0 {
			t.Fatalf("%s: err=%v rows=%d", q.what, err, len(rows))
		}
		if got := rows[0].String("updated_at"); got == bare {
			t.Errorf("%s updated_at = %q, the caller's bare-second clock. It is the LWW "+
				"conflict key and must come from NowTS()", q.what, got)
		}
	}
}
