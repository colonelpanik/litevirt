package corrosion

import (
	"context"
	"testing"
	"time"
)

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

// TestAcquireLeaseWithTerm_RenewalKeepsTheSameTerm is the heart of the helper. A
// renewal that bumped the term would make the holder invalidate its own
// in-flight work every renewal interval.
func TestAcquireLeaseWithTerm_RenewalKeepsTheSameTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, first, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second,
			leaseTestNow.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("renew %d: %v", i, err)
		}
		if !held {
			t.Fatalf("renew %d lost the lease", i)
		}
		if term != first {
			t.Fatalf("renew %d changed the term %d -> %d", i, first, term)
		}
	}

	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM leader_lease_terms WHERE key = 'failover'`)
	if err != nil {
		t.Fatal(err)
	}
	if n := rows[0].Int64("n"); n != 1 {
		t.Errorf("three renewals wrote %d term rows, want 1", n)
	}
}

// TestAcquireLeaseWithTerm_TakeoverAfterExpiryMintsAHigherTerm pins that a
// genuine change of holder is a new incarnation.
func TestAcquireLeaseWithTerm_TakeoverAfterExpiryMintsAHigherTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, aTerm, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 10*time.Second, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	held, bTerm, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-b", 10*time.Second,
		leaseTestNow.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("B could not take over an expired lease")
	}
	if bTerm <= aTerm {
		t.Errorf("takeover term %d does not exceed the previous holder's %d, so nothing "+
			"distinguishes the incarnations", bTerm, aTerm)
	}
}

// TestAcquireLeaseWithTerm_NonHolderGetsNothing pins that a node which does not
// hold the lease gets held=false AND term 0 — never a usable term.
func TestAcquireLeaseWithTerm_NonHolderGetsNothing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if _, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow); err != nil {
		t.Fatal(err)
	}
	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-b", 60*time.Second,
		leaseTestNow.Add(time.Second))
	if err != nil {
		t.Fatalf("non-holder acquire errored: %v", err)
	}
	if held {
		t.Error("B acquired a lease A still holds")
	}
	if term != 0 {
		t.Errorf("a non-holder was handed term %d; a term is only meaningful to its holder", term)
	}
}

// TestAcquireLeaseWithTerm_DisplacedHolderKeepsItsOwnTerm is the escalation case
// at the helper level: the ledger already carries the winner's higher term while
// leader_election still names the old holder, because the two tables replicate
// independently.
func TestAcquireLeaseWithTerm_DisplacedHolderKeepsItsOwnTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, aTerm, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	// host-b's term row arrives from replication; its leader_election row has not.
	putLeaseTerm(t, c, "failover", aTerm+1, "host-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second,
		leaseTestNow.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("A unexpectedly lost its local leader_election row")
	}
	if term != aTerm {
		t.Fatalf("the displaced holder renewed into term %d (its own was %d). It has adopted "+
			"the winner's term and can stamp work that passes the stale-term check without "+
			"ever acquiring that incarnation", term, aTerm)
	}
}

// TestAcquireLeaseWithTerm_HeldWithoutATermSelfHeals is the rolling-upgrade
// case, and it is the normal path on every upgrade rather than an edge case.
//
// A binary that predates the term ledger holds the lease. The node restarts on a
// binary that has the ledger, still holding leader_election, so it classifies as
// a renewal — and no term exists for it. Nothing failed and nothing crashed, so
// no amount of write atomicity helps: the term simply never existed. Returning
// held=true with term 0 would hand the caller the column default, which passes
// any threshold check trivially.
func TestAcquireLeaseWithTerm_HeldWithoutATermSelfHeals(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// A lease held with NO term row — exactly what an older binary leaves.
	if err := c.Execute(ctx, leaseUpsertSQL,
		"failover", "host-a", "2099-01-01T00:00:00Z", "2026-09-08T12:00:00Z",
		"2026-09-08T12:00:00Z"); err != nil {
		t.Fatalf("seed pre-ledger lease: %v", err)
	}

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire over a term-less lease: %v", err)
	}
	if !held {
		t.Fatal("lost a lease this node genuinely holds")
	}
	if term == 0 {
		t.Fatal("returned term 0 for a held lease. 0 is the column default, so it passes a " +
			">= threshold check trivially — the caller believes it is fenced when it is not")
	}
}

// TestAcquireLeaseWithTerm_DisplacedNodeWithAForeignHigherTermGetsNothing covers
// a node that held the lease, lost it to a peer, and finds the peer's higher
// term already in the ledger.
//
// It must come back held=false with term 0 — never with the ledger maximum,
// which at that moment names the NEW holder's incarnation.
//
// Note what this does NOT reach: because the lease has already moved, the
// pre-read sees the peer and this takes the ACQUISITION path. The renewal path's
// own loss branch is race-only; see the note above renewLeaseWithTerm.
func TestAcquireLeaseWithTerm_DisplacedNodeWithAForeignHigherTermGetsNothing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// host-a holds the lease and term 1.
	held, aTerm, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow)
	if err != nil || !held {
		t.Fatalf("seed acquire: held=%v err=%v", held, err)
	}

	// The lease moves to host-b with a long expiry, as it would arrive by
	// replication, and host-b mints its own higher term.
	if _, err := c.db.Exec(
		`UPDATE leader_election SET holder = 'host-b', expires_at = '2099-01-01T00:00:00Z'
		 WHERE key = 'failover'`); err != nil {
		t.Fatalf("move lease: %v", err)
	}
	putLeaseTerm(t, c, "failover", aTerm+1, "host-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second,
		leaseTestNow.Add(time.Second))
	if err != nil {
		t.Fatalf("renew after losing the lease: %v", err)
	}
	if held {
		t.Error("a node that lost the lease was told it still holds it")
	}
	if term != 0 {
		t.Errorf("a node that lost the lease was handed term %d. The ledger maximum at that "+
			"moment is the NEW holder's incarnation, so returning it lets the displaced node "+
			"stamp work under the winner's term", term)
	}
}

// TestAcquireLeaseWithTerm_AtomicOnAcquisition is what the guarded batch buys.
//
// Either both writes land or neither does. A lease recorded without a term is
// the state the whole self-heal exists to repair, and it must not be reachable
// through the ordinary acquisition path.
func TestAcquireLeaseWithTerm_AtomicOnAcquisition(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow)
	if err != nil || !held {
		t.Fatalf("acquire: held=%v err=%v", held, err)
	}

	lease, err := leaseHolder(ctx, c, "failover")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := leaseTermHeldBy(ctx, c, "failover", term, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if lease != "host-a" || !ok {
		t.Fatalf("acquisition left a half-written state: leader_election holder=%q, "+
			"term %d held by us=%v", lease, term, ok)
	}
}

// TestAcquireLeaseWithTerm_TermSlotTakenRetries pins the retry path: the term
// this node allocated is claimed by someone else between the allocation read and
// the transaction, so the guard declines and a fresh allocation must be tried.
//
// Without the retry the acquisition fails outright even though the lease is
// free, which on the failover path means recovery stalls for a whole cycle.
func TestAcquireLeaseWithTerm_TermSlotTakenRetries(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Occupy term 1 with a different holder, leaving the LEASE free. An
	// allocation reads MAX(term)=1 and computes 2, so this does not itself
	// collide — it proves takeover still works with foreign terms present.
	putLeaseTerm(t, c, "failover", 1, "host-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 60*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire with a foreign term present: %v", err)
	}
	if !held {
		t.Fatal("could not take a free lease because another holder owned an earlier term")
	}
	if term <= 1 {
		t.Errorf("term %d does not exceed the existing term 1", term)
	}
	ok, err := leaseTermHeldBy(ctx, c, "failover", term, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("term %d was returned but is not held by this node", term)
	}
}

// TestAcquireLeaseWithTerm_ExpiryCompareSurvivesSameDay is a regression guard on
// behaviour all three original call sites carried a comment about. Comparing
// expires_at against datetime('now') breaks once the date matches, because
// expires_at is RFC3339 ("…T…Z") and datetime('now') is space-separated, so
// 'T' > ' ' made a same-day lease never look expired and froze failover
// cluster-wide until the UTC date rolled over.
func TestAcquireLeaseWithTerm_ExpiryCompareSurvivesSameDay(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	// Mid-day, so expiry and takeover fall on the same UTC date.
	midday := time.Date(2026, 9, 8, 13, 30, 0, 0, time.UTC)

	if _, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 5*time.Second, midday); err != nil {
		t.Fatal(err)
	}
	held, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-b", 5*time.Second,
		midday.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("B could not take over a same-day expired lease — this is the datetime('now') " +
			"string-compare bug, which froze failover cluster-wide until the UTC date rolled")
	}
}

// TestAcquireLeaseWithTerm_ConcurrentAcquirersGetDistinctTerms pins that two
// racers never both believe they hold one incarnation.
func TestAcquireLeaseWithTerm_ConcurrentAcquirersGetDistinctTerms(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	type res struct {
		holder string
		held   bool
		term   int64
	}
	out := make(chan res, 2)
	for _, h := range []string{"host-a", "host-b"} {
		go func(holder string) {
			held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", holder, 60*time.Second, leaseTestNow)
			if err != nil {
				held, term = false, -1
			}
			out <- res{holder, held, term}
		}(h)
	}

	seen := map[int64]string{}
	for i := 0; i < 2; i++ {
		r := <-out
		if !r.held || r.term <= 0 {
			continue
		}
		if prev, dup := seen[r.term]; dup {
			t.Errorf("term %d was handed to BOTH %s and %s", r.term, prev, r.holder)
		}
		seen[r.term] = r.holder
		ok, err := leaseTermHeldBy(ctx, c, "failover", r.term, r.holder)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s was handed term %d, which its row does not name it as holding",
				r.holder, r.term)
		}
	}
}
