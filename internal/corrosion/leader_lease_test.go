package corrosion

import (
	"context"
	"testing"
	"time"
)

var leaseTestNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func TestMintLeaseTerm_IncrementsPerKey(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	t1, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}
	if t1 != 1 {
		t.Errorf("first term = %d, want 1. A first term of 0 is indistinguishable from the "+
			"column default, so a row written by a binary that knows nothing of terms would "+
			"read as a legitimate term 0 and pass a >= threshold check", t1)
	}

	t2, err := MintLeaseTerm(ctx, c, "failover", "host-b", leaseTestNow)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if t2 != 2 {
		t.Errorf("second term = %d, want 2", t2)
	}

	// Each key has its own sequence. A shared one would make an acquisition of
	// the rebalancer lease fence the failover coordinator.
	other, err := MintLeaseTerm(ctx, c, "rebalancer", "host-a", leaseTestNow)
	if err != nil {
		t.Fatalf("mint other key: %v", err)
	}
	if other != 1 {
		t.Errorf("rebalancer's first term = %d, want 1; terms are per-key", other)
	}
}

// TestCurrentLeaseTerm_IsTheMaxAcrossHolders pins the rejection threshold: the
// highest term anyone has minted, regardless of who.
func TestCurrentLeaseTerm_IsTheMaxAcrossHolders(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, h := range []string{"host-a", "host-b"} {
		if _, err := MintLeaseTerm(ctx, c, "failover", h, leaseTestNow); err != nil {
			t.Fatal(err)
		}
	}
	got, err := CurrentLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if got != 2 {
		t.Errorf("CurrentLeaseTerm = %d, want 2", got)
	}
}

// TestCurrentLeaseTerm_AbsentKeyIsZero pins that an unheld lease reports 0 rather
// than erroring, so a first acquisition has something to compare against.
func TestCurrentLeaseTerm_AbsentKeyIsZero(t *testing.T) {
	c := testClient(t)
	got, err := CurrentLeaseTerm(context.Background(), c, "never-held")
	if err != nil {
		t.Fatalf("absent key errored: %v", err)
	}
	if got != 0 {
		t.Errorf("absent key = %d, want 0", got)
	}
}

// TestOwnLeaseTerm_IsThisHoldersHighest is the most important test in this file.
//
// A displaced holder must report ITS OWN term, never the cluster maximum.
// leader_lease_terms and leader_election replicate independently, so there is a
// window in which host-a has received winner host-b's higher term row while
// host-a's leader_election row still names host-a. Because holdLease renews by
// calling acquireLease, that window is reached on the ordinary renewal tick — and
// a renewal reading MAX(term) there would hand host-a a term it never acquired,
// letting it stamp work that passes the stale-term check.
func TestOwnLeaseTerm_IsThisHoldersHighest(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if _, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow); err != nil {
		t.Fatal(err)
	}
	// host-b wins the lease and mints a higher term; the row replicates to host-a.
	if _, err := MintLeaseTerm(ctx, c, "failover", "host-b", leaseTestNow); err != nil {
		t.Fatal(err)
	}

	own, err := OwnLeaseTerm(ctx, c, "failover", "host-a")
	if err != nil {
		t.Fatalf("own: %v", err)
	}
	if own != 1 {
		t.Fatalf("OwnLeaseTerm for the displaced holder = %d, want 1. Returning the cluster "+
			"maximum is a privilege escalation: the stale leader adopts the winner's term on "+
			"its next renewal and stamps proofs that pass the stale-term check", own)
	}

	cur, err := CurrentLeaseTerm(ctx, c, "failover")
	if err != nil {
		t.Fatal(err)
	}
	if cur <= own {
		t.Errorf("threshold (%d) must exceed the displaced holder's own term (%d), or nothing "+
			"refuses it", cur, own)
	}
}

func TestOwnLeaseTerm_NeverHeldIsZero(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if _, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow); err != nil {
		t.Fatal(err)
	}
	own, err := OwnLeaseTerm(ctx, c, "failover", "host-zz")
	if err != nil {
		t.Fatal(err)
	}
	if own != 0 {
		t.Errorf("a node that never held the lease reports term %d, want 0", own)
	}
}

// TestMintLeaseTerm_ConcurrentSameNodeIsAbsorbed pins the intra-node race the
// INSERT OR IGNORE exists for. rebalancer.go states "two loops on the leader
// renewing concurrently is safe", so two goroutines can read the same MAX and
// compute the same term; neither must error.
func TestMintLeaseTerm_ConcurrentSameNodeIsAbsorbed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow)
			errs <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent same-node mint errored: %v — same node, same holder, same "+
				"computed term is not a fault and the PK conflict must be absorbed", err)
		}
	}
}

// TestMintLeaseTerm_NeverReturnsAnotherHoldersTerm closes the gap that made
// MintLeaseTerm's read-back interchangeable in every other test here.
//
// Inside a successful mint, OwnLeaseTerm and CurrentLeaseTerm agree — we just
// minted the maximum — so swapping one for the other changes nothing and the
// escalation hole hides. They diverge only when our INSERT is silently IGNOREd,
// and a tombstone makes that reachable deterministically:
//
// CurrentLeaseTerm filters deleted_at IS NULL, so a tombstoned term leaves a
// GAP. With term 1 live and term 2 tombstoned, the threshold reads 1, the mint
// computes 2, and the INSERT collides with the tombstoned row and is dropped.
// This holder now owns nothing — and returning the cluster maximum here would
// hand it term 1, which belongs to a different node.
//
// Returning 0 is correct: the caller must treat it as "no term recorded", which
// is what the lease helper's held-without-a-term path is for.
func TestMintLeaseTerm_NeverReturnsAnotherHoldersTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// host-b holds term 1. Term 2 exists but is tombstoned, so the threshold
	// read skips it and the next mint will compute 2 and collide.
	putLeaseTerm(t, c, "failover", 1, "host-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	putLeaseTerm(t, c, "failover", 2, "host-b", "2026-01-01T00:00:01Z", "2026-01-01T00:00:01Z")
	tombstoneLeaseTerm(t, c, "failover", 2, "2026-01-02T00:00:00Z")

	term, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if term == 0 {
		return // no term claimed is a safe outcome; the caller must handle it
	}

	// Whatever term came back, its row must name THIS holder. Returning any
	// maximum — the cluster's or even this holder's own — cannot distinguish "my
	// insert landed" from "my insert was dropped and some other row carries that
	// number", and handing back a term another node holds means every proof this
	// leader stamps passes the stale-term check while fencing nobody.
	rows, err := c.Query(ctx,
		`SELECT holder, COALESCE(deleted_at, '') AS del FROM leader_lease_terms
		 WHERE key = 'failover' AND term = ?`, term)
	if err != nil {
		t.Fatalf("read back term %d: %v", term, err)
	}
	if len(rows) == 0 {
		t.Fatalf("MintLeaseTerm returned term %d but no such row exists", term)
	}
	if got := rows[0].String("holder"); got != "host-a" {
		t.Fatalf("MintLeaseTerm returned term %d, whose row names holder %q rather than the "+
			"caller. The mint was dropped and a maximum was read back in its place", term, got)
	}
	if rows[0].String("del") != "" {
		t.Fatalf("MintLeaseTerm returned term %d, whose row is tombstoned", term)
	}
}

// TestMintLeaseTerm_ReacquisitionNeverReusesAnOwnedTerm is the case my first
// attempt at the test above missed, because it used a holder with no history.
//
// A holder that already owns term 1 re-acquires. If allocation skips the
// tombstoned term 2 and the insert is dropped, reading back this holder's own
// maximum returns 1 — and a brand-new acquisition is reported as holding a
// STALE incarnation. That is the exact confusion the ledger exists to remove,
// reintroduced by the read-back.
func TestMintLeaseTerm_ReacquisitionNeverReusesAnOwnedTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	putLeaseTerm(t, c, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	putLeaseTerm(t, c, "failover", 2, "host-a", "2026-01-01T00:00:01Z", "2026-01-01T00:00:01Z")
	tombstoneLeaseTerm(t, c, "failover", 2, "2026-01-02T00:00:00Z")

	term, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if term == 1 {
		t.Fatalf("a NEW acquisition returned the holder's OWN OLD term 1 as success. No new " +
			"incarnation was recorded, so every proof this leader stamps carries a term it " +
			"held in a previous incarnation")
	}
	if term <= 2 {
		t.Fatalf("new term %d does not exceed every retained term (1 live, 2 tombstoned); "+
			"reusing a term number makes two incarnations indistinguishable", term)
	}
}

// TestMintLeaseTerm_AdvancesPastATombstonedTerm pins that allocation is not
// blocked by a tombstone.
//
// With the threshold read used for allocation, a holder with no history retried
// into the same collision indefinitely: the tombstone-filtered maximum never
// advanced, so the computed term never changed and the lease could never be
// acquired at all.
func TestMintLeaseTerm_AdvancesPastATombstonedTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	putLeaseTerm(t, c, "failover", 1, "host-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	putLeaseTerm(t, c, "failover", 2, "host-b", "2026-01-01T00:00:01Z", "2026-01-01T00:00:01Z")
	tombstoneLeaseTerm(t, c, "failover", 2, "2026-01-02T00:00:00Z")

	term, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if term == 0 {
		t.Fatal("allocation could not get past the tombstoned term, so this holder can never " +
			"acquire one. Retries recompute the same colliding term forever and the lease is " +
			"permanently unacquirable")
	}
	if term <= 2 {
		t.Errorf("term %d reuses a retained term number", term)
	}
}

// TestMintLeaseTerm_RacingHoldersNeverBothClaimATerm asserts the invariant that
// the post-insert verification exists for, across two holders racing one term.
//
// Coverage limit, stated rather than implied: this is PROBABILISTIC. The
// verification's distinct value over reading back the holder's own maximum only
// shows when a racing node takes the allocated term AND the loser already owns an
// earlier term — then the read-back returns that earlier term as though the new
// acquisition had succeeded, while the verification correctly returns 0. Forcing
// that interleaving needs a hook between the allocation read and the insert,
// which does not exist, so the mutation swapping verification for the read-back
// is NOT caught by this suite. The assertion below is still sound and never
// false-fails; it simply may not reach the collision on a given run.
func TestMintLeaseTerm_RacingHoldersNeverBothClaimATerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Give one racer a prior term, so a dropped mint has something stale to
	// wrongly return.
	putLeaseTerm(t, c, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")

	type res struct {
		holder string
		term   int64
	}
	out := make(chan res, 2)
	for _, h := range []string{"host-a", "host-b"} {
		go func(holder string) {
			term, err := MintLeaseTerm(ctx, c, "failover", holder, leaseTestNow)
			if err != nil {
				term = -1
			}
			out <- res{holder, term}
		}(h)
	}

	seen := map[int64]string{}
	for i := 0; i < 2; i++ {
		r := <-out
		if r.term <= 0 {
			continue // no term claimed, or an error — both safe outcomes
		}
		if prev, dup := seen[r.term]; dup {
			t.Errorf("term %d was returned to BOTH %s and %s; two holders believing they own "+
				"one incarnation is the split this ledger exists to make impossible",
				r.term, prev, r.holder)
		}
		seen[r.term] = r.holder

		rows, err := c.Query(ctx,
			`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = ?`, r.term)
		if err != nil || len(rows) == 0 {
			t.Fatalf("read back term %d: err=%v rows=%d", r.term, err, len(rows))
		}
		if got := rows[0].String("holder"); got != r.holder {
			t.Errorf("%s was handed term %d, whose row names %q", r.holder, r.term, got)
		}
		if r.term == 1 && r.holder == "host-a" {
			t.Errorf("host-a's NEW acquisition returned its pre-existing term 1; the mint was " +
				"dropped and a stale incarnation was reported as success")
		}
	}
}

// TestLeaseTermWAL_ReplayCannotRewriteAHoldersTerm is the immutability test
// deferred out of Task 2, and it is the one that proves appendOnlyTables takes
// effect. It could not be written earlier: it drives a replicated statement, and
// a statement shape may only be registered in the compatibility ledger once a
// real caller emits it.
//
// A term's holder must never change once written. The executor's (term, holder)
// check is the whole mechanism for refusing a concurrent claimant that lost the
// merge; if a stale peer's replayed INSERT could rewrite term 1's holder, that
// check would refuse whichever node replayed last — worse than not checking.
// LWW would apply the replay because its updated_at is later. INSERT OR IGNORE,
// which appendOnlyTables selects, is what refuses it.
func TestLeaseTermWAL_ReplayCannotRewriteAHoldersTerm(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	if _, err := MintLeaseTerm(ctx, c, "failover", "host-a", leaseTestNow); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// A stale peer replays its own losing claim on term 1, stamped far in the
	// future so LWW would prefer it.
	const newer = "2999-01-01T00:00:00Z"
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.applyStatementLWW(ctx, tx, mintLeaseTermStmt("failover", 1, "host-b", newer), newer); err != nil {
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
			"term's holder must be immutable, or the executor refuses whichever node replayed "+
			"last instead of the node that actually lost the term", got)
	}
}
