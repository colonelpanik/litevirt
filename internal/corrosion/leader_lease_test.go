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
	if term != 0 {
		// Whatever it returned, it must at minimum be a term host-a actually owns.
		rows, qerr := c.Query(ctx,
			`SELECT holder FROM leader_lease_terms WHERE key = 'failover' AND term = ?`, term)
		owner := "<missing>"
		if qerr == nil && len(rows) > 0 {
			owner = rows[0].String("holder")
		}
		t.Fatalf("MintLeaseTerm returned term %d, whose holder is %q, not host-a. The mint was "+
			"dropped by INSERT OR IGNORE, so this holder owns no term — returning the cluster "+
			"maximum hands it another node's incarnation and every proof it stamps passes the "+
			"stale-term check", term, owner)
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
