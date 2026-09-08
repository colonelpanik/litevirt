package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestRebalancer_AcquireRecordsLeaseTerm: a successful acquire records a
// non-zero fencing term, and losing the lease clears it.
//
// Phase 1 only records the term, so without this assertion the store is
// unobservable and could be dropped without any test noticing.
func TestRebalancer_AcquireRecordsLeaseTerm(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	db := newRebalancerTestDB(t)
	r := NewRebalancer("me", db)
	r.Now = func() time.Time { return now }

	if got := r.LeaseTerm(); got != 0 {
		t.Fatalf("term before any acquire = %d, want 0", got)
	}
	if !r.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	first := r.LeaseTerm()
	if first <= 0 {
		t.Fatalf("term after a successful acquire = %d, want > 0", first)
	}

	// Renewal must not mint: the executor loop and the proposing loop both renew.
	if !r.acquireLease(ctx) {
		t.Fatal("must renew its own lease")
	}
	if got := r.LeaseTerm(); got != first {
		t.Fatalf("renewal changed the term %d -> %d", first, got)
	}

	// Another host takes it validly → our term must clear.
	valid := now.Add(time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, 'other', ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at`, r.LeaseKey, valid, valid); err != nil {
		t.Fatalf("hand the lease to another host: %v", err)
	}
	if r.acquireLease(ctx) {
		t.Fatal("must not steal a still-valid lease")
	}
	if got := r.LeaseTerm(); got != 0 {
		t.Errorf("term after losing the lease = %d, want 0", got)
	}
}

// TestRebalancer_LeaseTTLIsTwicePollInterval pins the rebalancer's own TTL.
//
// All three lease consumers now share one helper but keep DIFFERENT TTLs —
// the coordinator's leaseDuration, the detector's 2*interval, this one's
// 2*PollInterval. The TTL sets how long a dead rebalancer-leader blocks
// takeover cluster-wide, so a copy-paste of a neighbour's constant is both an
// easy mistake and an invisible one without this assertion.
//
// PollInterval is set to a value that is not a plausible default so a hardcoded
// constant cannot coincidentally match it.
func TestRebalancer_LeaseTTLIsTwicePollInterval(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2031, 3, 14, 1, 59, 0, 0, time.UTC)

	db := newRebalancerTestDB(t)
	r := NewRebalancer("me", db)
	r.Now = func() time.Time { return now }
	r.PollInterval = 37 * time.Second

	if !r.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	rows, err := db.Query(ctx,
		`SELECT expires_at FROM leader_election WHERE key = ?`, r.LeaseKey)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	want := now.Add(2 * r.PollInterval).UTC().Format(time.RFC3339)
	if got := rows[0].String("expires_at"); got != want {
		t.Errorf("expires_at = %q, want %q — the TTL must be 2*PollInterval on "+
			"r.now(), not a constant and not another consumer's TTL", got, want)
	}
}

// TestRebalancer_SeparateInstancesShareOneTenure is the production shape, and it
// is not the one an earlier version of this test assumed.
//
// That version ran two goroutines against ONE *Rebalancer and justified itself
// by saying the executor shares this instance. It does not: daemon.go,
// grpcapi/rebalance_executor.go and grpcapi/rebalance.go each call
// NewRebalancer, so three DISTINCT instances contend for one lease key with the
// same holder name. That is what races the first acquisition and every takeover.
//
// The invariant is that they share one tenure: exactly one term row, and every
// instance that holds the lease reports the same term. Asserting only
// "HoldsLease() == true" — as the earlier version did — passes even when each
// instance mints its own term, which leaves whichever one kept the lower number
// below the rejection threshold and fenced by its own ledger.
func TestRebalancer_SeparateInstancesShareOneTenure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	db := newRebalancerTestDB(t)
	const instances = 4
	rs := make([]*Rebalancer, instances)
	for i := range rs {
		rs[i] = NewRebalancer("me", db) // same holder, separate instances
		rs[i].Now = func() time.Time { return now }
	}

	var wg sync.WaitGroup
	for _, r := range rs {
		wg.Add(1)
		go func(r *Rebalancer) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r.HoldsLease(ctx)
			}
		}(r)
	}
	wg.Wait()

	rows, err := db.Query(ctx,
		`SELECT COUNT(*) AS n FROM leader_lease_terms WHERE key = ? AND deleted_at IS NULL`,
		rs[0].LeaseKey)
	if err != nil || len(rows) == 0 {
		t.Fatalf("count terms: err=%v rows=%d", err, len(rows))
	}
	if n := rows[0].Int64("n"); n != 1 {
		t.Errorf("%d term rows for one unbroken tenure, want 1 — the daemon loop, the "+
			"executor and the RunRebalance RPC are separate instances with the same holder, "+
			"and each minting its own term fences the ones holding a lower number", n)
	}

	// Every instance that believes it holds the lease must report the same term.
	var seen int64
	for i, r := range rs {
		term := r.LeaseTerm()
		if term == 0 {
			continue
		}
		if seen == 0 {
			seen = term
			continue
		}
		if term != seen {
			t.Errorf("instance %d reports term %d, another reports %d — one tenure must "+
				"have one term, or the proposer and executor disagree", i, term, seen)
		}
	}
	if seen == 0 {
		t.Error("no instance recorded a term after acquiring the lease")
	}
}
