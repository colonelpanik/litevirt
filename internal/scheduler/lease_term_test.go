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

// TestRebalancer_ConcurrentHoldsLeaseIsRaceFree exercises the two-writer case
// that HoldsLease exists for.
//
// HoldsLease is exported so the rebalance executor (grpcapi/rebalance_executor.go,
// a SEPARATE loop) can gate on the same lease as the proposing loop, so two
// goroutines call acquireLease on one *Rebalancer concurrently. Recording the
// term made that struct field mutable for the first time; a plain int64 written
// from both loops is a data race, which is why leaseTerm is atomic. Run under
// -race this fails on a plain field.
func TestRebalancer_ConcurrentHoldsLeaseIsRaceFree(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	db := newRebalancerTestDB(t)
	r := NewRebalancer("me", db)
	r.Now = func() time.Time { return now }

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if !r.HoldsLease(ctx) {
					t.Error("the sole holder must always hold its own lease")
					return
				}
				_ = r.LeaseTerm()
			}
		}()
	}
	wg.Wait()

	if got := r.LeaseTerm(); got <= 0 {
		t.Errorf("term after concurrent renewal = %d, want > 0", got)
	}
}
