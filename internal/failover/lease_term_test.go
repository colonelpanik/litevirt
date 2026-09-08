package failover

import (
	"context"
	"testing"
	"time"
)

// TestCoordinator_AcquireRecordsLeaseTerm: a successful acquire must leave a
// non-zero fencing term on the coordinator.
//
// This exists because Phase 1 only RECORDS the term — nothing enforces on it
// yet — so without an assertion the store is unobservable and could be dropped
// silently, leaving Phase 2 to read a permanent zero. Terms start at 1
// precisely so that 0 stays distinguishable from a real acquisition.
func TestCoordinator_AcquireRecordsLeaseTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }

	if got := c.LeaseTerm(); got != 0 {
		t.Fatalf("term before any acquire = %d, want 0", got)
	}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	if got := c.LeaseTerm(); got <= 0 {
		t.Fatalf("term after a successful acquire = %d, want > 0 — the term is "+
			"recorded nowhere observable, so Phase 2 has nothing to read", got)
	}
}

// TestCoordinator_NonLeaderHasNoTerm: losing the lease must clear the term
// rather than leave a stale one behind.
//
// A term is only meaningful to its holder. A coordinator that kept its previous
// number after being displaced would carry a token it no longer owns into the
// Phase-2 enforcement path.
func TestCoordinator_NonLeaderHasNoTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	if c.LeaseTerm() == 0 {
		t.Fatal("expected a term after acquiring")
	}

	// Another host takes it with a lease valid well past our clock.
	valid := now.Add(time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'other', ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at`, valid, valid); err != nil {
		t.Fatalf("hand the lease to another host: %v", err)
	}

	if c.acquireLease(ctx) {
		t.Fatal("must not take a lease another host holds validly")
	}
	if got := c.LeaseTerm(); got != 0 {
		t.Errorf("term after losing the lease = %d, want 0 — a displaced "+
			"coordinator must not keep a token it no longer holds", got)
	}
}

// TestCoordinator_RenewalKeepsItsOwnTerm: renewing must NOT mint a new term.
//
// acquireLease is the renewal path too (holdLease calls it), so a mint on every
// call would make the holder invalidate its own in-flight work once per renewal
// interval — which would defeat the entire point of a fencing token.
func TestCoordinator_RenewalKeepsItsOwnTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	first := c.LeaseTerm()

	for i := 0; i < 3; i++ {
		if !c.acquireLease(ctx) {
			t.Fatalf("renewal %d must succeed", i)
		}
		if got := c.LeaseTerm(); got != first {
			t.Fatalf("renewal %d changed the term %d -> %d; a renewal that mints "+
				"makes the holder fence its own in-flight work", i, first, got)
		}
	}
}

// TestCoordinator_LeaseUsesInjectedClockAndDuration pins BOTH the coordinator's
// clock and its TTL, which the shared helper takes as parameters.
//
// The clock half matters because the fleet harness overrides Now with a virtual
// clock to advance past lease expiry without sleeping; passing time.Now() into
// the shared helper instead would break those scenarios in a way that a
// takeover test with a past-dated clock only catches by accident. The TTL half
// matters because leaseDuration is sized against worst-case fence latency, and
// the other two consumers deliberately use different TTLs through the same
// helper — so a copy-paste of the wrong one is exactly the plausible mistake.
func TestCoordinator_LeaseUsesInjectedClockAndDuration(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// Deliberately NOT near the real clock, in either direction.
	now := time.Date(2031, 3, 14, 1, 59, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	rows, err := db.Query(ctx,
		`SELECT expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	want := now.Add(leaseDuration).UTC().Format(time.RFC3339)
	if got := rows[0].String("expires_at"); got != want {
		t.Errorf("expires_at = %q, want %q — the lease must expire at "+
			"c.now()+leaseDuration, not on the wall clock or another consumer's TTL",
			got, want)
	}
}
