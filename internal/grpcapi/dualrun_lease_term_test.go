package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/events"
)

// TestAcquireDualRunLease_RecordsTerm: the detector records the term of the
// lease incarnation it holds, and a node that loses the election records none.
//
// The detector is alert-only and destroys nothing, so this term is
// observability rather than enforcement — which is exactly why it needs an
// assertion. An unread field that nothing checks is the shape that lets a
// silent drop pass review.
func TestAcquireDualRunLease_RecordsTerm(t *testing.T) {
	s1 := dualRunTestServer(t, 2)
	s2 := &Server{hostName: "h2", db: s1.db, events: events.NewBus()}
	ctx := context.Background()

	if got := s1.dualRunLeaseTerm.Load(); got != 0 {
		t.Fatalf("term before any acquire = %d, want 0", got)
	}
	if !s1.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h1 should acquire the lease")
	}
	first := s1.dualRunLeaseTerm.Load()
	if first <= 0 {
		t.Fatalf("term after a successful acquire = %d, want > 0", first)
	}

	// The loser records nothing — a term handed to a non-holder invites use.
	if s2.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h2 must not acquire while h1 holds a valid lease")
	}
	if got := s2.dualRunLeaseTerm.Load(); got != 0 {
		t.Errorf("the losing node's term = %d, want 0", got)
	}

	// Renewal keeps the same incarnation.
	if !s1.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h1 should renew its own lease")
	}
	if got := s1.dualRunLeaseTerm.Load(); got != first {
		t.Errorf("renewal changed the term %d -> %d; the detector's lease is "+
			"renewed every interval, so minting per renewal would churn it", first, got)
	}

	// A node that HELD the lease and then lost it must clear its term. Asserting
	// this on s2 above would prove nothing: s2 never acquired, so its term was
	// already 0 and dropping the clear-on-loss would go unnoticed. Only a
	// previous holder can show the difference.
	stolen := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := s1.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, 'h2', ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at`, dualRunLeaseKey, stolen, stolen); err != nil {
		t.Fatalf("hand the lease to h2: %v", err)
	}
	if s1.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h1 must not reacquire while h2 holds a valid lease")
	}
	if got := s1.dualRunLeaseTerm.Load(); got != 0 {
		t.Errorf("a displaced holder's term = %d, want 0 — it must not keep "+
			"reporting a token it no longer holds", got)
	}
}

// TestAcquireDualRunLease_TTLIsTwiceInterval pins the detector's own TTL.
//
// The three lease consumers share one helper and keep different TTLs on
// purpose; this one is 2x the detector's poll interval. Without an assertion a
// copy-paste of the coordinator's leaseDuration would look identical in review.
func TestAcquireDualRunLease_TTLIsTwiceInterval(t *testing.T) {
	s := dualRunTestServer(t, 2)
	ctx := context.Background()
	const interval = 37 * time.Second

	before := time.Now()
	if !s.acquireDualRunLease(ctx, interval) {
		t.Fatal("should acquire the lease")
	}
	after := time.Now()

	rows, err := s.db.Query(ctx,
		`SELECT expires_at FROM leader_election WHERE key = ?`, dualRunLeaseKey)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	got, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	// The detector uses time.Now() rather than an injectable clock, so bound the
	// expiry by the window the call actually spanned instead of pinning an exact
	// instant. 2*interval is 74s: a wrong TTL (the coordinator's 30s, or a bare
	// interval) falls outside this window comfortably.
	lo := before.Add(2 * interval).Add(-2 * time.Second)
	hi := after.Add(2 * interval).Add(2 * time.Second)
	if got.Before(lo) || got.After(hi) {
		t.Errorf("expires_at = %s, want within [%s, %s] — the TTL must be "+
			"2*interval, not a constant and not another consumer's TTL",
			got.UTC().Format(time.RFC3339), lo.UTC().Format(time.RFC3339), hi.UTC().Format(time.RFC3339))
	}
}
