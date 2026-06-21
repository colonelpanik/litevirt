package scheduler

import (
	"context"
	"testing"
	"time"
)

// TestRebalancer_LeaseTakeoverWhenExpired guards the RFC3339-vs-datetime('now')
// string-compare bug in the rebalancer's leader lease: expires_at is stored
// RFC3339, and the acquire compared it against datetime('now') as a string —
// same-day, 'T' > ' ' makes the lease never look expired, so a dead
// rebalancer-leader's lease could never transfer until the UTC date rolled.
func TestRebalancer_LeaseTakeoverWhenExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// Expired same-day lease held by "other" → must be taken over.
	db := newRebalancerTestDB(t)
	r := NewRebalancer("me", db)
	r.Now = func() time.Time { return now }
	exp := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES (?, 'other', ?, ?)`,
		r.LeaseKey, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
	if !r.acquireLease(ctx) {
		t.Fatal("must take over an expired same-day rebalancer lease")
	}

	// Valid lease held by another host → must NOT be stolen.
	db2 := newRebalancerTestDB(t)
	r2 := NewRebalancer("me", db2)
	r2.Now = func() time.Time { return now }
	valid := now.Add(time.Minute).UTC().Format(time.RFC3339)
	if err := db2.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES (?, 'other', ?, ?)`,
		r2.LeaseKey, valid, valid); err != nil {
		t.Fatalf("seed valid lease: %v", err)
	}
	if r2.acquireLease(ctx) {
		t.Error("must NOT steal a still-valid rebalancer lease")
	}
}
