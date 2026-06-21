package failover

import (
	"context"
	"testing"
	"time"
)

// TestCoordinator_LeaseTakeoverWhenExpired guards the lease-transfer bug: the
// failover lease's expires_at is RFC3339, and the acquire path compared it
// against datetime('now') as a string. Once the date matched, 'T' > ' ' made a
// same-day lease never look expired — so a dead leader's lease could never be
// taken over (failover stalls cluster-wide until the UTC day rolls over). With
// the fix (RFC3339 on both sides, via the injected clock) an expired same-day
// lease is taken over.
func TestCoordinator_LeaseTakeoverWhenExpired(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }

	// A lease held by "other", expired one minute ago — same UTC day, RFC3339.
	exp := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'other', ?, ?)`, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	if !c.acquireLease(ctx) {
		t.Fatal("must take over an expired same-day lease")
	}
	rows, err := db.Query(ctx, `SELECT holder FROM leader_election WHERE key = 'failover'`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	if got := rows[0].String("holder"); got != "me" {
		t.Errorf("lease holder = %q, want me", got)
	}

	// And a still-valid lease held by someone else is NOT stolen.
	db2 := newTestDB(t)
	c2 := NewCoordinator("me", db2)
	c2.Now = func() time.Time { return now }
	valid := now.Add(20 * time.Second).UTC().Format(time.RFC3339)
	if err := db2.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'other', ?, ?)`, valid, valid); err != nil {
		t.Fatalf("seed valid lease: %v", err)
	}
	if c2.acquireLease(ctx) {
		t.Error("must NOT take over a still-valid lease held by another host")
	}
}
