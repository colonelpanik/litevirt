package failover

import (
	"context"
	"testing"
	"time"
)

// TestRecentlyFenced_SameDayTimestamp guards the bug that blocked live
// auto-promotion: a host fenced earlier the same UTC day was treated as
// "recently fenced" forever, so the coordinator never re-fenced it (its VMs
// never recovered). The original SQL compared an RFC3339 timestamp
// ("…T…Z") against datetime('now',…) as a string — once the date matched, the
// 'T' sorted above the space and the row always looked recent. The comparison
// now happens in Go.
func TestRecentlyFenced_SameDayTimestamp(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c := NewCoordinator("coordinator", db)
	// Pin the clock so "now" is deterministic regardless of wall time.
	now := time.Date(2026, 6, 8, 12, 30, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }

	insert := func(id, result string, ts time.Time) {
		if err := db.Execute(ctx,
			`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
			 VALUES (?, 'h1', 'best-effort-ssh', ?, ?, '')`,
			id, result, ts.UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("insert fence row: %v", err)
		}
	}

	// A fence 38 minutes earlier the SAME day — outside the 5-min window.
	insert("old", "fenced", now.Add(-38*time.Minute))
	if c.recentlyFenced(ctx, "h1") {
		t.Error("a same-day 38-min-old fence must NOT count as recently fenced")
	}

	// A fence 1 minute ago — within the window.
	insert("new", "fenced", now.Add(-1*time.Minute))
	if !c.recentlyFenced(ctx, "h1") {
		t.Error("a 1-min-old fence must count as recently fenced")
	}

	// manualFenceConfirmed only accepts manual-confirmed rows.
	if c.manualFenceConfirmed(ctx, "h1") {
		t.Error("manualFenceConfirmed must ignore plain 'fenced' rows")
	}
	insert("mc", "manual-confirmed", now.Add(-1*time.Minute))
	if !c.manualFenceConfirmed(ctx, "h1") {
		t.Error("a recent manual-confirmed row must be detected")
	}
}
