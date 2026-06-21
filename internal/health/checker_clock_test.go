package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testCheckerDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestCheckClockSkew_NoSkew(t *testing.T) {
	db := testCheckerDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	// Peer timestamp is now — no skew.
	c.checkClockSkew(context.Background(), "host-b", time.Now())

	// Verify no row was written to clock_skew (skew < 1s).
	rows, err := db.Query(context.Background(),
		`SELECT target FROM clock_skew WHERE observer = ?`, "host-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no clock_skew rows for small skew, got %d", len(rows))
	}
}

func TestCheckClockSkew_LargeSkew(t *testing.T) {
	db := testCheckerDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	// Peer timestamp is 5 seconds ago — should trigger warning and DB write.
	c.checkClockSkew(context.Background(), "host-b", time.Now().Add(-5*time.Second))

	rows, err := db.Query(context.Background(),
		`SELECT target FROM clock_skew WHERE observer = ?`, "host-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 clock_skew row, got %d", len(rows))
	}
	if rows[0].String("target") != "host-b" {
		t.Errorf("target = %q, want host-b", rows[0].String("target"))
	}
}

func TestCheckClockSkew_FutureTimestamp(t *testing.T) {
	db := testCheckerDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	// Peer claims to be 3 seconds in the future — should also trigger.
	c.checkClockSkew(context.Background(), "host-c", time.Now().Add(3*time.Second))

	rows, err := db.Query(context.Background(),
		`SELECT target FROM clock_skew WHERE observer = ?`, "host-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 clock_skew row for future skew, got %d", len(rows))
	}
}
