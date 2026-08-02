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

// The skew check only means anything if something calls it. It was implemented,
// unit-tested and never invoked until 2026-08-02: probe() is a bare TLS dial
// that never learns a peer's clock, so no clock_skew row was ever written and
// the warning could not fire. It now rides the fresh Ping the capability path
// already makes, so it costs no extra RPC.
func TestPeerSupportsFresh_RecordsClockSkew(t *testing.T) {
	for _, tc := range []struct {
		name    string
		peerNow func() time.Time
		wantRow bool
	}{
		{name: "peer clock agrees", peerNow: time.Now, wantRow: false},
		{name: "peer clock is 5s behind", peerNow: func() time.Time { return time.Now().Add(-5 * time.Second) }, wantRow: true},
		{name: "peer clock is 5s ahead", peerNow: func() time.Time { return time.Now().Add(5 * time.Second) }, wantRow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testCheckerDB(t)
			c := NewChecker("host-a", "/etc/litevirt/pki", db)
			c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
				return []string{"split_brain_gate_v1"}, tc.peerNow(), nil
			})

			if !c.PeerSupportsFresh(context.Background(), "host-b", "split_brain_gate_v1") {
				t.Fatal("precondition: the capability answer must still come through")
			}

			rows, err := db.Query(context.Background(),
				`SELECT target, skew_seconds FROM clock_skew WHERE observer = ?`, "host-a")
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if got := len(rows) == 1; got != tc.wantRow {
				t.Fatalf("clock_skew rows=%d, want row=%v — the fresh Ping must feed the skew check",
					len(rows), tc.wantRow)
			}
			if tc.wantRow && rows[0].String("target") != "host-b" {
				t.Errorf("target = %q, want host-b", rows[0].String("target"))
			}
		})
	}
}

// A peer that reports no clock (an older build, whose PingResponse has no
// wall_clock field) must not be recorded as infinitely skewed.
func TestPeerSupportsFresh_PeerWithoutAClockIsNotSkewed(t *testing.T) {
	db := testCheckerDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return []string{"split_brain_gate_v1"}, time.Time{}, nil
	})

	c.PeerSupportsFresh(context.Background(), "host-b", "split_brain_gate_v1")

	rows, err := db.Query(context.Background(),
		`SELECT target FROM clock_skew WHERE observer = ?`, "host-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("a peer that reports no clock must not be recorded as skewed, got %d row(s)", len(rows))
	}
}
