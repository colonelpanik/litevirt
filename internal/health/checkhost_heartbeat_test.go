package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func healthRowUpdatedAt(t *testing.T, db *corrosion.Client, observer, target string) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT updated_at FROM host_health WHERE observer = ? AND target = ?`, observer, target)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row for %s->%s, got %d", observer, target, len(rows))
	}
	return rows[0].String("updated_at")
}

// TestCheckHost_RefreshesASteadilyHealthyRow is the #196 regression.
//
// checkHost wrote a host_health row ONLY on transition. A peer that fails keeps
// changing — consecutive_failures increments every probe — so the failing
// direction is always fresh. A peer that is steadily healthy changes nothing
// after the first probe, so its row is written once and then never again.
//
// failover.recoverHosts counts healthy observers with updated_at newer than
// healthFreshness (30 s). Nothing refreshes a healthy row inside that window,
// so the count it sees is normally zero and a host in 'offline'/'fenced' can
// only recover if recoverHosts happens to run in the 30 s after the transition
// — which recentlyFenced's 5-minute suppression guarantees it does not. The
// host then stays offline until a manual `lv host undrain`.
//
// Measured on the lab (kvm003, four healthy nodes, 2026-09-20T19:47:46Z): every
// healthy row was stamped 19:43:0xZ, 4m42s old, while the suspect rows for the
// one down node were under 3 s old. Fresh healthy observers available to
// recovery: zero.
func TestCheckHost_RefreshesASteadilyHealthyRow(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)
	host := corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port}

	c.checkHost(ctx, host)
	first := healthRowUpdatedAt(t, db, "host-a", "host-b")

	// Inside the heartbeat window an unchanged healthy peer must stay free —
	// this write is replicated, and one row per peer per probe is not.
	c.checkHost(ctx, host)
	if got := healthRowUpdatedAt(t, db, "host-a", "host-b"); got != first {
		t.Fatalf("an unchanged healthy peer re-wrote its row inside the heartbeat "+
			"window: %s then %s", first, got)
	}

	// Past the heartbeat the identical verdict must be re-stamped, so a host
	// that recovers can still be seen as healthy-and-fresh minutes later.
	restore := HeartbeatInterval
	HeartbeatInterval = time.Millisecond
	t.Cleanup(func() { HeartbeatInterval = restore })
	time.Sleep(20 * time.Millisecond)

	c.checkHost(ctx, host)
	second := healthRowUpdatedAt(t, db, "host-a", "host-b")
	if second == first {
		t.Fatalf("a steadily healthy peer was never re-stamped (%s); every recovery "+
			"gated on a freshness cutoff can therefore never see it", first)
	}
}

// The heartbeat must not manufacture a healthy row for a peer that is failing:
// the refresh re-publishes the CURRENT verdict, whatever it is.
func TestCheckHost_HeartbeatRepublishesTheCurrentVerdict(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	host := corrosion.HostRecord{Name: "host-b", Address: "127.0.0.1", GRPCPort: 1}

	for range suspectThreshold {
		c.checkHost(ctx, host)
	}
	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := rows[0].String("status"); got != "suspect" {
		t.Errorf("status = %q, want suspect", got)
	}
	if got := rows[0].Int("consecutive_failures"); got != suspectThreshold {
		t.Errorf("consecutive_failures = %d, want %d", got, suspectThreshold)
	}
}
