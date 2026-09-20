package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCheckHost_DoesNotInheritFailuresAcrossARestart is the #201 regression.
//
// checkHost seeds a peer's consecutive_failures from the host_health row when
// it has no in-memory state for that peer — which is exactly the state a
// freshly started daemon is in. The very first probe of a restarted daemon
// therefore publishes prev+1 with a CURRENT updated_at: a fence-quorum-eligible
// "suspect" verdict carrying a failure count this run never observed.
//
// gate.go:151 closed precisely this hole in the HEALTHY direction, and says why
// — peerState.status is seeded from the DB, so a restarted isolated node would
// read a peer as healthy from a stale pre-restart row. lastHealthyAt is a local
// monotonic anchor, zero until THIS run probes the peer healthy, so it cannot be
// credited across a restart. The failing direction had no such anchor.
//
// Measured on the lab (kvm003, node-1 -> node-5): the row read suspect|141
// before `systemctl restart litevirt` and suspect|178 forty seconds after it.
// The count did not restart at 1.
func TestCheckHost_DoesNotInheritFailuresAcrossARestart(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()

	// The row a previous run of this daemon left behind: well past
	// suspectThreshold, so an inherited count is instantly a fence vote.
	db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		"host-a", "host-b", "suspect", 141)

	// A NEW Checker is a restarted daemon: no in-memory peer state at all.
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.checkHost(ctx, corrosion.HostRecord{
		Name:     "host-b",
		Address:  "127.0.0.1",
		GRPCPort: 1, // unreachable
	})

	rows, err := db.Query(ctx,
		`SELECT consecutive_failures, status FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].Int("consecutive_failures"); got != 1 {
		t.Errorf("consecutive_failures = %d, want 1 — this run has observed exactly "+
			"one failure; %d would be a count inherited from a previous daemon", got, got)
	}
	if got := rows[0].String("status"); got != "healthy" {
		t.Errorf("status = %q, want healthy — one fresh failure is below "+
			"suspectThreshold (%d), so a just-restarted observer must not vote to fence",
			got, suspectThreshold)
	}
}

// A restarted daemon must still reach suspect on its OWN evidence, at the same
// threshold as any other run. The fix must not make a node unable to fence.
func TestCheckHost_RestartedObserverStillReachesSuspectOnItsOwnFailures(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()

	db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		"host-a", "host-b", "suspect", 141)

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	host := corrosion.HostRecord{Name: "host-b", Address: "127.0.0.1", GRPCPort: 1}
	for range suspectThreshold {
		c.checkHost(ctx, host)
	}

	rows, err := db.Query(ctx,
		`SELECT consecutive_failures, status FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := rows[0].Int("consecutive_failures"); got != suspectThreshold {
		t.Errorf("consecutive_failures = %d, want %d", got, suspectThreshold)
	}
	if got := rows[0].String("status"); got != "suspect" {
		t.Errorf("status = %q, want suspect after %d fresh failures", got, suspectThreshold)
	}
}
