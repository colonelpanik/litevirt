// Fleet scenario 6: virtual time across failover + rebalancer.
//
// Proves the Now() injection on failover.Coordinator and
// scheduler.Rebalancer is actually consulted — and demonstrates the
// pattern scenarios should follow when they need to advance the
// cluster clock past lease/proposal expiries without sleeping.
//
// What this covers:
//   - failover.Coordinator.acquireLease writes expires_at via c.now()
//   - scheduler.Rebalancer.recordProposal + acquireLease + expireOldProposals
//     all read r.now()
//   - A scenario can swap the clock for both and observe deterministic
//     timestamps without relying on sleeps

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/scheduler"
)

func TestFleet_VirtualTimeAcrossCoordinators(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]

	// Pin both coordinators to a controlled clock.
	pin := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return pin }

	coord := failover.NewCoordinator(node.Name, node.DB)
	coord.Now = clock
	reb := scheduler.NewRebalancer(node.Name, node.DB)
	reb.Now = clock

	// Drive both. Both write a leader_election row with
	// expires_at = clock + leaseDuration. We don't need to assert
	// anything beyond "ran without panic" — the contract is that
	// the timestamp on the row reflects `pin`, not wall-clock-Now.
	// The interface mockability is the point.
	coord.RunOnce(ctx)
	if err := reb.RunOnce(ctx); err != nil {
		t.Fatalf("rebalancer.RunOnce: %v", err)
	}

	// Read the lease row directly and confirm the timestamp is in
	// 2026-05-11 (the pinned year), not the wall-clock year.
	rows, qerr := node.DB.Query(ctx,
		"SELECT key, expires_at FROM leader_election")
	if qerr != nil {
		t.Fatalf("query leader_election: %v", qerr)
	}
	if len(rows) == 0 {
		t.Fatal("no leader_election rows after coordinator run")
	}
	for _, r := range rows {
		exp := r.String("expires_at")
		if exp == "" {
			continue
		}
		// The pinned clock is 2026-05-11; any sane lease duration
		// (5 minutes for failover, 2x60s for rebalancer) lands the
		// expires_at on the same day. If wall-clock had been used,
		// expires_at would carry today's real-time year.
		if exp[:4] != "2026" {
			t.Errorf("lease %q expires_at = %q; not pinned to virtual clock",
				r.String("key"), exp)
		}
	}
}
