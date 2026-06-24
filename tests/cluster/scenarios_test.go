package cluster

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestThreeCoordinators_AtMostOneFences extends the leader-election scenario
// from two contenders to three. The lease is granted to whichever coordinator
// commits first; the other two must back off rather than parallel-fence.
//
// This exercises the single-fencer invariant in the steady-state-after-growth case: a freshly added
// node in a previously-2-node cluster must integrate into the lease protocol
// without creating a third concurrent fencer.
func TestThreeCoordinators_AtMostOneFences(t *testing.T) {
	ctx := context.Background()
	db := sharedTestDB(t, "node-a", "three-coord-1")

	for _, h := range []string{"node-a", "node-b", "node-c", "victim"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + h, SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Quorum: three observers all report victim suspect. Without the
	// lease, naive logic would fence three times.
	// updated_at MUST be RFC3339 to match production (internal/health/checker.go)
	// and the coordinator's freshness gate; SQLite datetime('now') is space-
	// separated and sorts before any 'T'-separated cutoff, so it reads as
	// permanently stale and the row never reaches quorum (the freshness bug).
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, observer := range []string{"node-a", "node-b", "node-c"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'victim', 'suspect', 5, NULL, ?)`,
			observer, nowRFC,
		); err != nil {
			t.Fatalf("insert health %s: %v", observer, err)
		}
	}

	var counts [3]atomic.Int32
	coords := [3]*failover.Coordinator{
		failover.NewCoordinator("node-a", db),
		failover.NewCoordinator("node-b", db),
		failover.NewCoordinator("node-c", db),
	}
	for i, c := range coords {
		i := i
		c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
			counts[i].Add(1)
			return fence.Result{Method: "test", Success: true}
		})
	}

	var wg sync.WaitGroup
	wg.Add(len(coords))
	for _, c := range coords {
		c := c
		go func() { defer wg.Done(); c.RunOnce(ctx) }()
	}
	wg.Wait()

	total := counts[0].Load() + counts[1].Load() + counts[2].Load()
	if total != 1 {
		t.Errorf("expected exactly 1 fence call across three coordinators, got [%d %d %d] (total %d)",
			counts[0].Load(), counts[1].Load(), counts[2].Load(), total)
	}

	// Re-run all three. None should re-fence — recentlyFenced is the
	// authoritative gate in the second cycle.
	for _, c := range coords {
		c.RunOnce(ctx)
	}
	if got := counts[0].Load() + counts[1].Load() + counts[2].Load(); got != total {
		t.Errorf("re-fence after first cycle: total fences grew to %d, want %d", got, total)
	}
}

// TestPartitionMinorityCannotFence simulates a 3-node cluster cleaved into
// two CRDT views: the *minority* side ({node-c}) sees its peers as unhealthy
// but cannot satisfy quorum-of-2 since only one observer (itself) is on its
// side of the partition. The majority view ({node-a, node-b}) is held in a
// separate DB to model the partition; the minority view *must not* fence
// even with a unanimous-of-1 vote.
//
// This exercises the freshness+quorum predicate's robustness: a minority
// partition that is loud about peer failures still gets blocked by the
// "≥2 distinct fresh observers" rule.
func TestPartitionMinorityCannotFence(t *testing.T) {
	ctx := context.Background()
	// Distinct dsnSuffix values give us isolated CRDT views.
	minority := sharedTestDB(t, "node-c", "partition-minority")

	for _, h := range []string{"node-a", "node-b", "node-c"} {
		if err := corrosion.InsertHost(ctx, minority, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + h, SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Only node-c (this side of the partition) reports its peers
	// unhealthy. Quorum-of-2 cannot be satisfied.
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, target := range []string{"node-a", "node-b"} {
		if err := minority.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES ('node-c', ?, 'suspect', 5, NULL, ?)`,
			target, nowRFC,
		); err != nil {
			t.Fatalf("insert health %s: %v", target, err)
		}
	}

	var fenceCount atomic.Int32
	c := failover.NewCoordinator("node-c", minority)
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fenceCount.Add(1)
		return fence.Result{Method: "test", Success: true}
	})
	c.RunOnce(ctx)

	if fenceCount.Load() != 0 {
		t.Errorf("minority partition fenced peers (count=%d); quorum predicate is broken under partition", fenceCount.Load())
	}
	for _, name := range []string{"node-a", "node-b"} {
		h, _ := corrosion.GetHost(ctx, minority, name)
		if h == nil || h.State != "active" {
			t.Errorf("%s should still be active in minority view; got %v", name, h)
		}
	}
}
