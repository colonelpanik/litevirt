// Package cluster contains integration tests for litevirt's clustering,
// replication, and failover code. These tests exercise *real* package
// internals (internal/corrosion, internal/failover, internal/health,
// internal/hlc, internal/fence) but use the chaos harness for
// deterministic time and network simulation.
//
// The tests in this directory are "Jepsen-style" clustering-correctness
// scenarios: each one names the exact failure mode it exercises so a
// future regression is obvious.
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

// sharedTestDB returns a corrosion client whose underlying SQLite DB is
// shared among multiple clients via the given dsnSuffix. Callers passing
// the same suffix get clients pointing at the same in-memory DB — a
// reasonable proxy for "all hosts converged via CRDT replication" while
// avoiding a full replication harness.
//
// Use distinct dsnSuffix values when you want to simulate a partition.
func sharedTestDB(t *testing.T, hostName, dsnSuffix string) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewSharedTestClient("cluster-"+dsnSuffix, hostName)
	if err != nil {
		t.Fatalf("NewSharedTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

// TestLeaderElection_OnlyOneFences exercises the single-fencer invariant: with the leader_election
// table now present in the schema, two coordinators sharing the same CRDT
// state must not concurrently fence the same host.
//
// Before the fix, the table was missing → INSERT/SELECT swallowed errors →
// every coordinator passed the "do I hold the lease?" gate → all of them
// called fence.Execute concurrently.
func TestLeaderElection_OnlyOneFences(t *testing.T) {
	ctx := context.Background()
	db := sharedTestDB(t, "node-a", "leader-election-1")

	// Three active hosts in the cluster.
	for _, h := range []string{"node-a", "node-b", "victim"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + h, SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Quorum-of-2 observers (node-a and node-b) report victim failing.
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, observer := range []string{"node-a", "node-b"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'victim', 'suspect', 5, NULL, ?)`,
			observer, nowRFC,
		); err != nil {
			t.Fatalf("insert health %s: %v", observer, err)
		}
	}

	// Two coordinators racing on the same DB. Each has a counter-bumping
	// fencer so the test can prove only one of them actually fenced.
	var aCount, bCount atomic.Int32
	a := failover.NewCoordinator("node-a", db)
	a.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		aCount.Add(1)
		return fence.Result{Method: "test", Success: true}
	})
	b := failover.NewCoordinator("node-b", db)
	b.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		bCount.Add(1)
		return fence.Result{Method: "test", Success: true}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.RunOnce(ctx) }()
	go func() { defer wg.Done(); b.RunOnce(ctx) }()
	wg.Wait()

	total := aCount.Load() + bCount.Load()
	if total != 1 {
		t.Errorf("expected exactly 1 fence call across both coordinators, got a=%d b=%d (total %d)",
			aCount.Load(), bCount.Load(), total)
	}

	// Loser may or may not also see victim already-fenced via recentlyFenced
	// on a second cycle. Run again to verify nobody re-fences.
	a.RunOnce(ctx)
	b.RunOnce(ctx)
	if got := aCount.Load() + bCount.Load(); got != total {
		t.Errorf("re-fence after first cycle: total fences grew to %d, want %d", got, total)
	}
}

// TestQuorumIgnoresStaleHealth exercises stale-health exclusion: a long-dead observer's
// host_health rows must not satisfy the quorum predicate.
func TestQuorumIgnoresStaleHealth(t *testing.T) {
	ctx := context.Background()
	db := sharedTestDB(t, "coordinator", "stale-health-1")

	for _, h := range []string{"coordinator", "victim", "watcher"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + h, SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Two observers report failure, but both rows are 10 minutes old. Use an
	// RFC3339 timestamp (matching production) so the row is rejected for genuine
	// AGE, not a datetime('now') format quirk — exercising the freshness gate.
	staleRFC := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	for _, observer := range []string{"watcher", "coordinator"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'victim', 'suspect', 5, NULL, ?)`,
			observer, staleRFC,
		); err != nil {
			t.Fatalf("insert stale: %v", err)
		}
	}

	var fenceCount atomic.Int32
	c := failover.NewCoordinator("coordinator", db)
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fenceCount.Add(1)
		return fence.Result{Method: "test", Success: true}
	})
	c.RunOnce(ctx)

	if fenceCount.Load() != 0 {
		t.Errorf("stale rows triggered fence (count=%d); freshness predicate broken", fenceCount.Load())
	}
	v, _ := corrosion.GetHost(ctx, db, "victim")
	if v == nil || v.State != "active" {
		t.Errorf("victim should still be active; got state=%v", v)
	}
}
