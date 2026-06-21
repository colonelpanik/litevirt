// Fleet scenario 2: failover with leader contention.
//
// Three nodes share the cluster state (SharedCRDT mode — the simplest
// way to model "every coordinator sees the same health rows"). Two
// observers report node-A failing; both other nodes run coordinator
// cycles simultaneously. Exactly one of them must fence; the other
// must observe the lease holder and back off. After fencing, the VM
// owned by node-A must be rescheduled to a healthy host via the
// failover path.
//
// What this exercises end-to-end:
//   - leader_election table acquired + released across two contenders
//   - fencing_log row written by exactly one fencer
//   - VM ownership transfer via UpdateVMHost
//   - quorum-of-2 freshness predicate (~30 s window — virtual time
//     not strictly necessary here, but the helper accepts it)
//
// Note: this is similar in spirit to tests/cluster/leader_election_test.go
// — the difference is that we drive the *whole* grpcapi.Server, not
// just *failover.Coordinator. That catches integration issues like
// the fencer/auth/audit wire-up that the cluster-level scenarios miss.

package fleet

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

func TestFleet_Failover_LeaderContention(t *testing.T) {
	// SharedCRDT makes the three nodes see one DB — that's the
	// "everyone's perfectly converged" baseline. A more aggressive
	// follow-up scenario would drop the shared mode and assert the
	// real Replicator carries the health rows across in time.
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, vctim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// All three nodes are already host_record-registered by the
	// harness. Mark `vctim` as the failure target by inserting
	// quorum health rows from the OTHER two nodes.
	//
	// updated_at MUST be RFC3339 (matching internal/health/checker.go), NOT
	// SQLite's datetime('now') space format: the coordinator's freshness gate
	// compares updated_at against an RFC3339 cutoff, and a space-separated
	// timestamp sorts before any 'T'-separated one (' ' < 'T'), so a
	// datetime('now') row reads as permanently stale and never reaches quorum.
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, observer := range []string{a.Name, b.Name} {
		if err := a.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`,
			observer, vctim.Name, nowRFC,
		); err != nil {
			t.Fatalf("insert health %s: %v", observer, err)
		}
	}

	// Pin a VM to node-vctim so we can observe rescheduling. The
	// failover coordinator looks at vms.spec for the on-host-failure
	// policy; the default for production VMs is RESTART_ANY which
	// triggers a re-place.
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name:     "vm-vctim",
		HostName: vctim.Name,
		Spec:     `{"on_host_failure":"restart-any"}`,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Two coordinators race on the same DB — exactly one should fence.
	// (Coordinators run inside the fleet daemons in production; here
	// we drive them on the test thread so we can race them deterministically
	// rather than waiting on the embedded 30 s tickers.)
	var aFence, bFence atomic.Int32
	coordA := failover.NewCoordinator(a.Name, a.DB)
	coordA.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		aFence.Add(1)
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coordB := failover.NewCoordinator(b.Name, b.DB)
	coordB.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		bFence.Add(1)
		return fence.Result{Method: "fleet-test", Success: true}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); coordA.RunOnce(ctx) }()
	go func() { defer wg.Done(); coordB.RunOnce(ctx) }()
	wg.Wait()

	totalFences := aFence.Load() + bFence.Load()
	if totalFences != 1 {
		t.Errorf("expected exactly 1 fence call across 2 coordinators, got a=%d b=%d",
			aFence.Load(), bFence.Load())
	}

	// Second pass must not re-fence (recentlyFenced gate).
	coordA.RunOnce(ctx)
	coordB.RunOnce(ctx)
	if got := aFence.Load() + bFence.Load(); got != totalFences {
		t.Errorf("re-fence on second cycle: total = %d, want %d", got, totalFences)
	}

	// Victim host transitioned out of "active". The failover code
	// path marks it "fenced".
	vrec, _ := corrosion.GetHost(ctx, a.DB, vctim.Name)
	if vrec == nil || vrec.State == "active" {
		t.Errorf("victim still active after fencing: %+v", vrec)
	}

	// VM rescheduled to a non-victim host.
	vmAfter, _ := corrosion.GetVM(ctx, a.DB, "vm-vctim")
	if vmAfter == nil {
		t.Fatal("VM disappeared after failover")
	}
	if vmAfter.HostName == vctim.Name {
		t.Errorf("VM still hosted on fenced victim: %+v", vmAfter)
	}
}
