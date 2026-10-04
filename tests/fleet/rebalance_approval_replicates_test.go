// Fleet scenario: every rebalance_proposals status transition reaches the peer.
//
// A proposal moves pending → approved → applying → applied/failed, each step a
// partial UPDATE of one row. The receiver orders those writes by updated_at
// (last-writer-wins), and a partial UPDATE that TIES the row it lands on is
// dropped — by design, since a tie between two full images is resolved and a
// tie against a partial one is left for anti-entropy. So each transition must
// carry an updated_at strictly newer than the one before it.
//
// The writers used to stamp updated_at as whole-second RFC3339 from the
// rebalancer's own clock. A cycle inserts a proposal and auto-approves it in
// the same second, so the peer kept it pending forever while the leader showed
// it approved — and a peer that later took the rebalancer lease would never
// execute it. The executor's claim and terminal status had the same flaw.
//
// rebalance_proposals is outside anti-entropy, so nothing repairs a dropped
// transition later.
//
// The clocks here are pinned to one instant, which is exactly the same-second
// case: the transitions only order if updated_at comes from the replicated
// LWW clock rather than the coordinator's wall clock.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// proposalStatuses maps proposal id → status on one node.
func proposalStatuses(t *testing.T, db *corrosion.Client) map[string]string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id, status FROM rebalance_proposals`)
	if err != nil {
		t.Fatalf("list proposals: %v", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.String("id")] = r.String("status")
	}
	return out
}

// assertProposalsAgree carries the writer's mutation_log to every other node
// over the real PushMutations RPC, then names each node and row still apart
// from want's id → status map. Anti-entropy cannot stand in for it:
// rebalance_proposals is outside the state digest and anti-entropy, so a
// dropped write there never shows up as divergence — and never heals.
func assertProposalsAgree(t *testing.T, c *Cluster, writer *Node, want map[string]string) {
	t.Helper()
	for _, n := range c.Nodes {
		if n != writer {
			pumpMutations(t, c, writer, n)
		}
	}
	for _, n := range c.Nodes {
		got := proposalStatuses(t, n.DB)
		if len(got) != len(want) {
			t.Errorf("%s holds %d proposals, want %d: %v", n.Name, len(got), len(want), got)
			continue
		}
		for id, st := range want {
			if got[id] != st {
				t.Errorf("%s: proposal %s is %q, the writer holds %q", n.Name, id, got[id], st)
			}
		}
	}
}

func TestFleet_RebalanceAutoApprovalReplicatesInTheSameSecond(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	loaded := c.Nodes[0]
	seedRebalanceAutoImbalance(t, c)

	instant := time.Now().UTC().Truncate(time.Second)
	r := scheduler.NewRebalancer(loaded.Name, loaded.DB)
	r.Now = func() time.Time { return instant }
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := proposalStatuses(t, loaded.DB)
	approved := 0
	for _, st := range want {
		if st == "approved" {
			approved++
		}
	}
	if approved == 0 {
		t.Fatalf("leader approved nothing (%v); the scenario proves nothing", want)
	}

	assertProposalsAgree(t, c, loaded, want)
}

func TestFleet_RebalanceExecutorTransitionsReplicateInTheSameSecond(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	loaded := c.Nodes[0]
	seedRebalanceAutoImbalance(t, c)

	instant := time.Now().UTC().Truncate(time.Second)
	r := scheduler.NewRebalancer(loaded.Name, loaded.DB)
	r.Now = func() time.Time { return instant }
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// The real executor on the lease holder, on the same pinned second: it
	// claims each approved row (approved → applying) and records a terminal
	// status, every step a same-second partial UPDATE of the row.
	e := grpcapi.NewRebalanceExecutor(loaded.Server, loaded.Name, loaded.DB)
	e.Now = func() time.Time { return instant }
	e.RunOnce(ctx)
	var want map[string]string
	eventually(t, 10*time.Second, "executor to record a terminal status for every claimed row", func() bool {
		want = proposalStatuses(t, loaded.DB)
		for _, st := range want {
			if st == "approved" || st == "applying" {
				return false
			}
		}
		return true
	})

	assertProposalsAgree(t, c, loaded, want)
}
