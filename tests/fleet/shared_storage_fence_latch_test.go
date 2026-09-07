// Fleet scenario: the shared-storage fence latches on BUILD uniformity, not on
// config uniformity — and this test exists because getting that backwards is a
// live, repeatedly-proposed change that no single-package test can catch.
//
// shared_storage_fence_v1 gates a corruption hazard, which makes it look like it
// belongs with operation_protocol_v1 and the other tokens advertisedCapabilities
// withholds while their config flag is off. It does not, because no node RELIES
// on a peer enforcing it: the coordinator refuses to CREATE a shared-disk
// transfer without a proof-grade fence of the old owner, so whenever a transfer
// exists at all the old owner is provably down and a destination with its flag
// off starts it safely.
//
// Making it conditional therefore prevents no corruption, and costs two things
// this test pins:
//
//   - A WITNESS holds the fence off fleet-wide, permanently. internal/health's
//     activation sweep gates on every voting-eligible host with NO role filter,
//     and a witness operator has no reason to set the flag — a witness hosts no
//     workload and can never perform a fence. `lv doctor fence` could not even
//     explain it, because GetFenceReadiness deliberately drops witnesses from
//     its per-host report.
//   - Every node mid-rollout stops enforcing, including nodes already
//     configured: both the source-side refusal (failover) and the executor's
//     re-verify (health/reconciler) gate on the latch, so a partial enable
//     would take away protection that a partial enable used to provide.
//
// Only a fleet reaches this. The latch is negotiated by separate health.Checker
// instances exchanging real Ping RPCs over real mTLS against the real
// corrosion.ListHosts sweep; a single-package test builds one Server and never
// forms a latch at all.

package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// makeWitness flips a host's role in the replicated table. The activation sweep
// reads corrosion.ListHosts, so the row is what makes the node a witness as far
// as latching is concerned.
func makeWitness(t *testing.T, c *Cluster, witness *Node) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := n.DB.Execute(context.Background(),
			`UPDATE hosts SET role = 'witness', updated_at = ? WHERE name = ?`,
			n.DB.NowTS(), witness.Name); err != nil {
			t.Fatalf("make %s a witness in %s's rows: %v", witness.Name, n.Name, err)
		}
	}
}

// TestFleet_SharedStorageFenceLatchesOnMixedConfig is the regression guard.
//
// The enforcing node must reach a latch while a worker AND a witness both have
// the kill-switch off, because its own enforcement is `flag && Enforced` — if
// the latch cannot close, the node that opted in silently stops fencing, which
// is worse than the state the change would be trying to improve.
func TestFleet_SharedStorageFenceLatchesOnMixedConfig(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	gates := gateAll(t, c)

	enforcer, holdout, witness := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	makeWitness(t, c, witness)

	// Only the enforcer opts in — the mixed state a fleet occupies for the whole
	// of a rollout, and the steady state of any cluster running a witness.
	for _, n := range c.Nodes {
		n.Server.SetEnforcementConfig(false, false, false, false, false, n == enforcer)
	}

	if !gates[enforcer.Name].Enforced(ctx, capabilities.SharedStorageFenceV1) {
		t.Fatalf("%s has enforcement.shared_storage_fence on, but %s did not latch with "+
			"%s (worker) and %s (witness) holding the flag off. Its own gate is "+
			"`flag && Enforced`, so the node that opted in now enforces NOTHING: the "+
			"coordinator stops refusing unproven shared-disk transfers and the executor "+
			"stops re-verifying. A witness makes this permanent — its operator has no "+
			"reason to ever set the flag",
			enforcer.Name, capabilities.SharedStorageFenceV1, holdout.Name, witness.Name)
	}

	// The kill-switch must stay a purely LOCAL decision on top of that latch:
	// a latched token on a flag-off node is not enforcement, and conflating the
	// two is what makes `lv doctor fence` necessary.
	if !gates[holdout.Name].Enforced(ctx, capabilities.SharedStorageFenceV1) {
		t.Errorf("%s did not latch either; the latch is cluster-wide and does not depend "+
			"on the local flag", holdout.Name)
	}
	r := fenceReadinessFrom(t, c, enforcer)
	if r.GetEnforcedEverywhere() {
		t.Error("enforced_everywhere is true while two hosts have the kill-switch off — " +
			"a latched token is being read as proof of enforcement")
	}
}
