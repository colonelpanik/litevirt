package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Phase 4 mixed-rollout coverage: owner_epoch_v1 carries TWO advertisement
// preconditions — the operator's config flag (uniformity, like every
// enforcement token) and this node's readiness (no workload it owns is still
// at the pre-epoch 0). Either one missing on ANY node must hold the whole
// fleet back, because a node that latched early would begin enforcing
// marker/epoch agreement across peers whose generations do not exist yet:
// "never bless an already-diverged cluster".

// wireOwnerEpochReadiness installs the real readiness probe (the same closure
// the daemon installs) WITHOUT opting in. Kept separate from the flag so a
// scenario can isolate one precondition from the other: an unwired probe also
// withholds the token, which would let a flag-only test pass for the wrong
// reason (it did — mutation testing caught it).
func wireOwnerEpochReadiness(n *Node) {
	n.Server.SetOwnerEpochReady(func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ok, err := corrosion.OwnerEpochBackfillComplete(ctx, n.DB, n.Name)
		return err == nil && ok
	})
}

// enableOwnerEpoch is readiness + the operator opt-in.
func enableOwnerEpoch(n *Node) {
	wireOwnerEpochReadiness(n)
	n.Server.SetOwnerEpochEnforce(true)
}

// TestFleet_OwnerEpoch_LatchWaitsForEveryNodeFlag proves config uniformity:
// one node with the flag off holds the latch closed for everyone.
func TestFleet_OwnerEpoch_LatchWaitsForEveryNodeFlag(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	gates := gateAll(t, c)

	// Readiness is wired and satisfied on EVERY node (none owns a pre-epoch
	// workload), so the config flag is the only variable. Wiring the laggard's
	// probe matters: an unwired probe withholds the token by itself, which
	// would make this pass without the flag check ever running.
	laggard := c.Nodes[len(c.Nodes)-1]
	for _, n := range c.Nodes {
		wireOwnerEpochReadiness(n)
	}
	for _, n := range c.Nodes {
		if n != laggard {
			n.Server.SetOwnerEpochEnforce(true)
		}
	}
	for _, n := range c.Nodes {
		if gates[n.Name].Enforced(ctx, capabilities.OwnerEpochV1) {
			t.Fatalf("%s: owner_epoch_v1 latched while %s had the flag off", n.Name, laggard.Name)
		}
	}

	laggard.Server.SetOwnerEpochEnforce(true)
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "owner_epoch_v1 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.OwnerEpochV1)
		})
	}
}

// TestFleet_OwnerEpoch_LatchWaitsForEveryNodeBackfill proves the readiness
// half: every node has opted in, but one still owns a workload at the
// pre-epoch 0 — that node must withhold the token until its backfill runs.
func TestFleet_OwnerEpoch_LatchWaitsForEveryNodeBackfill(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	gates := gateAll(t, c)

	// The laggard owns a VM that has never been graduated out of epoch 0.
	laggard := c.Nodes[len(c.Nodes)-1]
	if err := corrosion.InsertVM(ctx, laggard.DB, corrosion.VMRecord{
		Name: "pre-epoch-vm", HostName: laggard.Name, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	for _, n := range c.Nodes {
		enableOwnerEpoch(n)
	}
	for _, n := range c.Nodes {
		if gates[n.Name].Enforced(ctx, capabilities.OwnerEpochV1) {
			t.Fatalf("%s: owner_epoch_v1 latched while %s still owned a pre-epoch workload",
				n.Name, laggard.Name)
		}
	}

	// Run the laggard's backfill — the graduation the readiness gate waits on.
	if err := corrosion.BackfillOwnerEpochs(ctx, laggard.DB, laggard.Name); err != nil {
		t.Fatalf("BackfillOwnerEpochs on %s: %v", laggard.Name, err)
	}
	if vm, _ := corrosion.GetVM(ctx, laggard.DB, "pre-epoch-vm"); vm == nil || vm.OwnerEpoch == 0 {
		t.Fatalf("backfill did not graduate the workload: %+v", vm)
	}
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "owner_epoch_v1 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.OwnerEpochV1)
		})
	}
}
