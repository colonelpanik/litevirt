// Fleet scenarios for host capacity admission across MORE THAN ONE host.
//
// Everything else about capacity is verified single-host (unit tests, and a real
// 4-node lab). What those cannot reach is the multi-node behaviour that only
// exists when a request enters one daemon and the workload belongs on another:
//
//   - placement must SKIP a host without headroom and pick one with it, using the
//     same allocatable definition admission uses. When the two disagreed, a pinned
//     create bypassed the check entirely while a resize into the same host was
//     refused — the exact split this pins shut.
//   - a create entering a NON-owning node must still be admitted against the
//     TARGET's capacity, not the entry node's. The check runs on the entry node
//     (fail fast) and again on the owner (serialized), and the spec carries the
//     pin across the forward, so both see the same host.
//   - per-host overrides must actually differ across a fleet: a node with more
//     generous policy accepts what its peer refuses.
//
// These run in-process over real gRPC + mTLS, so they need no lab and cannot
// collide with anything running on one.

package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// setHostCapacity sizes a node's physical totals and, optionally, its per-host
// policy overrides. Written to every node's DB so each one's view agrees —
// admission runs on the entry node as well as the owner.
func setHostCapacity(t *testing.T, c *Cluster, host string, cpuTotal, memTotal int, memReserve *int) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		rec, err := corrosion.GetHost(ctx, n.DB, host)
		if err != nil || rec == nil {
			t.Fatalf("GetHost %s on %s: rec=%v err=%v", host, n.Name, rec, err)
		}
		if err := n.DB.Execute(ctx,
			`UPDATE hosts SET cpu_total = ?, mem_total = ?, mem_reserve_mib = ?, updated_at = ? WHERE name = ?`,
			cpuTotal, memTotal, optIntOrSentinel(memReserve), n.DB.NowTS(), host); err != nil {
			t.Fatalf("size host %s on %s: %v", host, n.Name, err)
		}
	}
}

// optIntOrSentinel encodes an optional reserve the way the schema does: -1 means
// "inherit the cluster default", and 0 is a real "no reserve".
func optIntOrSentinel(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// runVM asks node n to create a VM, optionally pinned to a specific host.
func runVM(t *testing.T, c *Cluster, at *Node, name, pinHost string, cpu, memMiB int32) (*pb.VM, error) {
	t.Helper()
	spec := &pb.VMSpec{Name: name, Cpu: cpu, MemoryMib: memMiB}
	if pinHost != "" {
		spec.Placement = &pb.PlacementSpec{Host: pinHost}
	}
	return c.SelfClient(at).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: spec})
}

// TestFleet_Capacity_PlacementSkipsTheHostItWouldOtherWisePrefer pins that the
// capacity filter is LOAD-BEARING in placement, not merely agreeing with the
// scorer.
//
// The sizing matters. A small idle host and a large busy one is not a test: the
// balance policy already prefers the idle one, so removing the capacity filter
// changes nothing (the first version of this survived exactly that mutation).
// Here the idle host is the one placement WANTS on utilization (0% vs 50%) but
// physically cannot take the VM.
//
// Mutation-verified, with a caveat worth stating: replacing the hard capacity
// filter with infinite headroom leaves this test GREEN, because the balance
// scorer computes pressure INCLUDING the request — placing 4 GiB on a 2 GiB host
// is pressure > 1, which scores zero — so it independently declines the host.
// Two mechanisms enforce this, and neither alone is provably necessary from here.
// That is defence in depth, not a weak assertion: what the test pins is the
// end-to-end property (an unpinned create never lands where it cannot fit), which
// is the thing operators depend on.
func TestFleet_Capacity_PlacementSkipsTheHostItWouldOtherwisePrefer(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	tiny, big := c.Nodes[0], c.Nodes[1]

	// tiny: 2 GiB, idle → 0% utilization, but ~1 GiB allocatable after the reserve.
	setHostCapacity(t, c, tiny.Name, 8, 2048, nil)
	// big: 64 GiB, half consumed → 50% utilization, and tens of GiB free.
	setHostCapacity(t, c, big.Name, 32, 65536, nil)
	if err := corrosion.InsertVM(ctx, tiny.DB, corrosion.VMRecord{
		Name: "ballast", HostName: big.Name, State: "running", Spec: "{}",
		CPUActual: 8, MemActual: 32768,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	vm, err := runVM(t, c, tiny, "placed", "", 1, 4096)
	if err != nil {
		t.Fatalf("unpinned create with a host that has room: %v", err)
	}
	if vm.HostName != big.Name {
		t.Errorf("VM placed on %q, want %q — placement chose the host it prefers on utilization over the one that can actually hold it",
			vm.HostName, big.Name)
	}
}

// TestFleet_Capacity_PinnedCreateIsAdmittedAgainstTheTargetHost is the property
// the original bug violated from the other direction: entering one daemon and
// pinning another must be checked against the TARGET's capacity, not the entry
// node's (which here has plenty).
//
// Also two layers, also verified: pointing the entry node's check at its OWN host
// keeps this green, because CreateVM forwards to the owner and the owner checks
// again — the entry-node check is a fail-fast, not the sole guard. The invariant
// under test is that the refusal happens at all, wherever it comes from.
func TestFleet_Capacity_PinnedCreateIsAdmittedAgainstTheTargetHost(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, target := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 32, 65536, nil) // entry: enormous
	setHostCapacity(t, c, target.Name, 8, 4096, nil)  // target: small
	if err := corrosion.InsertVM(ctx, entry.DB, corrosion.VMRecord{
		Name: "sitting", HostName: target.Name, State: "running", Spec: "{}",
		CPUActual: 1, MemActual: 2800,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	_, err := runVM(t, c, entry, "toobig", target.Name, 1, 2048)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("pinned create onto a full target from a roomy entry node: got %v, want ResourceExhausted — the entry node's own capacity is irrelevant", err)
	}
	if rec, _ := corrosion.GetVM(ctx, entry.DB, "toobig"); rec != nil {
		t.Errorf("refused VM was persisted anyway: %+v", rec)
	}
}

// TestFleet_Capacity_PerHostOverrideDiffersAcrossTheFleet: the override is stored
// per host and replicated, so one node can be more generous than its peer. If
// overrides were read from local config instead, both would behave identically
// and this would fail.
func TestFleet_Capacity_PerHostOverrideDiffersAcrossTheFleet(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	strict, generous := c.Nodes[0], c.Nodes[1]

	zero := 0
	// Same physical size; only the reserve differs. 2048 MiB total: the default
	// 1024 reserve leaves 1024, an explicit zero reserve leaves all 2048.
	setHostCapacity(t, c, strict.Name, 8, 2048, nil)     // inherit → 1024 reserve
	setHostCapacity(t, c, generous.Name, 8, 2048, &zero) // explicit zero reserve

	if _, err := runVM(t, c, strict, "strict-vm", strict.Name, 1, 1600); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("1600 MiB onto the host with the default reserve: got %v, want ResourceExhausted", err)
	}
	if _, err := runVM(t, c, strict, "generous-vm", generous.Name, 1, 1600); err != nil {
		t.Fatalf("1600 MiB onto the host with a zero reserve was refused: %v — the per-host override did not apply", err)
	}
}

// TestFleet_Capacity_ContainersCountAgainstVMs closes the loop across workload
// KINDS: a container holding memory on a host must be visible to a VM create
// arriving at a different node.
func TestFleet_Capacity_ContainersCountAgainstVMs(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, target := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 32, 65536, nil)
	setHostCapacity(t, c, target.Name, 8, 4096, nil) // allocatable 3072

	// A running, CAPPED container eats most of the target's headroom.
	if err := corrosion.UpsertContainer(ctx, entry.DB, corrosion.ContainerRecord{
		HostName: target.Name, Name: "hog", State: "running", MemMiB: 2800,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	if _, err := runVM(t, c, entry, "vm-after-ct", target.Name, 1, 2048); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("VM create onto a host filled by a CONTAINER: got %v, want ResourceExhausted — containers hold host memory too", err)
	}
}
