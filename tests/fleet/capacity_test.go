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
	"sync"
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

// TestFleet_Capacity_HostListingReportsContainerMemory: the operator-facing view
// must agree with admission.
//
// Admission counts container memory against host capacity. When `lv host ls`
// counted only VMs, a host could display plenty of free memory and still refuse a
// VM — indistinguishable, from the operator's side, from a bug in litevirt. This
// pins the two together.
func TestFleet_Capacity_HostListingReportsContainerMemory(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	n := c.Nodes[0]

	memOf := func(host string) int32 {
		t.Helper()
		resp, err := c.SelfClient(n).ListHosts(ctx, &pb.ListHostsRequest{})
		if err != nil {
			t.Fatalf("ListHosts: %v", err)
		}
		for _, h := range resp.Hosts {
			if h.Name == host {
				return h.MemUsedMib
			}
		}
		t.Fatalf("host %q absent from ListHosts", host)
		return 0
	}

	before := memOf(n.Name)
	if err := corrosion.UpsertContainer(ctx, n.DB, corrosion.ContainerRecord{
		HostName: n.Name, Name: "ct-visible", State: "running", MemMiB: 2048,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	if got, want := memOf(n.Name), before+2048; got != want {
		t.Errorf("host memory reported as %d after a running 2048 MiB container, want %d — the listing disagrees with what admission charges",
			got, want)
	}

	// A STOPPED container holds nothing, so it must not inflate the display either.
	if err := corrosion.UpsertContainer(ctx, n.DB, corrosion.ContainerRecord{
		HostName: n.Name, Name: "ct-stopped", State: "stopped", MemMiB: 4096,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if got, want := memOf(n.Name), before+2048; got != want {
		t.Errorf("host memory reported as %d with a STOPPED container present, want %d unchanged", got, want)
	}
}

// TestFleet_Capacity_ConcurrentSameProjectAdmissions is the cross-node test the F2
// item names: two concurrent admissions for the SAME project, entering DIFFERENT
// nodes, where the project quota fits either one but not both.
//
// Before reserve-then-verify, both read a headroom view containing neither and both
// persisted — the cluster ends up over its own quota with neither request having
// done anything wrong. The fix reserves first, so the loser sees the winner's
// reservation and stands down; operation ids give a total order, so the winner is
// the same on every node rather than whoever happened to read last.
//
// This is a SMOKE test and is timing-dependent by nature: it demonstrated the race
// (a check-then-write mutation produced 2 winners) but once the window narrowed it
// stopped reliably distinguishing the two implementations. The ordering guarantee
// itself is pinned deterministically by TestAdmitWithReservation_* in
// internal/grpcapi, which plants a competing reservation with a known id instead of
// racing goroutines. Do not treat a green run here as proof the mechanism works.
func TestFleet_Capacity_ConcurrentSameProjectAdmissions(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, a.Name, 64, 65536, nil)
	setHostCapacity(t, c, b.Name, 64, 65536, nil)

	// Quota fits ONE 4 GiB VM, not two.
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{
		Name: "/tight", Display: "Tight",
	}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := c.SelfClient(a).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{ProjectName: "/tight", VcpuLimit: 8, MemMibLimit: 6144},
	}); err != nil {
		t.Fatalf("SetProjectQuota: %v", err)
	}

	// Fire both at once, each entering a different node and pinned to that node —
	// so neither is serialized behind the other by a shared host lock.
	type res struct {
		name string
		err  error
	}
	out := make(chan res, 2)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		node *Node
		name string
	}{{a, "first"}, {b, "second"}} {
		wg.Add(1)
		go func(n *Node, name string) {
			defer wg.Done()
			_, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
				Name: name, Cpu: 2, MemoryMib: 4096, Project: "/tight",
				Placement: &pb.PlacementSpec{Host: n.Name},
			}})
			out <- res{name, err}
		}(tc.node, tc.name)
	}
	wg.Wait()
	close(out)

	var okCount int
	for r := range out {
		if r.err == nil {
			okCount++
			continue
		}
		if status.Code(r.err) != codes.ResourceExhausted {
			t.Errorf("%s failed for an unexpected reason: %v", r.name, r.err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d of 2 concurrent same-project admissions succeeded, want exactly 1 — "+
			"two winners means the quota was breached; zero means the racers deadlocked each other", okCount)
	}

	// And the survivor is genuinely within quota.
	usage, err := c.SelfClient(a).GetProjectUsage(ctx, &pb.GetProjectUsageRequest{ProjectName: "/tight"})
	if err != nil {
		t.Fatalf("GetProjectUsage: %v", err)
	}
	if usage.MemMibUsed > 6144 {
		t.Errorf("project memory used = %d MiB, over the 6144 quota", usage.MemMibUsed)
	}
}
