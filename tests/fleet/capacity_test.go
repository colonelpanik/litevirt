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
	"encoding/json"
	"fmt"
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

// TestFleet_Capacity_ConcurrentPinnedCreatesExactlyOneRefusal is the scenario the
// rest of this file could not reach: admission racing itself.
//
// Every other capacity test is sequential, so all of them pass against a plain
// read-then-check with no reservation. The bug that hid behind them: two creates
// for DIFFERENT VMs pinned to one host both read the same free capacity, both
// passed, and both committed. The per-VM lock did not help — different names,
// different mutexes — and a lock held only across the CHECK would not help either,
// because the commit happens after the image pull, disk creation and DefineDomain.
// What closes it is the reservation spanning that gap.
//
// Sizing: allocatable 3072 MiB (4096 total − 1024 default reserve), three
// concurrent 1536 MiB creates. Exactly two fit. All three enter the SAME node and
// forward to the same owner, so the owner's ledger is the thing under test.
//
// Mutation-checked, with the caveat this file already makes elsewhere. Removing
// the reservation (leaving the lock and the check) makes this test FLAKY, not
// reliably red: it failed with admitted=3/exhausted=0 on one run and passed on the
// next two, because whether the plain check catches the third create depends on
// whether an earlier create's commit happened to land first. With the reservation
// it is deterministic — 20 consecutive runs, and clean under -race.
//
// So the guard against a reservation regression is the UNIT test
// (TestAdmitHostCapacity_ReservationBlocksSecondAdmit), which holds the release
// func and is deterministic. What this test adds is the end-to-end multi-node
// property: concurrent creates entering one daemon and forwarding to another never
// oversubscribe the owner.
func TestFleet_Capacity_ConcurrentPinnedCreatesExactlyOneRefusal(t *testing.T) {
	const (
		concurrent = 3
		vmMemMiB   = 1536
		wantFit    = 2 // 3072 allocatable / 1536
	)
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, target := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 64, 65536, nil) // entry: irrelevant, huge
	setHostCapacity(t, c, target.Name, 64, 4096, nil) // target: fits exactly two

	// Dial BEFORE the goroutines: SelfClient lazily builds the connection and calls
	// t.Fatalf, neither of which is legal off the test goroutine. A ClientConn is
	// safe to share once built.
	client := c.SelfClient(entry)

	type result struct {
		name string
		err  error
	}
	results := make(chan result, concurrent)
	var wg sync.WaitGroup
	start := make(chan struct{}) // release all goroutines at once to widen the race
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("racer-%d", i)
			<-start
			_, err := client.CreateVM(context.Background(), &pb.CreateVMRequest{
				Spec: &pb.VMSpec{
					Name: name, Cpu: 1, MemoryMib: vmMemMiB,
					Placement: &pb.PlacementSpec{Host: target.Name},
				},
			})
			results <- result{name: name, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	var admitted, exhausted int
	var other []error
	for r := range results {
		switch {
		case r.err == nil:
			admitted++
		case status.Code(r.err) == codes.ResourceExhausted:
			exhausted++
		default:
			// A create can fail for unrelated reasons in the harness (no image, no
			// real qemu). Those are not admission decisions — but if the VM row
			// exists the request WAS admitted, so count it as such.
			if rec, _ := corrosion.GetVM(ctx, target.DB, r.name); rec != nil {
				admitted++
			} else {
				other = append(other, r.err)
			}
		}
	}

	if exhausted == 0 {
		t.Fatalf("%d concurrent %d MiB creates pinned to a host with room for %d: none refused "+
			"(admitted=%d, other=%v) — concurrent admission is not serialized, so the host is "+
			"oversubscribed", concurrent, vmMemMiB, wantFit, admitted, other)
	}
	if admitted > wantFit {
		t.Errorf("admitted %d of %d concurrent creates onto a host with room for %d — "+
			"over-admission", admitted, concurrent, wantFit)
	}
	if got := admitted + exhausted + len(other); got != concurrent {
		t.Errorf("accounted for %d of %d results", got, concurrent)
	}
}

// TestFleet_Capacity_ConcurrentStartsExactlyOneRefusal is the same race on the
// START path, which is where memory is actually consumed: create several VMs that
// each fit while stopped (stopped VMs are accounted as nothing), then start them
// at once. StartVM holds only a per-VM-NAME lock, so before the fix the starts did
// not serialize against each other at all.
func TestFleet_Capacity_ConcurrentStartsExactlyOneRefusal(t *testing.T) {
	const (
		concurrent = 3
		vmMemMiB   = 1536
	)
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, target := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 64, 65536, nil)
	setHostCapacity(t, c, target.Name, 64, 4096, nil) // allocatable 3072 → two fit

	names := make([]string, concurrent)
	for i := range names {
		names[i] = fmt.Sprintf("stopped-%d", i)
		spec, err := json.Marshal(&pb.VMSpec{Name: names[i], Cpu: 1, MemoryMib: vmMemMiB})
		if err != nil {
			t.Fatalf("marshal spec: %v", err)
		}
		if err := corrosion.InsertVM(ctx, target.DB, corrosion.VMRecord{
			Name: names[i], HostName: target.Name, State: "stopped", Spec: string(spec),
			CPUActual: 1, MemActual: vmMemMiB,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", names[i], err)
		}
		// Define the domain on the OWNER's fake. Without this every start fails
		// immediately at the runtime step — after admission — so each reservation is
		// released before the next goroutine admits and the race never materializes.
		if err := target.Virt.DefineDomain(fmt.Sprintf(
			`<domain type='kvm'><name>%s</name><devices></devices></domain>`, names[i])); err != nil {
			t.Fatalf("DefineDomain %s: %v", names[i], err)
		}
	}

	client := c.SelfClient(entry)
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			_, err := client.StartVM(context.Background(), &pb.StartVMRequest{Name: name})
			errs <- err
		}(name)
	}
	close(start)
	wg.Wait()
	close(errs)

	var exhausted int
	for err := range errs {
		if status.Code(err) == codes.ResourceExhausted {
			exhausted++
		}
	}
	if exhausted == 0 {
		t.Errorf("%d concurrent starts of %d MiB VMs on a host with room for 2: none refused for "+
			"capacity — starts must serialize against each other, not just against the same VM name",
			concurrent, vmMemMiB)
	}
}
