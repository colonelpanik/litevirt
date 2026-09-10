// Fleet scenarios for the two fail-closed paths that surround a NetBox claim:
// the VM row that MUST persist once an address has been claimed, and the
// per-lease release that runs when the VM goes away.
//
// Both properties are about a window, not a value, so they need the failure to
// happen INSIDE the daemon's own transaction with every earlier step really
// having run — which is what the cluster.go trigger seams provide. The one
// scenario that needs no seam at all (two NICs on one network) is the natural
// repro: vm_interfaces is keyed (vm_name, network_name), so the second NIC's
// row collides and the create's persistence fails on its own.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// createVMWithNICs creates a VM pinned to n with one NIC per entry in nets,
// returning the RPC error unchanged.
//
// Placement is pinned for the same reason as createVMOnNetwork: a scenario that
// means "this node aborts" must actually run on this node.
func createVMWithNICs(c *Cluster, n *Node, name string, nets ...string) (*pb.VM, error) {
	atts := make([]*pb.NetworkAttachment, 0, len(nets))
	for _, netName := range nets {
		atts = append(atts, &pb.NetworkAttachment{Name: netName})
	}
	return c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      name,
			Cpu:       1,
			MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: n.Name},
			Network:   atts,
		},
	})
}

// deleteVM runs a delete on n and returns the RPC error unchanged.
func deleteVM(c *Cluster, n *Node, name string) error {
	_, err := c.SelfClient(n).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: name})
	return err
}

// TestCreateAbortsWhenRowPersistFailsAfterClaim covers the sequence that would
// otherwise let the sweeper release a LIVE guest's address: the claim succeeds,
// the domain starts, the VM row fails to persist, the VM keeps running, and the
// sweeper later sees a tagged NetBox address with no matching VM anywhere in
// the cluster — which is exactly the proof it reclaims on.
//
// The create must abort instead: tear the domain down, and give the address
// back to NetBox while the local lease is still there to prove ownership.
func TestCreateAbortsWhenRowPersistFailsAfterClaim(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)
	n.FailVMRowWrites(t)

	if _, err := createVMOnNetwork(c, n, "vm-1", "bound"); err == nil {
		t.Fatal("create must abort when the VM row cannot be persisted after a claim")
	}
	if n.Virt.DomainExists("vm-1") {
		t.Fatal("the domain must be torn down, not left running without a row")
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("the NetBox address must be released, still held: %v", ids)
	}
	if got := leaseCount(t, n, "bound"); got != 0 {
		t.Fatalf("the local lease must be tombstoned too, %d still live", got)
	}
}

// TestUnboundCreateKeepsLogAndContinue is the behaviour-preservation guard for
// every deployment that has no external IPAM at all.
//
// With no claim in play there is nothing a stranded row can leak, so the
// pre-existing handling stands unchanged: the persistence error is LOGGED and
// the running domain is left alone. The RPC still fails — it ends with a
// read-back of the row that was never written — but that is today's behaviour
// and it is emphatically not the abort: nothing is torn down.
//
// Asserting on the surviving domain rather than on the error is what makes this
// non-vacuous. Both the old path and a wrongly-broadened abort return an error
// here; only one of them leaves the VM running.
func TestUnboundCreateKeepsLogAndContinue(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	// CreateVM preflights the resolved bridge with `ip link add`, EPERM for an
	// unprivileged test process. Stub the seam only.
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)

	n.FailVMRowWrites(t)

	_, err := createVMOnNetwork(c, n, "vm-1", ctNetName)
	if err != nil && strings.Contains(err.Error(), "persist VM state") {
		t.Fatalf("an unbound create must not take the claim-abort path, got %v", err)
	}
	if !n.Virt.DomainExists("vm-1") {
		t.Fatal("an unbound create must keep today's log-and-continue behaviour: the domain stays running")
	}
}

// TestNetBoxDeleteSkippedWhenTombstoneFails pins the release ORDER.
//
// Freeing the address in NetBox while litevirt still holds the lease lets
// another system take an address litevirt believes is its own. The reverse
// order only ever leaks an address the orphan sweep can reclaim, so the local
// tombstone is mandatory and the remote delete is gated on it.
func TestNetBoxDeleteSkippedWhenTombstoneFails(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)
	mustCreateVMOnNetwork(t, c, n, "vm-1", "bound")

	n.FailLeaseTombstones(t)

	// The error must be SURFACED, not swallowed — discarding it here would make
	// this test unable to enforce the requirement it claims to check, and would
	// leave the operator believing an address was returned when it was not.
	if err := deleteVM(c, n, "vm-1"); err == nil {
		t.Fatal("a failed lease release must surface as a delete error")
	}
	if ids := nb.Identities(); len(ids) != 1 {
		t.Fatalf("NetBox delete must not run when the local tombstone failed, identities = %v", ids)
	}
}

// TestEveryNICLeaseIsReleasedOnDelete pins that the delete iterates EVERY NIC.
//
// A loop that stopped after the first NIC would leave the second address held
// in NetBox forever — invisible locally, because the VM row is gone, and
// unreclaimable by the sweeper, because the identity still resolves.
//
// Two networks rather than two NICs on one: vm_interfaces is keyed
// (vm_name, network_name), so a VM with two NICs on ONE network cannot persist
// at all today (see TestTwoNICsOnOneNetworkAbortsAndReleasesBoth, which pins
// what happens instead). The per-NIC detach variant belongs with NIC hotplug.
func TestEveryNICLeaseIsReleasedOnDelete(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)
	nb.AddPrefix(8, "10.0.6.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound-a", "10.0.5.0/24", 7)
	mustCreateBoundNetwork(t, c, n, "bound-b", "10.0.6.0/24", 8)

	if _, err := createVMWithNICs(c, n, "vm-1", "bound-a", "bound-b"); err != nil {
		t.Fatalf("CreateVM with two bound NICs: %v", err)
	}
	if got := len(nb.Identities()); got != 2 {
		t.Fatalf("want two claims before the delete, got %d — the assertions below would be vacuous", got)
	}

	if err := deleteVM(c, n, "vm-1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	for _, netName := range []string{"bound-a", "bound-b"} {
		if got := leaseCount(t, n, netName); got != 0 {
			t.Fatalf("%s: %d lease(s) survived the delete", netName, got)
		}
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("every NIC's address must be returned to NetBox, still held: %v", ids)
	}
}

// TestTwoNICsOnOneNetworkAbortsAndReleasesBoth is the same window as
// TestCreateAbortsWhenRowPersistFailsAfterClaim reached with NO test seam at
// all, which is what makes it worth keeping separately: vm_interfaces is keyed
// (vm_name, network_name), so the second NIC's row collides and the whole
// persistence batch fails — after both addresses have been claimed and the
// domain is running.
//
// Before this change that create returned an error while leaving a running,
// row-less VM holding two NetBox addresses: the precise state the sweeper would
// later reclaim out from under a live guest.
func TestTwoNICsOnOneNetworkAbortsAndReleasesBoth(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)

	if _, err := createVMWithNICs(c, n, "vm-1", "bound", "bound"); err == nil {
		t.Fatal("two NICs on one network cannot persist — the create must fail")
	}
	if n.Virt.DomainExists("vm-1") {
		t.Fatal("the domain must be torn down, not left running without a row")
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("both claims must be released, still held: %v", ids)
	}
	if got := leaseCount(t, n, "bound"); got != 0 {
		t.Fatalf("both local leases must be tombstoned, %d still live", got)
	}
}

// TestDeleteVMTombstonesLeaseWhenBindingSuspended pins that an UNUSABLE binding
// cannot strand the address it leased.
//
// A suspended binding (or a def naming a prefix no binding row backs) makes
// allocatorFor fail, and the release loop cannot go through the allocator. The
// old handling warned and moved on, which tombstoned the vms row while leaving
// the ip_allocations row LIVE under an owner that no longer exists — and that
// burns the address in BOTH systems at once: the orphan sweep must never touch
// a live lease, and the guarded upsert refuses to reuse a live row even after
// an operator frees the address in NetBox by hand. Nothing surfaced it.
//
// The delete must still succeed (a suspended binding is not a reason a VM
// becomes undeletable) while doing both halves it still can: tombstone the
// local lease directly, and hand the now-unreferenced remote object to the
// sweeper, whose unreferenced-object case is exactly right for it.
//
// The three assertions are one property each, and the last two are what make it
// non-vacuous: without the queue item the NetBox object is simply abandoned,
// and without the surviving identity the test would pass against a release that
// wrongly went through NetBox with a suspended binding.
func TestDeleteVMTombstonesLeaseWhenBindingSuspended(t *testing.T) {
	ctx := context.Background()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)
	mustCreateVMOnNetwork(t, c, n, "vm-1", "bound")

	// The claim has to have really happened, or every assertion below passes for
	// the wrong reason.
	if got := leaseCount(t, n, "bound"); got != 1 {
		t.Fatalf("want one live lease before the delete, got %d", got)
	}
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want one NetBox identity before the delete, got %v", ids)
	}

	if err := corrosion.SuspendBinding(ctx, n.DB, 7, "test"); err != nil {
		t.Fatalf("SuspendBinding: %v", err)
	}

	if err := deleteVM(c, n, "vm-1"); err != nil {
		t.Fatalf("a suspended binding must not make the VM undeletable: %v", err)
	}
	if got := leaseCount(t, n, "bound"); got != 0 {
		t.Fatalf("the local lease must be tombstoned anyway, %d still live", got)
	}
	// The REMOTE half is deliberately deferred: releasing through a suspended
	// binding is what the suspension exists to prevent.
	if got := nb.Identities(); len(got) != 1 {
		t.Fatalf("the NetBox object must be left for the sweeper, identities = %v", got)
	}

	items, err := corrosion.DrainSyncQueue(ctx, n.DB, "orphan", 10)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	var found bool
	for _, it := range items {
		if it.Kind == "orphan" && it.Op == "check" && it.Key == ids[0] {
			found = true
		}
	}
	if !found {
		t.Fatalf("the deferred NetBox object must be queued as an orphan check for %q, queue = %+v", ids[0], items)
	}
}
