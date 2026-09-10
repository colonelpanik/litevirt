// A bind made on a node that has NOT received the cluster's VM rows, and the
// revalidation pass that converges out of it.
//
// This is the one shape a single-package test cannot reach. The hazard is that
// `SELECT … FROM vms` answers the same "nothing here" for a cluster with no VMs
// and for a node whose replication has not caught up — and on the second, every
// address the cluster's guests hold inside the prefix is invisible to the bind
// that is about to make NetBox the authority over it. Reproducing that needs two
// nodes with genuinely divergent local databases and a REAL anti-entropy repair
// between them, which is what this harness has and a unit fixture does not.
//
// The scenario is the operator error it models: a two-node cluster where one
// node holds the guest, the other has not learned about it yet, and the bind is
// run on the second.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// unhydratedCluster is a TWO-node NetBox cluster with the prefix registered and
// netbox_ipam_v1 latched, returning (fake, cluster, holder, binder).
//
// Two nodes is the point: with one node there is no peer that could be holding
// rows this node has not received, so the empty read is its own corroboration
// and the bind is live immediately — which is what every other NetBox fleet
// scenario relies on and must keep relying on.
func unhydratedCluster(t *testing.T) (*NetBoxFake, *Cluster, *Node, *Node) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)

	c := NewClusterWithNetBox(t, 2, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	return nb, c, c.Nodes[0], c.Nodes[1]
}

// mustCreateSuspendedBoundNetwork binds the prefix on a node that cannot
// corroborate its VM inventory, and asserts the RPC SAYS SO.
//
// The create genuinely does not fully succeed — the network exists and serves no
// address claims — so it comes back as FailedPrecondition. That is the operator
// surface for this state: without it `lv network create` would print success
// over a network that refuses every VM, and the only other notice is a health
// condition a maintenance pass raises up to fifteen minutes later.
func mustCreateSuspendedBoundNetwork(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	_, err := createBoundNetwork(c, n, adoptNetName, adoptSubnet, adoptPrefix)
	if err == nil {
		t.Fatal("a bind that could not corroborate its VM inventory must report the suspension")
	}
	if !strings.Contains(err.Error(), "SUSPENDED") ||
		!strings.Contains(err.Error(), "could not corroborate") {
		t.Fatalf("the create must say the binding is suspended and why, got: %v", err)
	}
	// …and it must NOT tell the operator to repair a cause, because there is
	// none: the pass lifts this one on its own.
	if strings.Contains(err.Error(), "Repair the cause") {
		t.Fatalf("a self-lifting suspension must not be reported as a fault to repair, got: %v", err)
	}
}

// TestFleetBindOnAnUnhydratedNodeSuspendsThenConverges.
//
// holder creates the network and a guest holding the FIRST address the fake
// hands out. binder never learns about either — nothing is converged — and binds
// the prefix. That bind must not go live: it would make NetBox the authority
// over a range whose first address a running guest already holds, and the next
// VM created there would be handed it.
//
// Then the rows arrive, over the real StreamStateDump → MergeStateBytesLWW
// repair path, and one revalidation pass adopts the address and resumes the
// binding — with no operator action, which a refusal could never have done.
func TestFleetBindOnAnUnhydratedNodeSuspendsThenConverges(t *testing.T) {
	nb, c, holder, binder := unhydratedCluster(t)
	ctx := context.Background()

	// holder's world: the network, and a guest on the address the fake offers
	// first.
	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
	want := vmNICIdentity(t, holder, "incumbent")

	// binder's world: nothing. Pinned, because if the harness converged on its
	// own the whole scenario would be about a hydrated node.
	vms, err := corrosion.ListVMs(ctx, binder.DB, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 0 {
		t.Fatalf("precondition: the binding node must not have received the guest, got %d VMs", len(vms))
	}

	mustCreateSuspendedBoundNetwork(t, c, binder)

	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("the bind must record a binding row — it is not a refusal")
	}
	if !b.Suspended {
		t.Fatal("a bind on a node that could not corroborate its empty VM inventory must not go live")
	}
	if !strings.Contains(b.SuspendReason, "could not corroborate") {
		t.Fatalf("the reason must say what could not be established, got %q", b.SuspendReason)
	}
	// No allocation is served, which is the whole value of the suspension.
	if _, verr := c.SelfClient(binder).CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "newcomer", Cpu: 1, MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: binder.Name},
			Network:   []*pb.NetworkAttachment{{Name: adoptNetName}},
		},
	}); verr == nil {
		t.Fatal("a suspended binding must refuse a create on that network")
	}

	// THE ROWS ARRIVE, over the production repair path.
	binder.DB.MergeStateBytesLWW(pullDump(t, c, holder))

	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}

	// The address the bind could not see is now an ip_address object carrying
	// that NIC's identity.
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("NetBox holds %v, want exactly [%s/24] — the pass must adopt what arrived",
			got, adoptFirstIP)
	}
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != want {
		t.Fatalf("adopted identity = %v, want [%s]", ids, want)
	}
	if lease := leaseFor(t, binder, adoptNetName, adoptFirstIP); lease == nil ||
		lease.NetBoxIPID == 0 || lease.NetBoxPrefix != adoptPrefix {
		t.Fatalf("the adopted address must be leased locally against this prefix, got %+v", lease)
	}

	// …and the binding is live again, with nobody having run a command.
	b, err = corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("the pass must resume the binding once it adopted everything, reason: %q",
			b.SuspendReason)
	}
}

// TestFleetUnhydratedBindTouchesNoAddressSurface is the cost control.
//
// The suspension exists because the bind cannot enumerate; it must not react by
// enumerating the prefix in NetBox instead. A bind that reached the address
// surface here would put a whole-prefix walk on the one path that has no
// standing to make it.
func TestFleetUnhydratedBindTouchesNoAddressSurface(t *testing.T) {
	nb, c, holder, binder := unhydratedCluster(t)

	// The precondition for the suspension at all: a guest exists on a node the
	// binder has not heard from.
	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)

	mustCreateSuspendedBoundNetwork(t, c, binder)

	if got := nb.AddressRequests(); got != 0 {
		t.Fatalf("a bind over an uncorroborated empty read made %d ipam address requests, want 0", got)
	}
}
