// A node whose view of the cluster is SHORT, on the two paths that hand out and
// take back addresses.
//
// Both proofs in netbox_adopt.go / netbox_sweeper.go rest on a claim about the
// whole cluster — "nothing else holds an address in this prefix", "nothing
// anywhere still claims this address" — and both used to reach that claim from
// reads that cannot support it:
//
//   - the bind corroborated its VM inventory only when the local read came back
//     COMPLETELY EMPTY, so a node that knew one unrelated VM skipped the check
//     entirely and bound live having adopted nothing;
//   - the sweeper built its participant universe from the replicated `hosts`
//     table alone, so a peer whose row had not hydrated was absent from BOTH
//     samples of its five-step proof, the samples agreed, and the address was
//     freed. Two samples establish stability, not completeness.
//
// These need two nodes with genuinely divergent local databases, which is what
// this harness has and a single-package fixture does not.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetSweepDoesNotFreeAnAddressAHostMissingFromTheHostTableHolds.
//
// The peer holds the MAC on a defined domain and is perfectly present — the live
// peer signal still names it — but its `hosts` row has not hydrated on the node
// running the sweep. Read from that table alone the peer is invisible, both
// samples agree that it does not exist, and the proof frees an address a guest
// is using.
func TestFleetSweepDoesNotFreeAnAddressAHostMissingFromTheHostTableHolds(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	c.Nodes[1].Virt.DefineStoppedDomain("ghost", orphanMAC)
	c.Nodes[1].Rejoin() // even the live peer signal still knows this host

	// Model a host table that has not hydrated its peer's row yet.
	if err := c.Nodes[0].DB.Execute(context.Background(),
		`DELETE FROM hosts WHERE name = ?`, c.Nodes[1].Name); err != nil {
		t.Fatal(err)
	}

	if err := c.Nodes[0].Server.RunNetBoxMaintenanceOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(nb.Identities()) != 1 {
		t.Fatalf("sweeper released a live peer's address with a stable but incomplete host set: %v",
			nb.Released())
	}
}

// TestFleetSweepStopsWhenAPeerKnowsAHostThisNodeDoesNot is the second half of
// the sweeper fix, and the half the union cannot supply.
//
// Both nodes are present in each other's `hosts` table and both answer, so the
// participant set is stable, complete-looking and identical in both samples. It
// is still SHORT: the peer holds a `hosts` row for a third host this node has
// never received, and that host was therefore never asked. A host in neither the
// local table nor gossip is invisible to both, so the only thing that can reveal
// it is the peer's own rows — which the participant-set closure reads, by name.
//
// The third host has no daemon, so the closure adds "unseen" to the set and then
// cannot reach it. That is the fail-closed direction, and what this pins is that
// the address survives.
func TestFleetSweepStopsWhenAPeerKnowsAHostThisNodeDoesNot(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	// A host row that exists ONLY on the peer, exactly as replication lag
	// leaves one: the node running the sweep has never heard of it.
	if err := corrosion.InsertHost(context.Background(), c.Nodes[1].DB, corrosion.HostRecord{
		Name: "unseen", Address: "203.0.113.9", GRPCPort: 7443, SSHUser: "root", SSHPort: 22,
		State: "active", FenceStrategy: "best-effort", CPUTotal: 64, MemTotal: 262144,
	}); err != nil {
		t.Fatalf("insert a peer-only host row: %v", err)
	}

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a node whose host table is short of a peer's cannot have asked every host, "+
			"released %v", nb.Released())
	}
}

// TestFleetBindOnAPartiallyHydratedNodeDoesNotHandOutTheIncumbentsAddress.
//
// The binder is not empty — it holds a VM of its own on an unrelated network —
// so every check that keyed off an empty read is bypassed. What it has NOT
// received is the guest on the network being bound, sitting on the first address
// NetBox will offer.
//
// Either safe outcome passes: a refused bind, or a suspended one. What must not
// happen is a live binding that hands the incumbent's address to the next VM
// created there.
func TestFleetBindOnAPartiallyHydratedNodeDoesNotHandOutTheIncumbentsAddress(t *testing.T) {
	nb, c, holder, binder := unhydratedCluster(t)
	ctx := context.Background()

	// holder's world: the network, and a guest on the address the fake offers
	// first.
	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)

	// binder's world: one VM of its own, on a network that has nothing to do
	// with the prefix. Enough to make its `vms` read non-empty, and — with both
	// nodes holding exactly one row — enough to make the two tables the same
	// SIZE, which is why a row count alone cannot separate them.
	mustCreateUnboundNetwork(t, c, binder, "other-net", "10.90.0.0/24")
	mustCreateVMHoldingIP(t, c, binder, "unrelated", "other-net", "10.90.0.50")

	if _, err := createBoundNetwork(c, binder, adoptNetName, adoptSubnet, adoptPrefix); err != nil {
		t.Logf("bind refused safely: %v", err)
		return
	}
	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil && b.Suspended {
		return
	}

	_, err = c.SelfClient(binder).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "newcomer", Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: binder.Name},
		Network:   []*pb.NetworkAttachment{{Name: adoptNetName}},
	}})
	if err != nil {
		t.Fatalf("bind went live without adopting incumbent; create error: %v", err)
	}
	for _, addr := range nb.Addresses() {
		if addr == adoptFirstIP+"/24" {
			t.Fatalf("newcomer was allocated incumbent's live address %s; binder knew only an unrelated VM", addr)
		}
	}
}

// TestFleetAPartiallyHydratedBindIsSuspendedUnderTheSelfLiftingReason pins the
// MECHANISM the scenario above only pins the outcome of.
//
// Two things have to hold, and neither is implied by "no collision happened".
// The binding must exist and be SUSPENDED — a refusal would refuse the operator
// with nothing to do about it — and the reason must be the one class the
// revalidation pass lifts by itself, because a partially hydrated node has BOTH
// a list of candidates it can see and no standing to call that list complete,
// and writing the adoption reason over the uncorroborated one would leave the
// binding waiting for an operator who has nothing to repair.
func TestFleetAPartiallyHydratedBindIsSuspendedUnderTheSelfLiftingReason(t *testing.T) {
	_, c, holder, binder := unhydratedCluster(t)
	ctx := context.Background()

	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
	mustCreateUnboundNetwork(t, c, binder, "other-net", "10.90.0.0/24")
	mustCreateVMHoldingIP(t, c, binder, "unrelated", "other-net", "10.90.0.50")

	// The precondition that makes this the PARTIAL case rather than the empty
	// one: the binder's own read returns a VM, so nothing about it looks bare.
	vms, err := corrosion.ListVMs(ctx, binder.DB, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 {
		t.Fatalf("precondition: the binding node must hold exactly its own VM, got %d", len(vms))
	}

	if _, err := createBoundNetwork(c, binder, adoptNetName, adoptSubnet, adoptPrefix); err == nil {
		t.Fatal("a bind that could not corroborate its VM inventory must report the suspension")
	} else if !strings.Contains(err.Error(), "SUSPENDED") ||
		!strings.Contains(err.Error(), "could not corroborate") {
		t.Fatalf("the create must say the binding is suspended and why, got: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a bind on a node that could not corroborate its inventory must not go live")
	}
	if !strings.Contains(b.SuspendReason, "could not corroborate") {
		t.Fatalf("the reason must be the self-lifting one the revalidation pass recognises, got %q",
			b.SuspendReason)
	}

	// …and it converges, with nobody running a command: the rows arrive over the
	// production repair path and one pass adopts the address and resumes.
	//
	// BOTH directions, because that is what anti-entropy does and what
	// corroboration now asks for. Each node pulls from every peer, so the guest
	// this binder never received arrives here AND the binder's own guest — which
	// the holder has never received either — arrives there. A one-way pull
	// leaves the two `vms` tables still different, which is not a converged
	// cluster and must not corroborate as one: the earlier rule that read "the
	// peer holds fewer rows, so it is merely behind" is exactly the arithmetic
	// that handed an incumbent's address away.
	holderDump := pullDump(t, c, holder)
	binderDump := pullDump(t, c, binder)
	binder.DB.MergeStateBytesLWW(holderDump)
	holder.DB.MergeStateBytesLWW(binderDump)
	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}
	b, err = corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("the pass must resume the binding once the inventory arrived, reason: %q",
			b.SuspendReason)
	}
}
