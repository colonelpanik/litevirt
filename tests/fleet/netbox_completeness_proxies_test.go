// The three CHEAP PROXIES for completeness that this feature shipped, one per
// review round, and the collisions each of them let through.
//
// All three proofs in netbox_adopt.go / netbox_sweeper.go rest on a claim about
// the whole cluster — "nothing else holds an address in this prefix", "nothing
// anywhere still claims this address". Three times running, that claim was
// reached from something cheaper to compare than the property it stands for:
//
//   - a ROW COUNT relationship, where a peer holding fewer rows was read as a
//     peer that is merely behind. Fewer rows do not make a subset;
//   - ONE TABLE standing in for four, where identical `vms` tables corroborated
//     while the NIC rows that actually carry the addresses were missing;
//   - EQUAL CARDINALITY standing in for the same members, where a host set of
//     the same size but different membership compared as agreement.
//
// Each scenario below is the smallest arithmetic that separates the proxy from
// the property, so a proof that goes back to any of them fails here. They need
// two or three nodes with genuinely divergent local databases and real gRPC
// between them, which is what this harness has and a single-package fixture does
// not.

package fleet

import (
	"context"
	"net"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// assertBindHandsOutNoHeldAddress is the outcome every bind scenario here
// shares: whatever the binding node decides, the incumbent's live address must
// not end up leased to a newcomer.
//
// Three outcomes are safe and all three are accepted — a refused bind, a
// suspended binding, or a live binding that adopted the incumbent first — because
// what is under test is the collision, not which of the safe paths the node
// takes. The one thing that fails is a newcomer holding the address a running
// guest already has.
func assertBindHandsOutNoHeldAddress(t *testing.T, c *Cluster, binder *Node) {
	t.Helper()
	ctx := context.Background()
	if _, err := createBoundNetwork(c, binder, adoptNetName, adoptSubnet, adoptPrefix); err != nil {
		t.Logf("bind refused safely: %v", err)
		return
	}
	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil && b.Suspended {
		return // suspended: serves no claim, and the revalidation pass finishes it
	}
	if _, err := c.SelfClient(binder).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "newcomer", Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: binder.Name},
		Network:   []*pb.NetworkAttachment{{Name: adoptNetName}},
	}}); err != nil {
		t.Fatalf("the binding went live, so a create on it must succeed: %v", err)
	}
	leases, err := corrosion.ListLeasesByNetwork(ctx, binder.DB, adoptNetName)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leases {
		if l.VMName == "newcomer" && l.IP == adoptFirstIP {
			t.Fatalf("newcomer was allocated the incumbent's live address: %+v", l)
		}
	}
}

// TestFleetABinderHoldingMORERowsThanAPeerIsStillNotComplete.
//
// The binder holds TWO VMs, both on a network that has nothing to do with the
// prefix. The peer holds ONE — the incumbent, sitting on the first address the
// prefix will offer. So the peer is strictly behind on row count, and the
// relaxation that read "a peer with fewer rows cannot be why my list is short"
// corroborated the binder's inventory and bound live having adopted nothing.
//
// The arithmetic is the whole point: 1 < 2, and the one row is exactly the row
// the binder does not have. No relation between two cardinalities means "nothing
// you hold is missing here" — only agreement does.
func TestFleetABinderHoldingMORERowsThanAPeerIsStillNotComplete(t *testing.T) {
	_, c, holder, binder := unhydratedCluster(t)

	// The holder's world: the network, and the incumbent on the first address
	// the fake hands out.
	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)

	// The binder's world: two guests of its own, neither on the network being
	// bound. Two, so its `vms` table is strictly LARGER than the holder's and
	// the comparison cannot be dismissed as "the same size, different rows".
	mustCreateUnboundNetwork(t, c, binder, "other-net", "10.90.0.0/24")
	mustCreateVMHoldingIP(t, c, binder, "unrelated-1", "other-net", "10.90.0.50")
	mustCreateVMHoldingIP(t, c, binder, "unrelated-2", "other-net", "10.90.0.51")

	assertBindHandsOutNoHeldAddress(t, c, binder)
}

// TestFleetMatchingVMTablesWithTheIncumbentsNICRowsMissing.
//
// The addresses do not live in `vms`. They live on the NIC rows — vm_nics and
// vm_interfaces, written from an explicit address on the attachment or
// discovered from DHCP — so a corroboration that covered `vms` alone compared
// the one table that carries no addresses at all.
//
// This is that state exactly: the binder receives the holder's whole dump, so
// the two `vms` tables are identical and agree on count AND content hash, and
// then the incumbent's rows are deleted from both NIC tables here. Adoption
// enumerates the VM, finds it has no NIC on the network, adopts nothing, and the
// binding goes live over an address a running guest holds.
func TestFleetMatchingVMTablesWithTheIncumbentsNICRowsMissing(t *testing.T) {
	_, c, holder, binder := unhydratedCluster(t)
	ctx := context.Background()

	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)

	// Everything arrives over the production repair path, so `vms` is genuinely
	// identical on both nodes rather than merely the same size.
	binder.DB.MergeStateBytesLWW(pullDump(t, c, holder))

	// …and then exactly the rows that carry the address are gone from here. Both
	// tables, because either one alone would still name it: the v42 hardware
	// model dual-writes them.
	for _, q := range []string{
		"DELETE FROM vm_nics WHERE vm_name = ?",
		"DELETE FROM vm_interfaces WHERE vm_name = ?",
	} {
		if err := binder.DB.Execute(ctx, q, "incumbent"); err != nil {
			t.Fatal(err)
		}
	}
	// The network record too, so the binder can create it BOUND — the operator
	// action the whole feature is about.
	if err := binder.DB.Execute(ctx, "DELETE FROM networks WHERE name = ?", adoptNetName); err != nil {
		t.Fatal(err)
	}

	assertBindHandsOutNoHeldAddress(t, c, binder)
}

// TestFleetSweepStopsOnEqualHostCountsOverDifferentMembers.
//
// The membership corroboration compared `hosts` ROW COUNTS, so two nodes that
// each knew three hosts corroborated each other — even when they were not the
// same three.
//
// Here the sweeper has lost the holder's row from both of its local sources (the
// table and gossip) and gained a witness only it knows about, which keeps the
// counts equal. Its reachable peer knows the holder perfectly well. The holder
// has the address on a defined domain, so a proof that asked it would stop; a
// proof that never learns the holder exists asks two hosts, both answer "not
// me", and the address a live guest holds is deleted.
//
// The fix is not a stricter comparison of this node's set but a different
// question, asked of the peer: WHICH hosts do you know? The holder is then
// queried by name, whether or not this node's `hosts` table ever hydrated it.
func TestFleetSweepStopsOnEqualHostCountsOverDifferentMembers(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, peer, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	// The holder genuinely holds it, and is genuinely up: the live peer signal
	// names it, so no fence attestation can excuse asking.
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	holder.Rejoin()

	// The sweeper has not learned the holder via EITHER local source — the row
	// is gone from its table, and gossip does not name it.
	if err := sweeper.DB.Execute(ctx, "DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: peer.Name, Addr: net.JoinHostPort(peer.Address, "7946")}}
	})
	// …and a witness only this node knows about restores the row count, so the
	// two `hosts` tables are the same SIZE over different members — which is what
	// makes the sets differ in membership while agreeing in cardinality.
	//
	// Its role is `witness` only to keep it out of the RUNTIME scan. Rounds four
	// and five removed the exclusion that skipped a witness from the membership
	// fan-out, so it is asked what it knows like any other host; having no
	// daemon it cannot answer, which leaves the closure open. That is the
	// fail-closed direction and not what this scenario is about — the row-count
	// arithmetic is.
	if err := corrosion.InsertHost(ctx, sweeper.DB, corrosion.HostRecord{
		Name: "local-only-witness", Address: "203.0.113.8", GRPCPort: 7443, Role: "witness",
		SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("the sweeper freed a live holder's address over a host set that only MATCHED "+
			"IN SIZE, while its reachable peer knew the missing member: released %v", nb.Released())
	}
}
