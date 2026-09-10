// A witness contributes MEMBERSHIP and ROWS even though it never hosts a
// workload, and the sweeper's three host sets are three sets for that reason.
//
// What a participant OWES depends on what it HAS that the proof needs:
// knowledge of who exists (everyone has it), the replicated rows (everyone
// running the daemon has them, a witness included), or a running domain to scan
// (only a workload host has one). A witness has the first two and not the third.
//
// Every scenario here handed out or freed an address a live guest held, because
// one of those sets was read where another was meant:
//
//   - a host this node's `hosts` row still calls a witness, which has since been
//     made a worker and is running the domain. It was excluded from the fan-out
//     on that stale row, so the rule that a role counts only while every row
//     read agrees could never fire — the exclusion prevented the query that
//     would have refuted it.
//   - a genuine witness that is the only reachable node able to name the holder
//     at all. It runs the daemon, gossips and holds the replicated `hosts`
//     table, so it knows exactly what the proof was missing, and it was never
//     asked.
//   - the same witness, powered off and attested off by an operator. Being off
//     proves its libvirt is not running a domain; it proves nothing about the
//     hosts it alone knew existed, so the attestation must not excuse it from
//     the question.
//   - a witness holding the ONLY replicated copy of an incumbent's VM and NIC
//     rows, while the bind's inventory digest check asked the set that excuses
//     witnesses. The remaining nodes' equally short inventories agreed, and the
//     binding went live over an address a running guest held.
//
// Both directions run a real multi-node fleet: real gRPC, real host rows, real
// libvirt domains through libvirtfake. A single-package test cannot reach any of
// these shapes, because every one of them is about what ANOTHER node has.

package fleet

import (
	"context"
	"net"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetSweepDoesNotFreeAnAddressAStaleWitnessRoleHides.
//
// Every node starts out recording the holder as a witness. The operator then
// promotes it to worker, and that write lands on the holder while the sweeper's
// copy is still behind replication — the ordinary shape of a mutable role, since
// `lv host config --role` writes one replicated row.
//
// The holder is running a domain with the orphan's MAC, so the address is held.
// The sweeper must ASK it: a role reading is corroborated only by every row read
// agreeing, and the holder's own row is the one that says worker.
func TestFleetSweepDoesNotFreeAnAddressAStaleWitnessRoleHides(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, holder := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", holder.Name); err != nil {
			t.Fatal(err)
		}
	}
	// The promotion lands on the holder alone; the sweeper's row stays stale.
	if _, err := c.SelfClient(holder).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: holder.Name, Role: "worker",
	}); err != nil {
		t.Fatal(err)
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	holder.Rejoin()

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed address held by worker omitted on stale local witness role: %v",
			nb.Released())
	}
}

// TestFleetSweepDoesNotFreeAnAddressOnlyAWitnessCanName.
//
// The witness here is a genuine witness — every row in the cluster agrees — so
// it is rightly excused from producing a runtime scan. It is not excused from
// being asked what it knows, and in this topology it is the only node that can
// answer: the sweeper's own row for the holder is gone and its gossip names the
// witness alone, so nothing else in the sweeper's reach records the holder's
// existence.
func TestFleetSweepDoesNotFreeAnAddressOnlyAWitnessCanName(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	if err := sweeper.DB.Execute(ctx,
		"DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: witness.Name, Addr: net.JoinHostPort(witness.Address, "7946")}}
	})

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed address of holder known to reachable witness: %v", nb.Released())
	}
}

// TestFleetSweepDoesNotFreeAnAddressOnlyAFENCEDWitnessCanName is the scenario
// above with the witness POWERED OFF and attested off by an operator, and it is
// the one an earlier round of this got wrong on purpose.
//
// `lv host fence-confirm` was offered as the escape from a witness blocking the
// closure: attest the machine is off, and the sweep proceeds. But the witness
// here is the only node in the sweeper's reach that records the holder's
// existence at all — the sweeper's own row for the holder is gone and its gossip
// names the witness alone. Excusing the witness from being ASKED therefore frees
// the address of a host that is still running the domain.
//
// So power-off evidence excuses a host from the runtime SCAN and from nothing
// else. An unreachable or fenced host keeps the closure open, the sweep withholds
// for as long as that lasts, and the address leaks instead of colliding. That is
// the trade, chosen deliberately.
func TestFleetSweepDoesNotFreeAnAddressOnlyAFENCEDWitnessCanName(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	if err := sweeper.DB.Execute(ctx,
		"DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: witness.Name, Addr: net.JoinHostPort(witness.Address, "7946")}}
	})
	// The witness really is off, and the operator really has attested it. Both
	// halves of the strongest evidence available, and it still says nothing
	// about the holder.
	witness.Stop()
	mustFenceConfirm(t, sweeper, witness.Name)

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("confirming a witness is off freed an address held on another, still-running "+
			"host: %v", nb.Released())
	}
}

// TestFleetBindDoesNotHandOutAnAddressOnlyAWitnessHoldsTheRowsFor is the same
// three sets reached from the bind's side, and the round-five finding.
//
// The holder loses its workload rows while its QEMU survives — replication lag,
// a database loss, a row that never arrived — and the WITNESS is left holding the
// only replicated copy of the incumbent VM and of the NIC rows that record its
// address. Every remaining node's inventory is equally short, so they agree with
// each other perfectly.
//
// The bind's corroboration therefore has to ask the witness, and it did not: it
// read the sweeper's RUNTIME-PROOF set, which excuses witnesses because they have
// no domain to scan. A witness has no domain and every row. Asking the wrong set
// meant the binding went live having adopted nothing, and the next guest created
// was handed the incumbent's live address.
//
// Either safe outcome passes — a refused bind or a suspended one. What must not
// happen is a live binding that leases an address a running guest holds.
func TestFleetBindDoesNotHandOutAnAddressOnlyAWitnessHoldsTheRowsFor(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
	c := NewClusterWithNetBox(t, 3, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	binder, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
	witness.DB.MergeStateBytesLWW(pullDump(t, c, holder))
	// The holder loses its workload rows while QEMU survives. The witness
	// retains the only replicated copy of the VM and its address-bearing NIC
	// rows.
	for _, q := range []string{
		"DELETE FROM vm_nics WHERE vm_name = ?",
		"DELETE FROM vm_interfaces WHERE vm_name = ?",
		"DELETE FROM vms WHERE name = ?",
	} {
		if err := holder.DB.Execute(ctx, q, "incumbent"); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}

	assertBindHandsOutNoHeldAddress(t, c, binder)
}

// TestFleetBindGoesLiveWhenTheWitnessAgrees is the liveness half of putting
// witnesses in the inventory-corroboration set, and the reason that widening is
// affordable.
//
// A witness receives the replicated rows like any other node, so once the
// cluster has converged its digests AGREE and it corroborates instead of
// blocking. The binding here starts suspended for the ordinary reason — the
// binder had received nothing — and the revalidation pass then resumes it LIVE
// and adopts the address the incumbent holds, with nobody running a command.
// The witness is in the corroboration set, so the resume happens only because it
// answered and agreed — a witness that could not answer, or held different rows,
// would keep the binding suspended (the scenario above).
//
// Without this, the fix for the round-five finding could have been "ask the
// witness and wedge on it", which is indistinguishable from the bug for anyone
// running a witness.
func TestFleetBindGoesLiveWhenTheWitnessAgrees(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
	c := NewClusterWithNetBox(t, 3, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	binder, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}
	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
	want := vmNICIdentity(t, holder, "incumbent")

	mustCreateSuspendedBoundNetwork(t, c, binder)

	// The cluster converges, witness included: every node now holds the same
	// address-bearing rows.
	dump := pullDump(t, c, holder)
	binder.DB.MergeStateBytesLWW(dump)
	witness.DB.MergeStateBytesLWW(dump)

	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("a witness that holds the same rows must corroborate, not block: %q",
			b.SuspendReason)
	}
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != want {
		t.Fatalf("the resumed bind must adopt the address the incumbent holds, got %v want [%s]",
			ids, want)
	}
}
