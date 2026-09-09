package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/netbox"
)

// The pass's conclusions and the proof of them have to be about ONE read.
//
// A sweep reads its desired state and its removal evidence, diffs both against
// NetBox, and only then discovers that a removal rests on a mapping row alone —
// the record that names an incarnation without saying whether it stopped
// existing. The corroboration used to be a predicate that sampled its own
// digests when asked, so it answered about the inventory as it stood at the END
// of the pass: a row arriving mid-pass made the proof succeed about a read the
// plan had never seen, and a live VM's NetBox object was deleted on it.
//
// The sample is therefore taken BEFORE anything is read and the proof is bound
// to it. This package owns the ORDER; the proof's own binding check lives with
// the digest machinery (internal/grpcapi), and neither half is enough alone.

// TestTheInventoryIsSampledBeforeThePassReadsIt is that order, asserted through
// the consequence rather than by inspection.
//
// The sampler seeds a live `vms` row for the incarnation NetBox holds an object
// for. Sampled BEFORE the desired read, as production does it, that row is IN
// the desired state: the object is reconciled, no removal is planned, nothing
// has to be proven, and the pass CONVERGES.
//
// Sampled after that read, the same pass plans a delete for an incarnation whose
// row it holds. What that costs is asserted here as the missing convergence
// stamp, and the reason it is not asserted as a deleted object is worth being
// explicit about: the evidence read runs later still, sees the same live row and
// withholds the delete on its own. The damage of a late sample is therefore not
// visible as damage at that distance — a pass that plans removals its own
// database contradicts stops converging, which is the observable end of it, and
// the deletion itself is reachable only when the sample lands after the evidence
// read too. That is the fleet regression
// (TestIndependentCorroborationMustCoverTheDeletionSnapshot) and the proof's own
// binding check.
//
// The corroboration must not be REACHED at all here, and that is asserted too:
// this scenario passing because a gate withheld something would say nothing
// about the ordering.
func TestTheInventoryIsSampledBeforeThePassReadsIt(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	// One object, so nothing else in the pass has anything to withhold: NetBox
	// holds vm-1 under uuid-1 and the interface beneath it, which the object's
	// own cascade owns.
	nb.listVMs = nb.listVMs[:1]
	nb.listIfaces = nb.listIfaces[:1]
	// THE ONE RECORD THIS NODE HOLDS of uuid-1: the mapping row its own mirror
	// wrote. No `vms` row of any kind carries uuid-1 when the pass begins.
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-1", ""), 11)

	proof := &fixedProof{ok: true}
	var sampled int
	r.inventorySnapshot = func(context.Context) InventoryProof {
		sampled++
		// REPLICATION COMPLETING, at the moment the sample is taken. Everything
		// the pass reads afterwards sees this row; everything it read before
		// would not have.
		seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
		return proof
	}

	err := r.SyncOnce(context.Background())

	if sampled != 1 {
		t.Fatalf("the inventory was sampled %d time(s) in one pass, want exactly 1: two "+
			"samples are two bindings, and the conclusions can only be about one of them", sampled)
	}
	if vms, ifaces := deletes(nb); len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("the pass deleted VMs %v and interfaces %v for an incarnation whose live row "+
			"it held before it read anything: the sample was taken after the reads, so the "+
			"plan came from an inventory the proof never certified; sweep error=%v",
			vms, ifaces, err)
	}
	if got := mirrorSink(t, r).sweeps(); got[sweepOK] != 1 || got[sweepError] != 0 {
		t.Fatalf("sweeps = %v, want one converged pass: the row was in this node's database "+
			"before the pass began, so a pass that samples before it reads finds it in its "+
			"desired state and plans no removal at all. A pass that planned one — and had it "+
			"withheld by the evidence read that comes later — read its state before it "+
			"sampled; sweep error=%v", got, err)
	}
	if proof.asked != 0 {
		t.Fatal("the pass asked the cluster about an absence it should never have concluded: " +
			"with the row read into desired state there is no removal to prove, and a " +
			"scenario that passes through the corroboration is testing that gate instead of " +
			"the ordering")
	}
}

// TestAPassWithNoProofWithholdsAMappingOnlyRemoval is the fail-closed direction
// of the sampler itself.
//
// A sampler that could not read its own digests returns no proof, and the pass
// must then withhold exactly what an unwired corroboration withholds. Without
// this, a sampling failure would be indistinguishable from a corroborated read
// at the one gate that matters.
//
// The fixture holds a LIVE guest of its own, which is not decoration: with the
// desired read empty the whole-pass gate refuses every delete before the
// evidence is ever classified, so this scenario withheld its removal without
// reaching the proof at all — it passed with the nil handling deleted. The
// positive control at the bottom is what says so out loud, and what keeps it
// saying so: same fixture, same pass, a proof that AGREES, and the removal has
// to go.
func TestAPassWithNoProofWithholdsAMappingOnlyRemoval(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	// ONE object and NO interface under it: an interface the local database has
	// no NIC row for emits a nic/delete of its own, and a withheld child
	// withholds every destructive action in the pass — which is another gate
	// answering for this one.
	nb.listVMs = nb.listVMs[:1]
	nb.listIfaces = nil
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-1", ""), 11)
	seedHydratedVM(t, r, "vm-3", "uuid-3", macH3)
	r.inventorySnapshot = func(context.Context) InventoryProof { return nil }

	err := r.SyncOnce(context.Background())

	if vms, ifaces := deletes(nb); len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a pass whose inventory could not be sampled deleted VMs %v and interfaces "+
			"%v on a mapping row alone; sweep error=%v", vms, ifaces, err)
	}

	// THE POSITIVE CONTROL: the one thing that has to differ is the answer.
	withCorroboratedInventory(r)
	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the corroborated pass must run: %v", err)
	}
	if vms, _ := deletes(nb); len(vms) != 1 || vms[0] != 11 {
		t.Fatalf("deleted VMs = %v, want the mapping-only removal a corroborated inventory "+
			"authorizes: with this pass withholding it too, the assertion above is satisfied "+
			"by some other gate and says nothing about the missing proof", vms)
	}
}

// TestARowThatArrivedBeforeTheSampleStillProvesAMappingOnlyRemoval is the
// LIVENESS direction of the same ordering, and the one a safety-only reading of
// this binding gets wrong.
//
// A relevant row landing AFTER the sample discards this pass's removals, which
// is what the binding is for. The write that lands BEFORE it is the same write
// one moment earlier, and it must cost nothing at all: it is inside the sample,
// so the plan and the proof are about one read, they agree about that row, and
// every removal this pass can otherwise justify has to go through. An
// implementation that sampled too late, or compared its sample against some
// earlier baseline, would withhold on every early arrival instead — a mirror
// that stops converging on a cluster with any inventory churn, which reads as
// safety and is a stall.
//
// So the row arrives at the sample, and the pass still has a removal that NEEDS
// the cluster: uuid-2's object, whose only local record is the mapping row the
// mirror's own create wrote. The proof is asked, it agrees, and the object goes
// — asserted on the delete AND on the convergence stamp, because "did not error"
// is also what a pass that withheld everything returns.
//
// The ordering is what this pins, and it pins it from the direction the
// scenarios above cannot: move the sample below the reads and the arrival is
// outside the desired state instead of inside it, the pass plans a delete for
// the incarnation whose live row it holds, the evidence read withholds it, and
// this pass stops converging. The digest half of the sample is notional here (a
// fixed proof answers for it, as every scenario in this package does); what
// lives here is the ORDER, and the digests are pinned in internal/grpcapi and
// tests/fleet.
func TestARowThatArrivedBeforeTheSampleStillProvesAMappingOnlyRemoval(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	// TWO objects, and an interface under only the FIRST: vm-1 under uuid-1,
	// whose live row arrives at the sample, and vm-2 under uuid-2, the removal
	// that needs the cluster. An interface beneath the doomed object would emit
	// a nic/delete of its own, and a withheld child withholds every destructive
	// action in the pass — so the removal asserted below would be decided by a
	// bystander rather than by the proof.
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:1]
	// THE ONLY RECORD THIS NODE HOLDS OF uuid-2: the mapping row its own mirror
	// wrote when it created object 12. No `vms` row, tombstone included, carries
	// uuid-2 — which is exactly the removal a mapping row cannot justify alone
	// and the corroboration exists to authorize.
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-2", ""), 12)
	// A guest this node already held, so the desired read is never EMPTY. An
	// empty one is refused by the whole-pass gate, which withholds every delete
	// for a reason that has nothing to do with the sample.
	seedHydratedVM(t, r, "vm-3", "uuid-3", macH3)

	proof := &fixedProof{ok: true}
	var arrived bool
	r.inventorySnapshot = func(context.Context) InventoryProof {
		if !arrived {
			arrived = true
			// REPLICATION COMPLETING BEFORE THE DIGESTS ARE COLLECTED. Sampled
			// where production samples, this row is in the sample and in every
			// read the pass then makes; sampled after those reads, it is in
			// neither the desired state nor the plan.
			seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
		}
		return proof
	}

	err := r.SyncOnce(context.Background())

	if err != nil {
		t.Fatalf("the pass must run: %v", err)
	}
	if !arrived {
		t.Fatal("the pass never sampled its inventory, so nothing arrived before the sample " +
			"and this scenario proves nothing about an early arrival")
	}
	if proof.asked != 1 {
		t.Fatalf("the corroboration was asked %d time(s), want exactly 1: this scenario is "+
			"about a removal that RESTS on it, and one that never reached it would pass here "+
			"whatever the proof answered", proof.asked)
	}
	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 12 || len(ifaces) != 0 {
		t.Fatalf("deleted VMs %v and interfaces %v, want exactly the object whose incarnation "+
			"no host holds a row for: the row that arrived is inside the sample the proof "+
			"certified, so it cannot be why a removal drawn from that same read is withheld",
			vms, ifaces)
	}
	if got := mirrorSink(t, r).sweeps(); got[sweepOK] != 1 || got[sweepError] != 0 {
		t.Fatalf("sweeps = %v, want one converged pass. A pass that planned a delete for the "+
			"incarnation whose live row it holds — which is what reading the desired state "+
			"before sampling produces — has that delete withheld by the evidence read and "+
			"stops converging", got)
	}
	if mirrorSink(t, r).lastSuccess().IsZero() {
		t.Fatal("a converged pass must stamp its success: the staleness signal an operator " +
			"alerts on is the observable difference between a mirror that proceeded and one " +
			"that withheld everything without erroring")
	}
}
