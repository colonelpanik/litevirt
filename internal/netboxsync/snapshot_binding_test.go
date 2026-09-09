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
func TestAPassWithNoProofWithholdsAMappingOnlyRemoval(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	nb.listVMs = nb.listVMs[:1]
	nb.listIfaces = nb.listIfaces[:1]
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-1", ""), 11)
	r.inventorySnapshot = func(context.Context) InventoryProof { return nil }

	err := r.SyncOnce(context.Background())

	if vms, ifaces := deletes(nb); len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a pass whose inventory could not be sampled deleted VMs %v and interfaces "+
			"%v on a mapping row alone; sweep error=%v", vms, ifaces, err)
	}
}
