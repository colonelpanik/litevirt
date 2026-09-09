package netboxsync

import (
	"context"
	"strconv"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// The delete-authorization guard.
//
// Every scenario here is about ONE rule: a delete may only be computed from a
// desired state that is provably WHOLE. The mirror's desired side is a read of
// the local replicated database, and that read has two silent partial answers —
// an empty table (a node hydrating after a DB loss, or one that took an
// uncontested lease because the `leader_election` row had not replicated yet)
// and a row the reader skipped (no uuid, no MAC). Neither is an error, so
// without a guard both arrive at Diff looking exactly like "litevirt no longer
// holds this", and Diff's job is to emit a delete for that.
//
// The blast radius is the operator's source of truth: DeleteVM cascades away
// every vminterface under it, and the NetBox object ids external systems
// reference are gone for good.

// macGuard is the NIC MAC these scenarios mirror.
const macGuard = "52:54:00:aa:bb:cc"

// mustFingerprint is the cluster fingerprint the seeded `cluster` row derives,
// read the way the sweep reads it.
func mustFingerprint(t *testing.T, r *Reconciler) string {
	t.Helper()
	fingerprint, err := corrosion.ClusterFingerprint(context.Background(), r.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	return fingerprint
}

// guardReconciler is a leader-held reconciler over a NetBox holding exactly one
// mirrored VM and its interface, under identities this cluster owns.
//
// The objects are what makes every assertion here non-vacuous: a delete is
// computed from what NetBox holds and litevirt does not, so a fixture with an
// empty NetBox could not tell a guard from its absence.
func guardReconciler(t *testing.T) (*stubVirt, *Reconciler, string) {
	t.Helper()
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	fingerprint := mustFingerprint(t, r)
	nb.listVMs = []netbox.VirtualMachine{{
		ID: 11, Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
		Identity: netbox.Identity(fingerprint, "uuid-1", ""),
	}}
	nb.listIfaces = []netbox.VMInterface{{
		ID: 21, VMID: 11, Name: "eth0", MAC: macGuard,
		Identity: netbox.Identity(fingerprint, "uuid-1", macGuard),
	}}
	return nb, r, fingerprint
}

// deletes returns what a sweep destroyed.
func deletes(nb *stubVirt) ([]int, []int) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return append([]int(nil), nb.deleted...), append([]int(nil), nb.deletedInterfaces...)
}

// TestSweepDeletesNothingWhenDesiredIsEmpty is the CRITICAL case.
//
// An empty desired set is not evidence that litevirt holds nothing; it is the
// answer a local read gives while the database is still hydrating, and it is
// also the answer a node gives after taking a lease nobody contested because
// the `leader_election` row had not reached it. Against a populated NetBox it
// diffs to "delete everything".
//
// The same rule P1's orphan sweeper already states about proofs: an empty
// universe makes every proof vacuously complete, which is the one shape that
// must never authorize a delete.
func TestSweepDeletesNothingWhenDesiredIsEmpty(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	// No VM rows at all: desiredState returns ([], nil), not an error.

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-delete phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("an empty desired state deleted VMs %v and interfaces %v from NetBox — "+
			"a local read that returned nothing is not evidence that litevirt holds nothing", vms, ifaces)
	}
}

// TestSweepDeletesNothingWhenAVMWasSkipped covers the second partial read.
//
// desiredState SKIPS a VM whose spec carries no uuid and logs a warning. The
// skip is silent to everything downstream: the sweep goes on to record a
// success and stamp the staleness gauge, so a partial read is reported as a
// converged mirror — while the VM it dropped is, to Diff, a VM litevirt no
// longer holds.
//
// The claim in the code that a skip "can never turn into a delete" holds only
// for a VM that was never mirrored. This one was.
func TestSweepDeletesNothingWhenAVMWasSkipped(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	// The mirrored VM is present and whole, so nothing about IT is missing…
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`, macGuard)
	// …and a SECOND VM is unreadable. Its own object is not at risk — it has
	// never been mirrored — but the pass that dropped it is no longer a
	// complete picture of what litevirt holds.
	seedVMRow(t, r, "vm-2", `{"cpu":1,"memory_mib":512}`, "52:54:00:aa:bb:dd")
	// The interface object NetBox holds for the first VM is gone from the local
	// database, so a sweep that trusted this read would detach it.
	nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
		ID: 22, VMID: 11, Name: "eth1", MAC: "52:54:00:aa:bb:ee",
		Identity: netbox.Identity(mustFingerprint(t, r), "uuid-1", "52:54:00:aa:bb:ee"),
	})

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("the sweep must still run its non-delete phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a sweep that skipped an unreadable VM deleted VMs %v and interfaces %v — "+
			"a partial read must not authorize a delete", vms, ifaces)
	}
}

// TestSweepDeletesNothingWhenANICWasSkipped is the same rule one level down.
//
// A NIC with no MAC cannot be named in NetBox, so desiredNICs drops it. The VM
// it hangs off is still mirrored, so the sweep looks whole — but the interface
// set it computed for that VM is not, and every interface missing from it is a
// nic/delete.
func TestSweepDeletesNothingWhenANICWasSkipped(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	// A second NIC on the SAME VM, with no MAC — the shape a legacy row leaves.
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`, macGuard, "")
	nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
		ID: 22, VMID: 11, Name: "eth1", MAC: "52:54:00:aa:bb:ee",
		Identity: netbox.Identity(mustFingerprint(t, r), "uuid-1", "52:54:00:aa:bb:ee"),
	})

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("the sweep must still run its non-delete phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a sweep that skipped a MAC-less NIC deleted VMs %v and interfaces %v — "+
			"an incomplete interface set must not authorize a delete", vms, ifaces)
	}
}

// TestSweepStillDeletesOnWholeEvidence is the negative control.
//
// Without it every assertion above is satisfied by a mirror that never deletes
// anything at all, which is a different bug: a NetBox that keeps advertising
// VMs the cluster destroyed is exactly what the delete half exists to prevent.
func TestSweepStillDeletesOnWholeEvidence(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	// litevirt holds a DIFFERENT VM, read completely…
	seedVMRow(t, r, "vm-2", `{"uuid":"uuid-2","cpu":1,"memory_mib":512}`, "52:54:00:aa:bb:dd")
	// …and the mirrored one is gone, THROUGH THE PRODUCTION DELETE. A destroyed
	// VM leaves a tombstone behind and `vms.go`'s only hard delete fires solely
	// on a same-name re-create (which leaves a live row under that name), so a
	// mirrored VM with neither a live row nor a tombstone is not a state the
	// cluster can produce — it is what a database that has not finished
	// replicating looks like, and the per-object evidence rule withholds it.
	// Modelling the delete as "the row simply is not there" asserted convergence
	// on that shape.
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`, macGuard)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 11 {
		t.Fatalf("a whole desired state must still delete the VM litevirt no longer holds, deleted %v", vms)
	}
	if len(ifaces) != 1 || ifaces[0] != 21 {
		t.Fatalf("its interface must go with it, deleted %v", ifaces)
	}
}

// TestSweepWithholdsTheNameReplacementOnAPartialRead.
//
// A vm/replace frees a reused name from its superseded incarnation, and half of
// its proof is that the occupying object's UUID is NOT in the desired set. That
// premise is only as good as the desired read is whole — on a partial read the
// UUID may simply be missing from it — so the replacement is withheld exactly as
// every delete is, and the create then collides as it did before the replacement
// existed. A stalled mirror for one VM, rather than an object removed on evidence
// the pass has just admitted is partial.
func TestSweepWithholdsTheNameReplacementOnAPartialRead(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	// vm-1 recreated under a NEW uuid: NetBox still holds the old incarnation
	// (id 11, uuid-1) under that name.
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-new","cpu":2,"memory_mib":1024}`, macGuard)
	// …and a second VM whose spec carries no uuid, which desiredState SKIPS.
	// That is what makes this read partial.
	seedVMRow(t, r, "vm-2", `{"cpu":1,"memory_mib":512}`, "52:54:00:aa:bb:dd")

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("the sweep must still run its non-destructive phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a partial read replaced the object holding a reused name (VMs %v, "+
			"interfaces %v); \"this UUID is not in the desired set\" is not a fact a partial "+
			"desired read can establish", vms, ifaces)
	}
}

// TestSweepReplacesTheSupersededNameHolderOnWholeEvidence is the negative
// control for the scenario above: with the read whole, the replacement runs.
// Without this, a mirror that never replaced anything would satisfy it.
//
// The same-name re-create is the case that costs the superseded incarnation its
// `vms` tombstone — InsertVMWithHardware purges it to free the name for the new
// row — so the incarnation record this pass proves the replacement from is the
// mirror's own mapping row, seeded here because a caught-up node holds it, plus
// the corroboration that makes the uuid's absence from this read a fact about
// the cluster rather than about one node's replication progress. A caught-up
// node has both; see vmRemovalProven for why the row alone is not enough.
func TestSweepReplacesTheSupersededNameHolderOnWholeEvidence(t *testing.T) {
	nb, r, fingerprint := guardReconciler(t)
	ctx := context.Background()
	withCorroboratedInventory(r)
	seedMirroredObjectRef(t, r, netbox.Identity(fingerprint, "uuid-1", ""), 11)
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-new","cpu":2,"memory_mib":1024}`, macGuard)

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, _ := deletes(nb)
	if len(vms) != 1 || vms[0] != 11 {
		t.Fatalf("the superseded incarnation holding the reused name must be replaced, "+
			"deleted %v", vms)
	}
}

// TestSweepRetiresTheLastVMOnItsTombstone is the case an unqualified
// empty-desired refusal would strand forever.
//
// Deleting the last VM in a cluster leaves desired EMPTY and NetBox holding the
// object — the same shape a hydrating node presents. The two are told apart by
// evidence, not by shape: a delete leaves a `vms` tombstone behind and nothing
// prunes it, while a database that has never been read holds no row of any
// kind. Without this the mirror would advertise a destroyed VM for as long as
// the cluster stayed empty, and no later sweep could ever retire it.
func TestSweepRetiresTheLastVMOnItsTombstone(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`, macGuard)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 11 {
		t.Fatalf("a deleted last VM must be retired from NetBox, deleted %v", vms)
	}
	if len(ifaces) != 1 || ifaces[0] != 21 {
		t.Fatalf("its interface must go with it, deleted %v", ifaces)
	}
	if ts := mirrorSink(t, r).lastSuccess(); ts.IsZero() {
		t.Fatal("a sweep on corroborated evidence converged and must stamp the staleness gauge")
	}
}

// TestSuppressedSweepRecordsNoSuccess pins the reporting half.
//
// litevirt_netbox_mirror_last_success_seconds is the staleness signal an
// operator alerts on. A pass that withheld its deletes did NOT converge — it
// left NetBox advertising objects the diff could not prove are still real — so
// stamping success there reports a healthy mirror for exactly as long as the
// condition lasts, and the alert never fires.
func TestSuppressedSweepRecordsNoSuccess(t *testing.T) {
	nb, r, _ := guardReconciler(t)
	ctx := context.Background()
	m := mirrorSink(t, r)

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a sweep that withheld its deletes stamped a success at %v", ts)
	}
	if got := m.sweeps(); got[sweepOK] != 0 {
		t.Fatalf("sweep results = %v, want no ok result for a pass that did not converge", got)
	}

	// The positive control: the same fixture with whole evidence must advance
	// it, or the assertions above are satisfied by a sink nothing ever calls.
	// The mirrored VM is retired through the production delete, so the pass has
	// a record for every NetBox object it accounts for.
	seedVMRow(t, r, "vm-2", `{"uuid":"uuid-2","cpu":1,"memory_mib":512}`, "52:54:00:aa:bb:dd")
	seedVMRow(t, r, "vm-1", `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`, macGuard)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ts := m.lastSuccess(); ts.IsZero() {
		t.Fatal("a converged sweep must stamp the staleness gauge")
	}
	if got := m.sweeps(); got[sweepOK] != 1 {
		t.Fatalf("sweep results = %v, want exactly one ok", got)
	}
	_ = nb
}

// seedVMRow writes one running VM, under a caller-supplied spec so a scenario
// can model a spec the mirror cannot read, and one NIC per supplied MAC — an
// empty one being the MAC-less shape a legacy vm_interfaces row leaves behind.
func seedVMRow(t *testing.T, r *Reconciler, name, spec string, macs ...string) {
	t.Helper()
	ifaces := make([]corrosion.InterfaceRecord, 0, len(macs))
	for i, mac := range macs {
		// vm_interfaces is keyed on (vm_name, network_name), so a second NIC
		// needs a network of its own.
		ifaces = append(ifaces, corrosion.InterfaceRecord{
			VMName: name, NetworkName: "bound-" + strconv.Itoa(i), Ordinal: i,
			MAC: mac, IP: "10.0.5.100",
		})
	}
	if err := corrosion.InsertVM(context.Background(), r.db, corrosion.VMRecord{
		Name:     name,
		HostName: "host-a",
		State:    "running",
		Spec:     spec,
	}, ifaces, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}
