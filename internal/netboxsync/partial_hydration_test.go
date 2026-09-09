package netboxsync

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// The delete half against a PARTIALLY hydrated local database.
//
// sweep_guard_test.go closes the EMPTY read: a `vms` table with no live row is
// corroborated against tombstone history before any delete is computed. That
// leaves the far more common shape wide open — a table with SOME of the
// cluster's rows in it. A node rebuilt from scratch, or one that just joined,
// hydrates row by row, and every row that has not arrived yet is, to the diff,
// a VM litevirt no longer holds.
//
// Nothing throttles such a node into safety either. It reclaims the shared
// `netbox` lease immediately (the conflict clause admits its own holder
// unconditionally), the cluster-record heal supplies the CA locally at startup
// so a fingerprint derives, and the capability latch re-forms within seconds of
// the daemon coming up. The only brake left is the first sweep tick.
//
// The rule these scenarios pin is the same one the empty read already obeys,
// applied per OBJECT instead of per pass: a delete needs positive local evidence
// that the thing it removes is genuinely gone. The evidence is the record the
// local database holds — live or TOMBSTONED — because a workload the cluster
// destroyed leaves one behind and a row that never replicated leaves nothing.

// The MACs these scenarios use: one per mirrored VM, plus the one belonging to
// an interface that was genuinely detached.
const (
	macH1       = "52:54:00:cc:00:01"
	macH2       = "52:54:00:cc:00:02"
	macH3       = "52:54:00:cc:00:03"
	macDetached = "52:54:00:cc:00:09"
)

// hydrationReconciler is a leader-held reconciler over a NetBox that already
// mirrors THREE VMs of this cluster, each with one interface — and a local
// database holding nothing but the `cluster` row.
//
// Three, not one: the failure is a fraction of the inventory disappearing from
// the local read, and a single-object fixture cannot tell "deleted what it could
// not see" from "deleted nothing".
func hydrationReconciler(t *testing.T) (*stubVirt, *Reconciler, string) {
	t.Helper()
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	fp := mustFingerprint(t, r)

	macs := []string{macH1, macH2, macH3}
	for i, mac := range macs {
		uuid := "uuid-" + string(rune('1'+i))
		nb.listVMs = append(nb.listVMs, netbox.VirtualMachine{
			ID: 11 + i, Name: "vm-" + string(rune('1'+i)), ClusterID: 5,
			VCPUs: 2, MemoryMB: 1024, Status: "active",
			Identity: netbox.Identity(fp, uuid, ""),
		})
		nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
			ID: 21 + i, VMID: 11 + i, Name: "eth0", MAC: mac,
			Identity: netbox.Identity(fp, uuid, mac),
		})
	}
	return nb, r, fp
}

// seedHydratedVM writes the rows one running VM leaves behind. A nil macs slice
// writes the VM with NO interface rows at all, which is what a `vms` row that
// has replicated ahead of its `vm_interfaces` rows looks like.
func seedHydratedVM(t *testing.T, r *Reconciler, name, uuid string, macs ...string) {
	t.Helper()
	ifaces := make([]corrosion.InterfaceRecord, 0, len(macs))
	for i, mac := range macs {
		ifaces = append(ifaces, corrosion.InterfaceRecord{
			VMName: name, NetworkName: "net-" + string(rune('a'+i)), Ordinal: i, MAC: mac,
		})
	}
	if err := corrosion.InsertVM(context.Background(), r.db, corrosion.VMRecord{
		Name: name, HostName: "host-a", State: "running",
		Spec: `{"uuid":"` + uuid + `","cpu":2,"memory_mib":1024}`,
	}, ifaces, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

// TestPartiallyHydratedDesiredDeletesNothingUnproven is the CRITICAL case.
//
// One of the cluster's three VMs has reached this node. The other two are, to
// the diff, VMs NetBox holds and litevirt does not — and the pass has no local
// record of either, tombstone included, to say they were ever destroyed.
func TestPartiallyHydratedDesiredDeletesNothingUnproven(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-delete phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a partially-hydrated local read deleted VMs %v and interfaces %v from NetBox — "+
			"a row that has not replicated yet is not evidence that the workload is gone", vms, ifaces)
	}
}

// TestPartiallyHydratedSweepRecordsNoSuccess pins the reporting half: NetBox is
// still advertising objects this pass could not account for, which is not a
// converged mirror and must not stamp the staleness gauge an operator alerts on.
func TestPartiallyHydratedSweepRecordsNoSuccess(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	m := mirrorSink(t, r)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a pass that withheld unproven deletes stamped a success at %v", ts)
	}
	if got := m.sweeps(); got[sweepOK] != 0 {
		t.Fatalf("sweep results = %v, want no ok result for a pass that did not converge", got)
	}
	_ = nb
}

// TestGenuinelyDeletedVMIsStillRetired is the negative control for the VM half.
//
// Without it every assertion above is satisfied by a mirror that stopped
// deleting — and a NetBox that keeps advertising VMs the cluster destroyed is
// what the delete half exists to prevent. The fixture is FULLY hydrated and one
// VM is genuinely gone, which is the ordinary case on a healthy leader.
func TestGenuinelyDeletedVMIsStillRetired(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	ctx := context.Background()
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	seedHydratedVM(t, r, "vm-2", "uuid-2", macH2)
	seedHydratedVM(t, r, "vm-3", "uuid-3", macH3)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-3"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	m := mirrorSink(t, r)

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 13 {
		t.Fatalf("deleted VMs = %v, want exactly the one the cluster destroyed", vms)
	}
	if len(ifaces) != 1 || ifaces[0] != 23 {
		t.Fatalf("deleted interfaces = %v, want the destroyed VM's own", ifaces)
	}
	if ts := m.lastSuccess(); ts.IsZero() {
		t.Fatal("a pass that accounted for every NetBox object converged and must stamp the gauge")
	}
}

// TestUnhydratedInterfaceRowsEmitNoNICDelete is the same rule one level down.
//
// `vms` and `vm_interfaces` are separate replicated tables, so a VM row can
// arrive ahead of its interface rows. The VM is then in the desired set with an
// EMPTY interface set, and every interface NetBox holds under it is a
// nic/delete — with the VM object itself left in place, so the mirror ends up
// advertising a machine with no networking at all.
func TestUnhydratedInterfaceRowsEmitNoNICDelete(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	// Every VM row present; not one interface row.
	seedHydratedVM(t, r, "vm-1", "uuid-1")
	seedHydratedVM(t, r, "vm-2", "uuid-2")
	seedHydratedVM(t, r, "vm-3", "uuid-3")

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(ifaces) != 0 {
		t.Fatalf("a `vms` read that arrived ahead of its interface rows deleted interfaces %v — "+
			"an absent NIC row is not evidence the NIC was detached", ifaces)
	}
	if len(vms) != 0 {
		t.Fatalf("deleted VMs = %v; every VM is in the desired set", vms)
	}
}

// TestGenuinelyDetachedNICIsStillRetired is the negative control for the NIC
// half, and the mutation that catches a gate applied to the VM half only.
//
// A detach tombstones the interface row rather than removing it, so the record
// that proves the NIC is gone is exactly the evidence the rule asks for.
func TestGenuinelyDetachedNICIsStillRetired(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	ctx := context.Background()
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1, macDetached)
	seedHydratedVM(t, r, "vm-2", "uuid-2", macH2)
	seedHydratedVM(t, r, "vm-3", "uuid-3", macH3)
	// NetBox holds the detached NIC's interface; litevirt holds its tombstone.
	nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
		ID: 24, VMID: 11, Name: "eth1", MAC: macDetached,
		Identity: netbox.Identity(fp, "uuid-1", macDetached),
	})
	if err := corrosion.SoftDeleteInterfaceByMAC(ctx, r.db, "vm-1", macDetached); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(ifaces) != 1 || ifaces[0] != 24 {
		t.Fatalf("deleted interfaces = %v, want exactly the one whose row the cluster tombstoned", ifaces)
	}
	if len(vms) != 0 {
		t.Fatalf("deleted VMs = %v; every VM is in the desired set", vms)
	}
}

// ── the CAUSE of a withheld replacement ─────────────────────────────────────

// TestWithheldReplacementReportsTheIncompleteInventoryAsItsCause.
//
// Withholding the replacement is right: half its proof is "this UUID is absent
// from the desired set", which is only as good as the desired read is whole, so
// a pass that cannot prove its read whole must not act on it. The stall that
// produces is agreed and stays.
//
// What an operator saw was only the collision — `HTTP 400: a virtual machine
// with this name already exists in this cluster` — for a name litevirt can see
// is free, with nothing connecting it to the partial read that is the actual
// cause. So the failure has to name it.
//
// The scenario is the partially hydrated leader: one of the cluster's three VMs
// has reached this node, and it has been RENAMED onto a name another of our
// NetBox objects still holds. The replace that would free it is dropped with the
// unproven deletes, and the rename then collides.
func TestWithheldReplacementReportsTheIncompleteInventoryAsItsCause(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	nb.enforceNames = true
	// The one local row: uuid-1's VM, renamed onto vm-2 — a name NetBox still
	// holds under uuid-2, whose own row has not replicated here.
	seedHydratedVM(t, r, "vm-2", "uuid-1", macH1)

	err := r.SyncOnce(context.Background())
	if err == nil {
		t.Fatal("the rename must collide: the name is held by an object this pass may not remove")
	}
	// THE COLLISION IS STILL THERE — the fail-closed stall is the agreed
	// behaviour and must not have been traded away for a nicer message.
	if !strings.Contains(err.Error(), "already exists in this cluster") {
		t.Fatalf("want the NetBox name refusal preserved, got: %v", err)
	}
	// …and it now says WHY the replacement that would have cleared it was
	// withheld.
	for _, want := range []string{"withheld the replacement", "vm-2", "partial"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the failure must name %q as part of the cause; got: %v", want, err)
		}
	}
	// Nothing was removed on the partial evidence, which is the property the
	// message is explaining.
	if vms, ifaces := deletes(nb); len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a pass that admitted its read was partial removed VMs %v and interfaces %v",
			vms, ifaces)
	}
}

// TestAProvenReplacementIsNotReportedAsWithheld is the negative control: without
// it, an annotation applied unconditionally would satisfy the test above and
// attach a partial-read explanation to a pass that withheld nothing.
func TestAProvenReplacementIsNotReportedAsWithheld(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	nb.enforceNames = true
	ctx := context.Background()
	// FULLY hydrated, and uuid-2's VM destroyed and recreated under the same
	// name — so its old object is a superseded incarnation this pass CAN prove,
	// and the create onto its name goes through.
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	seedHydratedVM(t, r, "vm-2", "uuid-2", macH2)
	seedHydratedVM(t, r, "vm-3", "uuid-3", macH3)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-2"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	seedHydratedVM(t, r, "vm-2", "uuid-2b", macDetached)

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("a proven replacement must free the name and let the new incarnation land: %v", err)
	}

	// The superseded object is gone and the new incarnation took its name.
	if vms, _ := deletes(nb); len(vms) != 1 || vms[0] != 12 {
		t.Fatalf("deleted VMs = %v, want exactly the superseded object holding the name", vms)
	}
	var landed bool
	for _, v := range nb.created {
		if v.Name == "vm-2" {
			landed = true
		}
	}
	if !landed {
		t.Fatalf("the new incarnation was never created onto the freed name, got %+v", nb.created)
	}
}
