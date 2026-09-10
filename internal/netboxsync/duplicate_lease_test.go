package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// What happens when the desired-address join's key is not unique.
//
// The join is keyed on (network, MAC) because the NetBox address object is named
// by the NIC's IDENTITY and the recorded IP is not an identity component — see
// address_join_test.go. But (network, MAC) is not a uniqueness constraint
// anywhere in litevirt: the `ip_allocations` primary key is (network, ip), and
// the only MAC-collision check on the attach path is PER-VM. Two VMs given the
// same MAC on one bound network therefore leave TWO live leases under one key.
//
// A map keyed on it collapses them into one entry, and which of the two wins is
// not even stable — ListNetBoxLeases has no ORDER BY. The loser's NIC then
// resolves to the WINNER's address object, which the mirror faithfully assigns
// to the loser's interface and detaches from the winner's: one workload's
// address moved onto another workload's interface, while both `ip_allocations`
// rows stay live so the orphan sweeper can never see the stranding.
//
// So a duplicate key is not a state to resolve. It is ambiguous ownership, and
// ambiguous ownership must not drive a write at all.

// The MACs and addresses these scenarios use. macGuard is shared with
// sweep_guard_test.go; macDistinct is what a correctly-provisioned second VM
// carries, and is the control's only difference from the duplicate.
const (
	macDistinct = "52:54:00:aa:bb:d0"
	macStale    = "52:54:00:aa:bb:d1"
	dupIPFirst  = "10.0.5.100"
	dupIPSecond = "10.0.5.101"
)

// sharedMACReconciler is two VMs on ONE bound network, each holding its own
// NetBox address, plus a third VM that NetBox still advertises and litevirt no
// longer holds.
//
// mac2 is the second VM's MAC: macGuard makes the two leases collide, anything
// else is the well-formed control. addr42AssignedTo is which interface NetBox
// says address 42 hangs off — 0 models the address the allocator has claimed but
// no sweep has attached yet, which is what makes the control's assign
// observable.
//
// The stale third VM is what makes the withheld DELETE half observable: with
// only the two live VMs in the fixture no delete would be computed either way,
// and "no delete was emitted" would hold whether or not anything withheld it.
func sharedMACReconciler(t *testing.T, mac2 string, addr42AssignedTo int) (*stubVirt, *Reconciler) {
	t.Helper()
	ctx := context.Background()
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	fp := mustFingerprint(t, r)

	seedLeasedVM(t, r, "vm-1", "uuid-1", macGuard, dupIPFirst, 41)
	seedLeasedVM(t, r, "vm-2", "uuid-2", mac2, dupIPSecond, 42)
	// The third VM is retired through the PRODUCTION delete, so the pass holds
	// a record — a tombstone — for the NetBox objects it is expected to reap. A
	// row that simply is not there is what an unreplicated one looks like, and
	// the per-object evidence rule withholds those.
	seedHydratedVM(t, r, "vm-3", "uuid-3", macStale)
	if err := corrosion.DeleteVM(ctx, r.db, "vm-3"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	nb.listVMs = []netbox.VirtualMachine{
		{ID: 11, Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
			Identity: netbox.Identity(fp, "uuid-1", "")},
		{ID: 12, Name: "vm-2", ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
			Identity: netbox.Identity(fp, "uuid-2", "")},
		// The object litevirt no longer holds.
		{ID: 13, Name: "vm-3", ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
			Identity: netbox.Identity(fp, "uuid-3", "")},
	}
	nb.listIfaces = []netbox.VMInterface{
		{ID: 21, VMID: 11, Name: "eth0", MAC: macGuard,
			Identity: netbox.Identity(fp, "uuid-1", macGuard)},
		{ID: 22, VMID: 12, Name: "eth0", MAC: mac2,
			Identity: netbox.Identity(fp, "uuid-2", mac2)},
		{ID: 23, VMID: 13, Name: "eth0", MAC: macStale,
			Identity: netbox.Identity(fp, "uuid-3", macStale)},
	}
	nb.listIPs = []netbox.IPAddress{
		{ID: 41, Address: dupIPFirst + "/24", AssignedObjectID: 21,
			Identity: netbox.Identity(fp, "uuid-1", macGuard)},
		{ID: 42, Address: dupIPSecond + "/24", AssignedObjectID: addr42AssignedTo,
			Identity: netbox.Identity(fp, "uuid-2", mac2)},
	}
	return nb, r
}

// seedLeasedVM writes one running VM with one NIC on the bound network, and the
// `ip_allocations` row the NetBox allocator left behind for it.
func seedLeasedVM(t *testing.T, r *Reconciler, name, uuid, mac, ip string, netboxIPID int) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, r.db, corrosion.VMRecord{
		Name: name, HostName: "host-a", State: "running",
		Spec: `{"uuid":"` + uuid + `","cpu":2,"memory_mib":1024}`,
	}, []corrosion.InterfaceRecord{{
		VMName: name, NetworkName: joinNetwork, Ordinal: 0, MAC: mac, IP: ip,
	}}, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
	if err := r.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'vm', 'host-a', ?, 7, ?, ?)`,
		joinNetwork, ip, mac, name, netboxIPID, r.db.NowWall(), r.db.NowTS()); err != nil {
		t.Fatalf("seed ip_allocations(%s): %v", name, err)
	}
}

// assignments returns the (address -> interface) attachments a sweep made.
func assignments(nb *stubVirt) []ipAssignment {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return append([]ipAssignment(nil), nb.ipAssignments...)
}

// TestDuplicateLeaseKeyDrivesNoAddressWrite is the regression.
//
// Two live leases under one key resolve to ONE address id, so one of the two
// NICs is handed an address object that belongs to the other workload. Whichever
// duplicate the query happened to return last, the sweep both attaches that
// address to the wrong interface and detaches it from the right one.
func TestDuplicateLeaseKeyDrivesNoAddressWrite(t *testing.T) {
	nb, r := sharedMACReconciler(t, macGuard, 22)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-address phases: %v", err)
	}

	if got := assignments(nb); len(got) != 0 {
		t.Fatalf("the sweep attached %+v — two live leases under one (network, MAC) key name "+
			"no address unambiguously, and an ambiguous owner must not drive a write", got)
	}
	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("the sweep detached %v — the address a duplicated key could not resolve is "+
			"still correctly assigned, and unassigning it strands the workload in NetBox", got)
	}
}

// TestDuplicateLeaseKeyWithholdsTheDeleteHalf is the other half of the rule.
//
// A key the reader could not resolve makes the desired state PARTIAL in exactly
// the way an unreadable VM spec does, so the same evidence rule applies: the
// pass may not delete, and it may not report itself converged. Without this the
// duplicate would be an address bug only, and the sweep would go on to retire
// NetBox objects from a picture it had already admitted was incomplete.
func TestDuplicateLeaseKeyWithholdsTheDeleteHalf(t *testing.T) {
	nb, r := sharedMACReconciler(t, macGuard, 22)
	m := mirrorSink(t, r)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a pass whose address join was ambiguous deleted VMs %v and interfaces %v — "+
			"a partial desired state must not authorize a delete", vms, ifaces)
	}
	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a pass that withheld its deletes stamped a success at %v", ts)
	}
	if got := m.sweeps(); got[sweepOK] != 0 {
		t.Fatalf("sweep results = %v, want no ok result for a pass that did not converge", got)
	}
}

// TestDistinctMACsStillDriveTheAddressAndDeleteHalves is the negative control.
//
// Without it every assertion above is satisfied by a mirror that stopped
// assigning addresses and stopped deleting — which is the bug the address and
// delete halves exist to prevent. The fixture differs from the duplicate in
// ONE field: the second VM's MAC.
func TestDistinctMACsStillDriveTheAddressAndDeleteHalves(t *testing.T) {
	nb, r := sharedMACReconciler(t, macDistinct, 0)
	m := mirrorSink(t, r)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := assignments(nb)
	if len(got) != 1 || got[0].IPID != 42 || got[0].IfaceID != 22 {
		t.Fatalf("assignments = %+v, want the second VM's own address attached to its own interface", got)
	}
	if c := cleared(nb); len(c) != 0 {
		t.Fatalf("a well-formed fixture detached %v", c)
	}
	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 13 {
		t.Fatalf("deleted VMs = %v, want the one litevirt no longer holds", vms)
	}
	if len(ifaces) != 1 || ifaces[0] != 23 {
		t.Fatalf("deleted interfaces = %v, want the stale VM's own", ifaces)
	}
	if ts := m.lastSuccess(); ts.IsZero() {
		t.Fatal("a pass on an unambiguous read converged and must stamp the staleness gauge")
	}
}
