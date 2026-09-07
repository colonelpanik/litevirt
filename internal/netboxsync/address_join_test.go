package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
)

// How a NIC finds the NetBox address object it holds.
//
// The address object is keyed by the NIC's IDENTITY — lv:<fp>:<uuid>:<mac> — so
// the thing that resolves it must be keyed on an identity component too. The
// recorded IP is not one: `vm_interfaces.ip` is an inventory field, and
// SetVMIP writes an operator-supplied value straight into it with a fresh
// updated_at that wins MergedVMNICs' LWW. Join on it and every disagreement
// between the recorded IP and the lease's IP resolves to "this NIC holds no
// NetBox address", which routes a correct, live assignment into the CLEAR
// branch.

// joinNetwork and the two addresses these scenarios use: the address the lease
// actually claimed, and the different value an operator recorded on the NIC.
const (
	joinNetwork = "bound"
	leasedIP    = "10.0.5.100"
	recordedIP  = "10.0.5.200"
	// The address a lease of ours once claimed and has since released — the
	// genuinely stale assignment the clear half exists for.
	releasedIP = "10.0.5.201"
)

// addressJoinReconciler is one mirrored VM with one NIC that holds one
// litevirt-owned NetBox address, assigned and correct.
//
// The NIC's recorded IP is the caller's, so a scenario can set it to something
// other than what the lease claimed — which is exactly the state SetVMIP leaves
// behind.
func addressJoinReconciler(t *testing.T, nicIP string) (*stubVirt, *Reconciler) {
	t.Helper()
	ctx := context.Background()
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	fingerprint := mustFingerprint(t, r)

	if err := corrosion.InsertVM(ctx, r.db, corrosion.VMRecord{
		Name: "vm-1", HostName: "host-a", State: "running",
		Spec: `{"uuid":"uuid-1","cpu":2,"memory_mib":1024}`,
	}, []corrosion.InterfaceRecord{{
		VMName: "vm-1", NetworkName: joinNetwork, Ordinal: 0, MAC: macGuard, IP: nicIP,
	}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The lease the NetBox allocator recorded: address 41, claimed under this
	// NIC's MAC, at the IP NetBox handed out.
	if err := r.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, 'vm-1', 'vm', 'host-a', 41, 7, ?, ?)`,
		joinNetwork, leasedIP, macGuard, r.db.NowWall(), r.db.NowTS()); err != nil {
		t.Fatalf("seed ip_allocations: %v", err)
	}

	nicID := netbox.Identity(fingerprint, "uuid-1", macGuard)
	nb.listVMs = []netbox.VirtualMachine{{
		ID: 11, Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
		Identity: netbox.Identity(fingerprint, "uuid-1", ""),
	}}
	nb.listIfaces = []netbox.VMInterface{{
		ID: 21, VMID: 11, Name: "eth0", MAC: macGuard, Identity: nicID,
	}}
	nb.listIPs = []netbox.IPAddress{{
		ID: 41, Address: leasedIP + "/24", Identity: nicID, AssignedObjectID: 21,
	}}
	return nb, r
}

// cleared returns the address ids a sweep detached.
func cleared(nb *stubVirt) []int {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return append([]int(nil), nb.cleared...)
}

// TestRecordedIPEditKeepsTheLiveAssignment is the failure SetVMIP reaches.
//
// SetVMIP writes an operator-supplied IP into `vm_interfaces.ip` with no
// bound-network refusal, and MergedVMNICs' LWW hands the mirror that value. The
// address object it names has not moved and is still correctly assigned — but a
// lookup keyed on the recorded IP no longer finds it, so the sweep detaches the
// assignment the allocator made.
func TestRecordedIPEditKeepsTheLiveAssignment(t *testing.T) {
	nb, r := addressJoinReconciler(t, recordedIP)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("the sweep detached %v — a recorded-IP edit must not unassign the address "+
			"the lease actually claimed", got)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.ipAssignments) != 0 {
		t.Fatalf("the address is already assigned to this interface; re-assigning it is churn: %+v",
			nb.ipAssignments)
	}
}

// TestMatchingRecordedIPKeepsTheAssignment is the control for the ordinary
// case: the recorded IP and the lease agree, which is what every allocator path
// produces. It must be indistinguishable from the scenario above.
func TestMatchingRecordedIPKeepsTheAssignment(t *testing.T) {
	nb, r := addressJoinReconciler(t, leasedIP)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("a NIC whose recorded IP matches its lease had %v detached", got)
	}
}

// TestGenuinelyStaleAddressIsStillCleared is the negative control.
//
// Without it, both scenarios above are satisfied by a mirror that never clears
// anything — and the clear half is what stops an interface accumulating every
// address it has ever held. A litevirt-owned address on this interface that no
// LIVE lease of ours names is stale, and must go.
//
// The fixture models how one actually arises. A litevirt-owned address assigned
// to a litevirt interface got there because the mirror assigned it, from a lease
// this cluster held; what makes it stale afterwards is the RELEASE, and
// network.ReleaseLease tombstones the `ip_allocations` row while retaining
// netbox_ip_id. So the local database still holds a record naming the address,
// which is exactly the evidence the clear rule asks for.
//
// An `ip_allocations` row simply ABSENT is a different state and not this one:
// that is what an unreplicated table looks like, and those clears are withheld
// (clear_evidence_test.go). Using it here would have made this control pass on a
// shape production cannot produce.
func TestGenuinelyStaleAddressIsStillCleared(t *testing.T) {
	nb, r := addressJoinReconciler(t, leasedIP)
	fingerprint := mustFingerprint(t, r)
	nb.listIPs = append(nb.listIPs, netbox.IPAddress{
		ID: 42, Address: releasedIP + "/24", AssignedObjectID: 21,
		Identity: netbox.Identity(fingerprint, "uuid-1", macGuard),
	})
	seedReleasedJoinLease(t, r, releasedIP, 42)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := cleared(nb)
	if len(got) != 1 || got[0] != 42 {
		t.Fatalf("cleared %v, want exactly the address whose lease this cluster released", got)
	}
}

// seedReleasedJoinLease claims an address on the bound network for this
// fixture's VM and then releases it through the PRODUCTION path.
//
// network.ReleaseLease, not a hand-written tombstone: what this fixture rests on
// is that a release retains netbox_ip_id on the row it tombstones, and writing
// the row by hand would assert that instead of exercising it.
func seedReleasedJoinLease(t *testing.T, r *Reconciler, ip string, netboxIPID int) {
	t.Helper()
	ctx := context.Background()
	if err := r.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, 'vm-1', 'vm', 'host-a', ?, 7, ?, ?)`,
		joinNetwork, ip, macGuard, netboxIPID, r.db.NowWall(), r.db.NowTS()); err != nil {
		t.Fatalf("seed ip_allocations(%s): %v", ip, err)
	}
	if err := network.ReleaseLease(ctx, r.db,
		joinNetwork, ip, macGuard, "vm", "host-a", "vm-1"); err != nil {
		t.Fatalf("ReleaseLease(%s): %v", ip, err)
	}
}
