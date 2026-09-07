package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
)

// The CLEAR half against a partial local read.
//
// partial_hydration_test.go closes the delete half: a NetBox object whose VM or
// NIC row this node holds nothing for, tombstone included, is not retired. The
// clear half was left running in both of the states that gate reaches.
//
// A clear unassigns an `ip_address` from a `vminterface`. It is bounded where a
// delete is not — the address object survives and a healthy sweep re-attaches it
// — but the fleet's whole addressing is one pass away, because the shape that
// reaches it is not exotic. The desired side resolves each NIC's address through
// `ip_allocations`, and anti-entropy repairs PER TABLE: "`vms` and
// `vm_interfaces` repaired, `ip_allocations` not yet" is a state the repair
// mechanism itself produces. Every NIC then resolves to address 0 — read as
// "this NIC holds no address" — and every litevirt-owned address in the cluster
// routes into the clear branch.
//
// Two rules cover it, and they are deliberately different in blast radius:
//
//   - PER OBJECT: a clear needs a local `ip_allocations` record naming the
//     address, live or tombstoned. The evidence is complete because nothing
//     hard-deletes such a row — ReleaseLease tombstones it and retains
//     netbox_ip_id — so requiring the proof cannot strand a stale assignment.
//   - WHOLE PASS: a pass that withheld a DELETE has positive proof its inventory
//     read is partial, and the clear branch resolves addresses through that same
//     read. It withholds every clear as well rather than running the destructive
//     half of a read it has just called partial.

// The addresses and MACs these scenarios use. Three VMs, because the failure is
// "every address in the cluster detached at once" and a one-object fixture
// cannot tell that from "detached nothing".
const (
	clearNet   = "net-a"
	clearIP1   = "10.0.7.11"
	clearIP2   = "10.0.7.12"
	clearIP3   = "10.0.7.13"
	clearMAC1  = "52:54:00:dd:00:01"
	clearMAC2  = "52:54:00:dd:00:02"
	clearMAC3  = "52:54:00:dd:00:03"
	clearStale = "10.0.7.99"
	// A second stale address, deliberately WITHOUT a lease record of any kind —
	// the permanently unprovable clear the mixed-pass test below needs.
	clearOrphan = "10.0.7.98"
)

// clearFixture is three mirrored VMs, one NIC each, each NIC holding one
// litevirt-owned NetBox address that is already correctly assigned.
//
// hydrateVMs and hydrateLeases say which halves of the local database have
// arrived: `vms` + `vm_interfaces` and `ip_allocations` respectively. Splitting
// them is the whole point — they are separate replicated tables repaired
// separately.
func clearFixture(t *testing.T, hydrateVMs, hydrateLeases bool) (*stubVirt, *Reconciler) {
	t.Helper()
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	fp := mustFingerprint(t, r)

	macs := []string{clearMAC1, clearMAC2, clearMAC3}
	ips := []string{clearIP1, clearIP2, clearIP3}
	for i := range macs {
		name := "vm-" + string(rune('1'+i))
		uuid := "uuid-" + string(rune('1'+i))
		if hydrateVMs {
			seedVMOnClearNet(t, r, name, uuid, macs[i], ips[i])
		}
		if hydrateLeases {
			seedLiveLease(t, r, ips[i], macs[i], name, 41+i)
		}
		nb.listVMs = append(nb.listVMs, netbox.VirtualMachine{
			ID: 11 + i, Name: name, ClusterID: 5, VCPUs: 2, MemoryMB: 1024, Status: "active",
			Identity: netbox.Identity(fp, uuid, ""),
		})
		nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
			ID: 21 + i, VMID: 11 + i, Name: "eth0", MAC: macs[i],
			Identity: netbox.Identity(fp, uuid, macs[i]),
		})
		nb.listIPs = append(nb.listIPs, netbox.IPAddress{
			ID: 41 + i, Address: ips[i] + "/24", AssignedObjectID: 21 + i,
			Identity: netbox.Identity(fp, uuid, macs[i]),
		})
	}
	return nb, r
}

// seedVMOnClearNet writes the `vms` + `vm_interfaces` rows one running VM leaves
// behind, with its NIC on the network the leases below are keyed to.
func seedVMOnClearNet(t *testing.T, r *Reconciler, name, uuid, mac, ip string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), r.db, corrosion.VMRecord{
		Name: name, HostName: "host-a", State: "running",
		Spec: `{"uuid":"` + uuid + `","cpu":2,"memory_mib":1024}`,
	}, []corrosion.InterfaceRecord{{
		VMName: name, NetworkName: clearNet, Ordinal: 0, MAC: mac, IP: ip,
	}}, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

// seedLiveLease writes the `ip_allocations` row the NetBox allocator leaves
// behind for one claimed address.
func seedLiveLease(t *testing.T, r *Reconciler, ip, mac, name string, netboxIPID int) {
	t.Helper()
	if err := r.db.Execute(context.Background(),
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'vm', 'host-a', ?, 7, ?, ?)`,
		clearNet, ip, mac, name, netboxIPID, r.db.NowWall(), r.db.NowTS()); err != nil {
		t.Fatalf("seed ip_allocations(%s): %v", ip, err)
	}
}

// seedReleasedLease claims a lease and then releases it through the PRODUCTION
// release path, which is what leaves a genuinely stale NetBox assignment behind.
//
// network.ReleaseLease, not a hand-written tombstone: the property this fixture
// rests on is that a release RETAINS netbox_ip_id on the tombstoned row, and
// writing the row by hand would assert that rather than exercise it.
func seedReleasedLease(t *testing.T, r *Reconciler, ip, mac, name string, netboxIPID int) {
	t.Helper()
	seedLiveLease(t, r, ip, mac, name, netboxIPID)
	if err := network.ReleaseLease(context.Background(), r.db,
		clearNet, ip, mac, "vm", "host-a", name); err != nil {
		t.Fatalf("ReleaseLease(%s): %v", ip, err)
	}
}

// TestUnhydratedLeasesDetachNoAddress is the CRITICAL case.
//
// Every `vms` and `vm_interfaces` row has arrived; not one `ip_allocations` row
// has. So the mirror resolves all three NICs to address 0, computes no delete at
// all — every VM and NIC is in the desired set — and, before this rule, cleared
// every litevirt-owned address in the cluster.
func TestUnhydratedLeasesDetachNoAddress(t *testing.T) {
	nb, r := clearFixture(t, true, false)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-destructive phases: %v", err)
	}

	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("an unhydrated `ip_allocations` detached addresses %v — a lease row that has "+
			"not replicated is not evidence that no lease of ours names the address", got)
	}
}

// TestUnhydratedLeasesSweepRecordsNoSuccess is the reporting half, and it is
// half the defect: the probe that detached three addresses ALSO stamped the
// success gauge and counted the sweep ok, which removes the only signal an
// operator has that anything is wrong.
func TestUnhydratedLeasesSweepRecordsNoSuccess(t *testing.T) {
	_, r := clearFixture(t, true, false)
	m := mirrorSink(t, r)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a pass that withheld unproven clears stamped a success at %v", ts)
	}
	if got := m.sweeps(); got[sweepOK] != 0 {
		t.Fatalf("sweep results = %v, want no ok result for a pass that did not converge", got)
	}
}

// TestHydratedLeasesConvergeUntouched is the control that stops the two above
// from being satisfied by a mirror that never clears and never converges.
//
// The identical fixture with `ip_allocations` hydrated: every address is where
// the lease says it should be, so a correct pass writes nothing, detaches
// nothing, and DOES stamp success.
func TestHydratedLeasesConvergeUntouched(t *testing.T) {
	nb, r := clearFixture(t, true, true)
	m := mirrorSink(t, r)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("a fully hydrated pass detached %v — every address matches its lease", got)
	}
	if ts := m.lastSuccess(); ts.IsZero() {
		t.Fatal("a pass that accounted for every NetBox object converged and must stamp the gauge")
	}
}

// TestWithheldDeleteWithholdsTheClearsToo is the whole-pass rule, and it is
// distinct from the per-object one above.
//
// One of the three VMs has reached this node, so the other two are withheld
// deletes — the pass has PROVEN its inventory read is partial. The stale address
// on the hydrated VM's interface is individually provable: its lease was
// released through the production path, so a tombstone naming address 99 is
// right there. Per-object evidence alone would therefore clear it. It must not,
// because the read the clear branch resolves addresses through is the one this
// pass just called partial.
func TestWithheldDeleteWithholdsTheClearsToo(t *testing.T) {
	nb, r := clearFixture(t, false, false)
	fp := mustFingerprint(t, r)
	// Only the first VM's rows have arrived, lease included.
	seedVMOnClearNet(t, r, "vm-1", "uuid-1", clearMAC1, clearIP1)
	seedLiveLease(t, r, clearIP1, clearMAC1, "vm-1", 41)
	// A genuinely stale address on that VM's interface, with the tombstone that
	// proves it stale.
	nb.listIPs = append(nb.listIPs, netbox.IPAddress{
		ID: 99, Address: clearStale + "/24", AssignedObjectID: 21,
		Identity: netbox.Identity(fp, "uuid-1", clearMAC1),
	})
	seedReleasedLease(t, r, clearStale, clearMAC1, "vm-1", 99)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-destructive phases: %v", err)
	}

	if got := cleared(nb); len(got) != 0 {
		t.Fatalf("a pass that withheld its deletes still detached %v — having proven the local "+
			"view partial, it may not run the destructive half of it", got)
	}
	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("deleted VMs %v and interfaces %v on a partially hydrated read", vms, ifaces)
	}
}

// TestProvenStaleAddressIsClearedWhenNothingIsWithheld is the control for the
// rule above: the same stale address, on a pass with nothing withheld, is
// detached. Without it the assertion above is satisfied by a mirror that stopped
// clearing altogether.
func TestProvenStaleAddressIsClearedWhenNothingIsWithheld(t *testing.T) {
	nb, r := clearFixture(t, true, true)
	fp := mustFingerprint(t, r)
	nb.listIPs = append(nb.listIPs, netbox.IPAddress{
		ID: 99, Address: clearStale + "/24", AssignedObjectID: 21,
		Identity: netbox.Identity(fp, "uuid-1", clearMAC1),
	})
	seedReleasedLease(t, r, clearStale, clearMAC1, "vm-1", 99)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := cleared(nb)
	if len(got) != 1 || got[0] != 99 {
		t.Fatalf("cleared %v, want exactly the address whose lease this cluster released", got)
	}
}

// TestMixedClearsWithholdOnlyTheUnprovableOne pins the ASYMMETRY between the two
// withheld ops, and nothing else in this package does.
//
// The whole-pass rule above is deliberately ONE-DIRECTIONAL: a withheld delete
// withholds the clears, but a withheld CLEAR does not escalate to the whole
// destructive list. The reasoning is on the `unprovenDeletes > 0` branch in
// Reconciler.sweep, and it is not a simplification — a withheld clear proves only
// that `ip_allocations` is partial, which says nothing about the three tables
// DELETE evidence reads. Escalating it would therefore protect no delete and no
// other clear, while letting ONE permanently-unprovable address withhold every
// clear in the cluster for as long as it exists.
//
// Every other clear test here is all-unprovable or all-provable, and neither
// shape can tell per-object withholding from whole-list escalation: rewriting
// that branch to the symmetric `unprovenDeletes+unprovenClears > 0` leaves all of
// them green. This pass is MIXED — two stale addresses on one interface, one
// carrying the released-lease tombstone that proves it and one with no lease
// record at all — so "the provable clear still runs" is the assertion, and the
// symmetric form is what fails it.
//
// The unprovable address is the shape an operator produces by hand: a NetBox
// object assigned to a litevirt-owned interface that this cluster never leased.
// No sweep can ever prove it, which is exactly why it must not be allowed to hold
// the other clear hostage.
func TestMixedClearsWithholdOnlyTheUnprovableOne(t *testing.T) {
	// Hydrated on BOTH halves, so the pass computes no delete at all and
	// deleteBlocker has nothing to say. The only destructive actions here are
	// the two clears below — which is what isolates the per-object rule.
	nb, r := clearFixture(t, true, true)
	fp := mustFingerprint(t, r)

	// PROVABLE: this cluster leased address 99 and released it through the
	// production path, so a tombstone retaining netbox_ip_id 99 is right there.
	nb.listIPs = append(nb.listIPs, netbox.IPAddress{
		ID: 99, Address: clearStale + "/24", AssignedObjectID: 21,
		Identity: netbox.Identity(fp, "uuid-1", clearMAC1),
	})
	seedReleasedLease(t, r, clearStale, clearMAC1, "vm-1", 99)

	// UNPROVABLE: no `ip_allocations` row of any kind names address 98. Same
	// interface as the provable one, so both are computed by the same diff and
	// run in the same phase of the same pass.
	nb.listIPs = append(nb.listIPs, netbox.IPAddress{
		ID: 98, Address: clearOrphan + "/24", AssignedObjectID: 21,
		Identity: netbox.Identity(fp, "uuid-1", clearMAC1),
	})

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the sweep must still run its non-destructive phases: %v", err)
	}

	got := cleared(nb)
	if len(got) != 1 || got[0] != 99 {
		t.Fatalf("cleared %v, want exactly [99]. An unprovable clear must withhold ITSELF and "+
			"nothing else. An EMPTY list here means the `unprovenDeletes > 0` branch in "+
			"Reconciler.sweep has been made symmetric over clears: that asymmetry is deliberate, "+
			"because a withheld clear proves only that `ip_allocations` is partial — which says "+
			"nothing about the tables delete evidence reads — so escalating it protects no delete "+
			"and no other clear, and lets one permanently-unprovable address withhold every clear "+
			"in the cluster forever", got)
	}

	// The pass computed no delete at all, so nothing may have been retired: the
	// assertion above must not be satisfiable by a pass that skipped the gate
	// and ran the whole destructive half unfiltered.
	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a pass that computed no delete retired VMs %v and interfaces %v", vms, ifaces)
	}
}
