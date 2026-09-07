package corrosion

import (
	"context"
	"testing"
)

// Why the NIC evidence union reads BOTH interface tables.
//
// KnowsNIC asks whether the local database holds a record of a (VM, MAC) — the
// proof the NetBox mirror needs before it may retire that interface object. It
// reads `vm_interfaces` and `vm_nics`, and the second one is not belt-and-braces
// for the first: on the commonest hotplug sequence it is the ONLY row left.
//
// `vm_interfaces` keys on (vm_name, network_name) and InsertInterface is an
// INSERT OR REPLACE, so re-attaching on the same network — which gets a freshly
// randomised MAC — overwrites the detached NIC's row in place, MAC and tombstone
// together. `vm_nics` keys on (vm_name, id) with the id derived from the MAC, so
// the two incarnations occupy different rows and the old one's tombstone
// survives.
//
// Drop `vm_nics` from the union and an ordinary detach-then-re-attach makes the
// old MAC unprovable, which permanently strands its NetBox interface: every
// sweep withholds the delete and the mirror never converges again.

// The MACs one detach-and-re-attach cycle on a single network uses.
const (
	evidenceMACFirst  = "52:54:00:e0:00:01"
	evidenceMACSecond = "52:54:00:e0:00:02"
)

// reattachedNIC drives the real sequence: a VM created with one NIC on one
// network, that NIC detached, then a new NIC attached on the SAME network with a
// different MAC — through the production write paths, because the overwrite this
// pins is a property of those statements' primary keys.
func reattachedNIC(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()

	nicID := DeterministicNICID("vm-1", evidenceMACFirst)
	if err := InsertVMWithHardware(ctx, c,
		VMRecord{Name: "vm-1", HostName: "host-a", State: "running", Spec: `{"uuid":"uuid-1"}`},
		[]InterfaceRecord{{VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACFirst}},
		nil,
		[]NICRecord{{VMName: "vm-1", ID: nicID, NetworkName: "net-a", MAC: evidenceMACFirst}},
		nil, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}

	// Detach: both NIC tables are tombstoned, which is what a hot-detach does.
	if err := SoftDeleteInterfaceByMAC(ctx, c, "vm-1", evidenceMACFirst); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}
	if err := TombstoneNIC(ctx, c, "vm-1", nicID); err != nil {
		t.Fatalf("TombstoneNIC: %v", err)
	}

	// Re-attach on the SAME network with a fresh MAC, exactly as the hotplug
	// attach path does.
	if err := InsertInterface(ctx, c, InterfaceRecord{
		VMName: "vm-1", NetworkName: "net-a", Ordinal: 0, MAC: evidenceMACSecond,
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	if err := UpsertNIC(ctx, c, NICRecord{
		VMName: "vm-1", ID: DeterministicNICID("vm-1", evidenceMACSecond),
		NetworkName: "net-a", MAC: evidenceMACSecond,
	}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
}

// TestReattachOverwritesTheLegacyInterfaceTombstone is the precondition, and
// without it the assertion below proves nothing: it establishes that
// `vm_interfaces` really has forgotten the first MAC.
func TestReattachOverwritesTheLegacyInterfaceTombstone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	reattachedNIC(t, c)

	rows, err := c.Query(ctx, `SELECT mac FROM vm_interfaces WHERE vm_name = 'vm-1'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("vm_interfaces holds %d rows for one (vm, network); INSERT OR REPLACE keys on "+
			"(vm_name, network_name), so there can only be one", len(rows))
	}
	if got := rows[0].String("mac"); got != evidenceMACSecond {
		t.Fatalf("vm_interfaces MAC = %q, want the re-attached one — this test's premise is that "+
			"the re-attach overwrote the detached NIC's row", got)
	}
}

// TestDetachedMACStaysProvableAfterReattach is the property the mirror's delete
// half depends on, and the mutation that catches `vm_nics` being dropped from
// the evidence union.
func TestDetachedMACStaysProvableAfterReattach(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	reattachedNIC(t, c)

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if !known.KnowsNIC("vm-1", evidenceMACFirst) {
		t.Fatal("the DETACHED MAC is no longer provable after a re-attach on the same network. " +
			"`vm_interfaces` overwrote its row, so only the `vm_nics` tombstone carries the " +
			"evidence — remove that table from the union and every re-attached NIC strands its " +
			"old NetBox interface forever")
	}
	if !known.KnowsNIC("vm-1", evidenceMACSecond) {
		t.Fatal("the live NIC must be provable too")
	}
	// The negative control: an evidence set that answered yes to everything
	// would satisfy both assertions above and authorize every delete.
	if known.KnowsNIC("vm-1", "52:54:00:e0:00:09") {
		t.Fatal("a MAC this cluster has never recorded must not be provable")
	}
}

// TestKnowsAddressNeedsALeaseRecord pins the clear half's evidence: a lease row
// of ANY kind naming a NetBox address proves it, and nothing else does.
//
// The tombstoned row is the important half — that is what a released lease
// leaves, and it is what makes a genuinely stale NetBox assignment provable
// rather than permanently withheld.
func TestKnowsAddressNeedsALeaseRecord(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('net-a', '10.0.9.1', ?, 'vm-1', 'vm', 'host-a', 41, 7, ?, ?)`,
		evidenceMACFirst, c.NowWall(), c.NowTS()); err != nil {
		t.Fatalf("seed live lease: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at, deleted_at)
		 VALUES ('net-a', '10.0.9.2', ?, 'vm-1', 'vm', 'host-a', 42, 7, ?, ?, ?)`,
		evidenceMACFirst, c.NowWall(), c.NowTS(), c.NowWall()); err != nil {
		t.Fatalf("seed released lease: %v", err)
	}
	// A builtin allocation has no NetBox object, so its row must contribute no
	// address evidence at all.
	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('net-b', '10.0.9.3', ?, 'vm-2', 'vm', 'host-a', ?, ?)`,
		evidenceMACSecond, c.NowWall(), c.NowTS()); err != nil {
		t.Fatalf("seed builtin lease: %v", err)
	}

	known, err := ReadMirrorEvidence(ctx, c)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	if !known.KnowsAddress(41) {
		t.Fatal("a live lease must prove its own address")
	}
	if !known.KnowsAddress(42) {
		t.Fatal("a RELEASED lease keeps its netbox_ip_id, and that tombstone is the only thing " +
			"that makes a genuinely stale NetBox assignment clearable")
	}
	if known.KnowsAddress(43) {
		t.Fatal("an address no lease row names must not be provable")
	}
	if known.KnowsAddress(0) {
		t.Fatal("address 0 is what a builtin lease and an unresolved lookup read back as; it " +
			"can never be evidence")
	}
}
