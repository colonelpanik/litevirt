package corrosion

import (
	"context"
	"testing"
)

func TestDeterministicNICID_StableAndDistinct(t *testing.T) {
	a := DeterministicNICID("vm1", "52:54:00:aa:bb:cc")
	b := DeterministicNICID("vm1", "52:54:00:aa:bb:cc")
	c := DeterministicNICID("vm1", "52:54:00:aa:bb:dd")
	if a != b {
		t.Fatalf("id not stable: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("distinct MACs collided: %q", a)
	}
}

func TestUpsertAndGetNIC(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	r := NICRecord{VMName: "vm1", ID: DeterministicNICID("vm1", "52:54:00:aa:bb:cc"),
		NetworkName: "default", Model: "virtio", MAC: "52:54:00:aa:bb:cc", Ordinal: 0}
	if err := UpsertNIC(ctx, c, r); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
	got, err := GetVMNICsRaw(ctx, c, "vm_nics", "vm1")
	if err != nil || len(got) != 1 {
		t.Fatalf("GetVMNICsRaw: %v (n=%d)", err, len(got))
	}
	if got[0].Model != "virtio" || got[0].MAC != "52:54:00:aa:bb:cc" {
		t.Fatalf("bad row: %+v", got[0])
	}
}

// TestMergedVMNICs_OverlayTieAndTombstone exercises the vm_nics/vm_interfaces
// overlay rule end to end: greatest-updated_at wins, an exact tie prefers the
// vm_nics row, and the winner is only visible when its deleted_at is empty.
// Rows are written directly via c.Execute (the same exec the accessors use) so
// updated_at/deleted_at are fully controlled — UpsertNIC's c.NowTS() is
// monotonic-increasing and can't produce a controlled tie or backdated tombstone.
func TestMergedVMNICs_OverlayTieAndTombstone(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const vmName = "vm1"
	const mac = "52:54:00:aa:bb:cc"
	nicID := DeterministicNICID(vmName, mac)

	const t1 = "2026-01-01T00:00:00.000000000Z"
	const t2 = "2026-01-01T00:00:01.000000000Z"
	const t3 = "2026-01-01T00:00:02.000000000Z"

	// Legacy vm_interfaces row, live, at T1.
	if err := c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, "default", 0, mac, "", "", t1); err != nil {
		t.Fatalf("insert legacy iface: %v", err)
	}

	// vm_nics row, live, at the SAME updated_at T1 (exact tie). vm_nics must win
	// the tie over the legacy row.
	if err := c.Execute(ctx,
		`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, nicID, "default", "e1000", mac, 0, "", "", "", t1); err != nil {
		t.Fatalf("insert vm_nics tie row: %v", err)
	}

	got, err := MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(got) != 1 || got[0].Model != "e1000" {
		t.Fatalf("exact tie should prefer the vm_nics row: %+v", got)
	}

	// vm_nics row tombstoned at T2 (strictly later than the legacy row's T1) — the
	// overlay picks the vm_nics row as the winner (greatest updated_at) but must
	// hide it because its deleted_at is set.
	if err := c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vmName, nicID, "default", "e1000", mac, 0, "", "", "", t2, t2); err != nil {
		t.Fatalf("tombstone vm_nics row: %v", err)
	}

	got, err = MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs after tombstone: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("tombstoned winner must hide the NIC: %+v", got)
	}

	// vm_nics row live again at T3 (latest) — the NIC becomes visible again with
	// the newest field values.
	if err := c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, nicID, "default", "virtio", mac, 0, "10.0.0.5", "tap0", "", t3); err != nil {
		t.Fatalf("revive vm_nics row: %v", err)
	}

	got, err = MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs after revive: %v", err)
	}
	if len(got) != 1 || got[0].Model != "virtio" || got[0].IP != "10.0.0.5" {
		t.Fatalf("revived NIC should be visible with latest fields: %+v", got)
	}
}
