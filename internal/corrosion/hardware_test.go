package corrosion

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
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

// TestMergedVMNICs_HLCBeatsLegacyRFC3339 guards against a raw string comparison
// on updated_at in the overlay's winner-pick: once hlc_lww is enabled, updated_at
// is an HLC key ("<physms>-<logical>-<node>"), which sorts LEXICALLY BEFORE any
// legacy RFC3339 string (both start with digits, but "1..." < "2..."). A plain
// `>` comparison would therefore let a stale legacy vm_interfaces row beat a
// chronologically newer vm_nics HLC row, inverting the overlay. The comparison
// must go through lwwOrder, which compares by wall instant across formats.
func TestMergedVMNICs_HLCBeatsLegacyRFC3339(t *testing.T) {
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

	base := time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC)
	legacyTS := base.Format(time.RFC3339)
	// HLC row is an hour AFTER the legacy row's instant — chronologically newer —
	// but its string form still sorts lexically BEFORE legacyTS (premise below).
	hlcTS := hlc.Timestamp{PhysicalMS: base.Add(time.Hour).UnixMilli(), Logical: 0, NodeID: "n1"}.String()

	if !(legacyTS > hlcTS) {
		t.Fatalf("test premise wrong: expected legacy RFC3339 %q to sort lexically above HLC %q", legacyTS, hlcTS)
	}

	// Stale legacy vm_interfaces row.
	if err := c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, "legacy-net", 0, mac, "10.0.0.1", "", legacyTS); err != nil {
		t.Fatalf("insert legacy iface: %v", err)
	}

	// Newer vm_nics row (HLC updated_at).
	if err := c.Execute(ctx,
		`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, nicID, "new-net", "e1000", mac, 0, "10.0.0.2", "", "", hlcTS); err != nil {
		t.Fatalf("insert vm_nics row: %v", err)
	}

	got, err := MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(got) != 1 || got[0].NetworkName != "new-net" || got[0].Model != "e1000" || got[0].IP != "10.0.0.2" {
		t.Fatalf("chronologically newer vm_nics (HLC) row should win over stale legacy vm_interfaces row: %+v", got)
	}
}

// TestMergedVMNICs_MACCaseInsensitiveJoinKey guards against the overlay's join
// key using the raw, case-sensitive MAC string: if vm_interfaces and vm_nics
// disagree on MAC letter-case for the same physical NIC, a case-sensitive key
// groups them as two distinct NICs instead of one, so the overlay fails to
// merge and emits a duplicate. The join key must normalize case (the returned
// record's MAC field itself must NOT be mutated).
func TestMergedVMNICs_MACCaseInsensitiveJoinKey(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const vmName = "vm1"
	const macUpper = "AA:BB:CC:DD:EE:FF"
	const macLower = "aa:bb:cc:dd:ee:ff"
	nicID := DeterministicNICID(vmName, macLower)

	const t1 = "2026-01-01T00:00:00Z"
	const t2 = "2026-01-01T01:00:00Z"

	// Legacy vm_interfaces row, older, uppercase MAC.
	if err := c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, "old-net", 0, macUpper, "", "", t1); err != nil {
		t.Fatalf("insert legacy iface: %v", err)
	}

	// vm_nics row, newer, same physical NIC but lowercase MAC.
	if err := c.Execute(ctx,
		`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		vmName, nicID, "new-net", "e1000", macLower, 0, "", "", "", t2); err != nil {
		t.Fatalf("insert vm_nics row: %v", err)
	}

	got, err := MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("differing MAC letter-case across tables must merge to ONE NIC, got %d: %+v", len(got), got)
	}
	if got[0].NetworkName != "new-net" || got[0].MAC != macLower {
		t.Fatalf("winner should be the newer vm_nics row with its MAC unmutated: %+v", got[0])
	}
}
