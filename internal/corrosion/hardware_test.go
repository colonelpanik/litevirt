package corrosion

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
)

// TestClassifyPCISelector_Precedence guards the selector-kind classification
// order (mapping → sriov → type/vendor → address) and the rule that
// exclusive_key — the host-pinning field — is populated ONLY for kind
// "address". A mapping-classified spec that happens to also carry a resolved
// Address (a resolution artifact, not a request) must NOT host-pin: its
// exclusive_key must be nil even though Address is set.
func TestClassifyPCISelector_Precedence(t *testing.T) {
	// mapping+resolved-address → "mapping", nil exclusive_key (not host-pinned)
	k, ek := ClassifyPCISelector(&pb.DeviceSpec{Mapping: "gpu-pool", Address: "0000:41:00.0"})
	if k != "mapping" || ek != nil {
		t.Fatalf("mapping misclassified: kind=%q ek=%v", k, ek)
	}
	// pure address → "address", exclusive_key set (normalized)
	k, ek = ClassifyPCISelector(&pb.DeviceSpec{Address: "0000:41:00.0"})
	if k != "address" || ek == nil || *ek != "0000:41:00.0" {
		t.Fatalf("address misclassified: kind=%q ek=%v", k, ek)
	}
	// sriov beats type/vendor and address.
	k, ek = ClassifyPCISelector(&pb.DeviceSpec{Sriov: true, Vendor: "10de", Address: "0000:41:00.0"})
	if k != "sriov" || ek != nil {
		t.Fatalf("sriov misclassified: kind=%q ek=%v", k, ek)
	}
	// type/vendor beats address.
	k, ek = ClassifyPCISelector(&pb.DeviceSpec{Type: "gpu", Address: "0000:41:00.0"})
	if k != "type" || ek != nil {
		t.Fatalf("type misclassified: kind=%q ek=%v", k, ek)
	}
	k, ek = ClassifyPCISelector(&pb.DeviceSpec{Vendor: "10de"})
	if k != "type" || ek != nil {
		t.Fatalf("vendor-only misclassified: kind=%q ek=%v", k, ek)
	}
}

// TestDeterministicPCIIntentID_OccurrenceDistinct guards that the occurrence
// ordinal is mixed into the id: two DeviceSpecs producing the identical
// canonical selector string (e.g. a VM requesting two GPUs by the same
// type-selector) must NOT collide on device_id — occurrence 0 and 1 must
// diverge, or the second attach could never be represented as a distinct
// vm_pci_intent row (same vm_name, same device_id PK).
func TestDeterministicPCIIntentID_OccurrenceDistinct(t *testing.T) {
	sel := "type=gpu"
	if DeterministicPCIIntentID("vm1", sel, 0) == DeterministicPCIIntentID("vm1", sel, 1) {
		t.Fatal("identical selectors at different occurrence must differ")
	}
}

// TestDeterministicPCIIntentID_StableAndDistinct guards that the id is a pure
// function of its inputs (required for cross-peer convergence) and that
// distinct vm/selector inputs do not collide.
func TestDeterministicPCIIntentID_StableAndDistinct(t *testing.T) {
	a := DeterministicPCIIntentID("vm1", "type=gpu", 0)
	b := DeterministicPCIIntentID("vm1", "type=gpu", 0)
	if a != b {
		t.Fatalf("id not stable: %q != %q", a, b)
	}
	if DeterministicPCIIntentID("vm2", "type=gpu", 0) == a {
		t.Fatal("distinct vm_name collided")
	}
	if DeterministicPCIIntentID("vm1", "type=nic", 0) == a {
		t.Fatal("distinct selector collided")
	}
}

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

// TestUpsertAndListPCIIntent round-trips UpsertPCIIntent/ListVMPCIIntents
// through a real vm_pci_intent row (built via ClassifyPCISelector +
// CanonicalPCISelector + DeterministicPCIIntentID, the way a real caller
// would), then TombstonePCIIntent and confirms the live-only list hides it.
func TestUpsertAndListPCIIntent(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const vmName = "vm1"
	spec := &pb.DeviceSpec{Address: "0000:41:00.0"}
	kind, exclusiveKey := ClassifyPCISelector(spec)
	sel := CanonicalPCISelector(spec)
	deviceID := DeterministicPCIIntentID(vmName, sel, 0)

	rec := PCIIntentRecord{
		VMName:          vmName,
		DeviceID:        deviceID,
		HostName:        "host1",
		SelectorKind:    kind,
		SelectorPayload: sel,
		ExclusiveKey:    exclusiveKey,
	}
	if err := UpsertPCIIntent(ctx, c, rec); err != nil {
		t.Fatalf("UpsertPCIIntent: %v", err)
	}

	got, err := ListVMPCIIntents(ctx, c, vmName)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListVMPCIIntents: %v (n=%d)", err, len(got))
	}
	if got[0].DeviceID != deviceID || got[0].HostName != "host1" || got[0].SelectorKind != "address" {
		t.Fatalf("bad row: %+v", got[0])
	}
	if got[0].ExclusiveKey == nil || *got[0].ExclusiveKey != "0000:41:00.0" {
		t.Fatalf("exclusive_key not round-tripped: %v", got[0].ExclusiveKey)
	}

	// A portable (non-address) selector must round-trip a nil ExclusiveKey —
	// the column must actually be persisted as SQL NULL, not the string "".
	portableSpec := &pb.DeviceSpec{Type: "gpu"}
	pKind, pKey := ClassifyPCISelector(portableSpec)
	pSel := CanonicalPCISelector(portableSpec)
	pDeviceID := DeterministicPCIIntentID(vmName, pSel, 0)
	if err := UpsertPCIIntent(ctx, c, PCIIntentRecord{
		VMName: vmName, DeviceID: pDeviceID, HostName: "host1",
		SelectorKind: pKind, SelectorPayload: pSel, ExclusiveKey: pKey,
	}); err != nil {
		t.Fatalf("UpsertPCIIntent (portable): %v", err)
	}
	got, err = ListVMPCIIntents(ctx, c, vmName)
	if err != nil || len(got) != 2 {
		t.Fatalf("ListVMPCIIntents after second insert: %v (n=%d)", err, len(got))
	}
	for _, r := range got {
		if r.DeviceID == pDeviceID {
			if r.SelectorKind != "type" || r.ExclusiveKey != nil {
				t.Fatalf("portable row should have nil exclusive_key: %+v", r)
			}
		}
	}

	// Tombstone the address-selector intent; the live-only list must hide it
	// while leaving the portable one visible.
	if err := TombstonePCIIntent(ctx, c, vmName, deviceID); err != nil {
		t.Fatalf("TombstonePCIIntent: %v", err)
	}
	got, err = ListVMPCIIntents(ctx, c, vmName)
	if err != nil || len(got) != 1 || got[0].DeviceID != pDeviceID {
		t.Fatalf("tombstoned intent should be hidden from the live-only list: %v (got=%+v)", err, got)
	}
}

// TestUpsertAndListPCIRealization round-trips UpsertPCIRealization/
// ListVMPCIRealizations across multiple members of the same intent (e.g. an
// SR-IOV VF-pool realizing as several VFs), then TombstonePCIRealizations
// and confirms it retracts EVERY member for that device_id, not just one.
func TestUpsertAndListPCIRealization(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const vmName = "vm1"
	const deviceID = "deadbeefdeadbeefdeadbeefdeadbeef"

	if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{
		VMName: vmName, DeviceID: deviceID, MemberID: "m0",
		HostName: "host1", ResolvedAddress: "0000:41:00.0", XMLAlias: "hostdev0", Ordinal: 0,
	}); err != nil {
		t.Fatalf("UpsertPCIRealization m0: %v", err)
	}
	if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{
		VMName: vmName, DeviceID: deviceID, MemberID: "m1",
		HostName: "host1", ResolvedAddress: "0000:41:00.1", XMLAlias: "hostdev1", Ordinal: 1,
	}); err != nil {
		t.Fatalf("UpsertPCIRealization m1: %v", err)
	}

	got, err := ListVMPCIRealizations(ctx, c, vmName)
	if err != nil || len(got) != 2 {
		t.Fatalf("ListVMPCIRealizations: %v (n=%d)", err, len(got))
	}
	byMember := map[string]PCIRealizationRecord{}
	for _, r := range got {
		byMember[r.MemberID] = r
	}
	if byMember["m0"].ResolvedAddress != "0000:41:00.0" || byMember["m0"].Ordinal != 0 {
		t.Fatalf("bad m0 row: %+v", byMember["m0"])
	}
	if byMember["m1"].XMLAlias != "hostdev1" || byMember["m1"].Ordinal != 1 {
		t.Fatalf("bad m1 row: %+v", byMember["m1"])
	}

	if err := TombstonePCIRealizations(ctx, c, vmName, deviceID); err != nil {
		t.Fatalf("TombstonePCIRealizations: %v", err)
	}
	got, err = ListVMPCIRealizations(ctx, c, vmName)
	if err != nil || len(got) != 0 {
		t.Fatalf("TombstonePCIRealizations must retract every member: %v (got=%+v)", err, got)
	}
}
