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

// TestDeterministicPCIIntentID_NameIndependent proves the device_id is a pure
// function of (canonical_selector, occurrence) and carries NO VM name: the
// signature no longer takes one, so a VM rename (which changes only the VM
// name) cannot change the id, and the adoption audit's unconditional
// re-derive+upsert converges onto the same row instead of forking a duplicate.
// The (vm_name, device_id) PK already scopes the row per-VM, so cross-VM id
// equality is harmless. Distinct selectors must still not collide.
func TestDeterministicPCIIntentID_NameIndependent(t *testing.T) {
	sel := CanonicalPCISelector(&pb.DeviceSpec{Type: "gpu", Vendor: "10de"})
	if DeterministicPCIIntentID(sel, 0) != DeterministicPCIIntentID(sel, 0) {
		t.Fatal("id must be a stable pure function of (selector, occurrence)")
	}
	other := CanonicalPCISelector(&pb.DeviceSpec{Type: "nic"})
	if DeterministicPCIIntentID(sel, 0) == DeterministicPCIIntentID(other, 0) {
		t.Fatal("distinct selectors must not collide")
	}
}

// TestDeterministicPCIIntentID_OccurrenceDistinct guards that the occurrence
// ordinal is mixed into the id: two DeviceSpecs producing the identical
// canonical selector string (e.g. a VM requesting two GPUs by the same
// type-selector) must NOT collide on device_id — occurrence 0 and 1 must
// diverge, or the second attach could never be represented as a distinct
// vm_pci_intent row (same vm_name, same device_id PK).
func TestDeterministicPCIIntentID_OccurrenceDistinct(t *testing.T) {
	sel := CanonicalPCISelector(&pb.DeviceSpec{Type: "gpu"})
	if DeterministicPCIIntentID(sel, 0) == DeterministicPCIIntentID(sel, 1) {
		t.Fatal("identical selectors at different occurrence must differ")
	}
}

// TestCanonicalPCISelector_MappingIgnoresResolvedAddress proves a mapping
// selector's canonical form (and thus its id) is independent of the per-host
// resolved Address — a resolution artifact copied back onto the spec. Two
// mapping specs for the same pool that resolved to different BDFs on different
// hosts must derive the SAME id, or a re-resolve on another host would fork a
// duplicate intent row.
func TestCanonicalPCISelector_MappingIgnoresResolvedAddress(t *testing.T) {
	a := CanonicalPCISelector(&pb.DeviceSpec{Mapping: "gpu-pool", Address: "0000:41:00.0"})
	b := CanonicalPCISelector(&pb.DeviceSpec{Mapping: "gpu-pool", Address: "0000:42:00.0"})
	if a != b {
		t.Fatalf("mapping canonical selector must ignore the resolved Address: %q != %q", a, b)
	}
	if DeterministicPCIIntentID(a, 0) != DeterministicPCIIntentID(b, 0) {
		t.Fatal("mapping id must not depend on the resolved Address")
	}
}

// TestCanonicalPCISelector_TypeIgnoresAddress proves a type/vendor selector's
// canonical form ignores a resolved Address, for the same reason as mapping: a
// portable selector's id must be stable across host re-resolution.
func TestCanonicalPCISelector_TypeIgnoresAddress(t *testing.T) {
	a := CanonicalPCISelector(&pb.DeviceSpec{Type: "gpu", Address: "0000:41:00.0"})
	b := CanonicalPCISelector(&pb.DeviceSpec{Type: "gpu"})
	if a != b {
		t.Fatalf("type canonical selector must ignore Address: %q != %q", a, b)
	}
	if DeterministicPCIIntentID(a, 0) != DeterministicPCIIntentID(b, 0) {
		t.Fatal("type id must not depend on a resolution-artifact Address")
	}
}

// TestCanonicalPCISelector_ConcreteAddressNormalized proves a concrete-address
// selector folds non-canonical BDF forms (short form, letter-case, whitespace)
// to one id, and that ClassifyPCISelector's address-kind exclusive_key is the
// SAME normalized BDF — so the same physical device yields both the same id AND
// the same exclusive reservation regardless of the input form.
func TestCanonicalPCISelector_ConcreteAddressNormalized(t *testing.T) {
	short := &pb.DeviceSpec{Address: "41:00.0"}
	full := &pb.DeviceSpec{Address: "0000:41:00.0"}
	if CanonicalPCISelector(short) != CanonicalPCISelector(full) {
		t.Fatalf("non-canonical BDF must canonicalize: %q != %q",
			CanonicalPCISelector(short), CanonicalPCISelector(full))
	}
	if DeterministicPCIIntentID(CanonicalPCISelector(short), 0) != DeterministicPCIIntentID(CanonicalPCISelector(full), 0) {
		t.Fatal("short and full BDF forms must derive the same id")
	}
	_, ekShort := ClassifyPCISelector(short)
	_, ekFull := ClassifyPCISelector(full)
	if ekShort == nil || ekFull == nil || *ekShort != *ekFull || *ekShort != "0000:41:00.0" {
		t.Fatalf("address exclusive_key must be the normalized BDF for both forms: %v / %v", ekShort, ekFull)
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
	deviceID := DeterministicPCIIntentID(sel, 0)

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
	pDeviceID := DeterministicPCIIntentID(pSel, 0)
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

// assertDistinctPCIIntentIDs fails t unless a and b — which must classify to
// the same selector_kind, since this helper is only used to guard WITHIN-kind
// discrimination — derive different device_ids.
func assertDistinctPCIIntentIDs(t *testing.T, label string, a, b *pb.DeviceSpec) {
	t.Helper()
	idA := DeterministicPCIIntentID(CanonicalPCISelector(a), 0)
	idB := DeterministicPCIIntentID(CanonicalPCISelector(b), 0)
	if idA == idB {
		t.Fatalf("%s: distinct specs collapsed onto the same device_id %q (a=%+v b=%+v) — a semantic field is missing from this kind's canonical selector", label, idA, a, b)
	}
}

// TestCanonicalPCISelector_DiscriminatesSemanticFields pins the per-kind
// canonical-selector field-set COMPLETENESS: within a kind, two DeviceSpecs
// that differ ONLY by a resolution-DETERMINING field must derive DIFFERENT
// device_ids. This is the guard the id-primitive tests above don't provide —
// they prove a resolution ARTIFACT (Address on a portable selector) is
// correctly EXCLUDED, but nothing previously pinned that every semantic field
// is INCLUDED. A future edit that dropped a field from one kind's branch in
// CanonicalPCISelector (e.g. Vendor from the type/vendor branch) would compile
// and pass every existing test while silently collapsing two distinct devices
// onto the same device_id — a fleet-wide id-divergence / dropped-device bug.
//
// Only id INEQUALITY is asserted, never the literal canonical string (the
// scheme is deliberately not string-pinned — see CanonicalPCISelector's doc
// comment).
func TestCanonicalPCISelector_DiscriminatesSemanticFields(t *testing.T) {
	t.Run("type/vendor kind", func(t *testing.T) {
		assertDistinctPCIIntentIDs(t, "vendor",
			&pb.DeviceSpec{Type: "gpu", Vendor: "10de"}, &pb.DeviceSpec{Type: "gpu", Vendor: "8086"})
		assertDistinctPCIIntentIDs(t, "model",
			&pb.DeviceSpec{Type: "gpu", Model: "a"}, &pb.DeviceSpec{Type: "gpu", Model: "b"})
		assertDistinctPCIIntentIDs(t, "count",
			&pb.DeviceSpec{Type: "gpu", Count: 1}, &pb.DeviceSpec{Type: "gpu", Count: 2})
	})

	t.Run("sriov kind", func(t *testing.T) {
		assertDistinctPCIIntentIDs(t, "parent",
			&pb.DeviceSpec{Sriov: true, Parent: "0000:41:00.0"}, &pb.DeviceSpec{Sriov: true, Parent: "0000:42:00.0"})
		assertDistinctPCIIntentIDs(t, "type",
			&pb.DeviceSpec{Sriov: true, Type: "nic"}, &pb.DeviceSpec{Sriov: true, Type: "gpu"})
		assertDistinctPCIIntentIDs(t, "count",
			&pb.DeviceSpec{Sriov: true, Count: 1}, &pb.DeviceSpec{Sriov: true, Count: 2})
	})

	t.Run("mapping kind", func(t *testing.T) {
		assertDistinctPCIIntentIDs(t, "mapping name",
			&pb.DeviceSpec{Mapping: "pool-a"}, &pb.DeviceSpec{Mapping: "pool-b"})
	})

	// Cross-kind: already collision-proof by construction (each branch is
	// kind-prefixed), but locked here so a future change can't quietly erode
	// the kind prefix and let two different kinds' selectors collide.
	t.Run("cross-kind", func(t *testing.T) {
		specs := map[string]*pb.DeviceSpec{
			"mapping": {Mapping: "x"},
			"type":    {Type: "x"},
			"sriov":   {Sriov: true},
			"address": {Address: "0000:41:00.0"},
		}
		seenBy := make(map[string]string, len(specs))
		for kind, spec := range specs {
			id := DeterministicPCIIntentID(CanonicalPCISelector(spec), 0)
			if other, ok := seenBy[id]; ok {
				t.Fatalf("cross-kind collision: kinds %q and %q share device_id %q", kind, other, id)
			}
			seenBy[id] = kind
		}
	})
}
