package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// mustGetVM reads back a VM record with its full (F1) column set, failing the
// test if it's missing.
func mustGetVM(t *testing.T, s *Server, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): err=%v nil=%v", name, err, vm == nil)
	}
	return vm
}

// TestUpdateVM_HotplugDiskSurvivesRedefine is the production disk-drop
// regression: a stopped VM whose stored spec.Disks lists ONLY the root disk, but
// whose vm_disks table also carries a hotplug-added data disk (written only to
// vm_disks, never back into the spec blob). A full-regeneration redefine (here a
// cpu change) must NOT drop the hotplug-added disk.
func TestUpdateVM_HotplugDiskSurvivesRedefine(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp1", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{
			Name: "hp1", Cpu: 2, MemoryMib: 4096,
			Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		}))
	// vm_disks carries BOTH the root disk and a hotplug-added data disk.
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "hp1", DiskName: "root", HostName: "test-host",
		Path: "/x/hp1-root.qcow2", DeviceKind: "disk", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "hp1", DiskName: "data1", HostName: "test-host",
		Path: "/x/hp1-data1.qcow2", DeviceKind: "disk", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1: %v", err)
	}

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp1", Cpu: 4}); err != nil {
		t.Fatalf("redefine: %v", err)
	}
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("hp1")
	if !strings.Contains(xml, "hp1-data1.qcow2") {
		t.Fatalf("hotplug-added disk dropped from UpdateVM redefine:\n%s", xml)
	}
	// The root disk (in spec) must of course still be present too.
	if !strings.Contains(xml, "hp1-root.qcow2") {
		t.Fatalf("root disk missing from redefine:\n%s", xml)
	}
}

// TestReconcile_HotplugDiskSurvivesRedefine exercises the reconcile primitive
// directly: with no prior inactive XML it first-defines the domain from the
// authoritative vm_disks rows (root + a hotplug-added data disk), so neither
// disk is dropped even though the spec blob lists only root.
func TestReconcile_HotplugDiskSurvivesRedefine(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "vm1", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{
			Name: "vm1", Cpu: 2, MemoryMib: 4096,
			Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		}))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "test-host",
		Path: "/x/root.qcow2", DeviceKind: "disk", Bus: "virtio", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path: "/x/data1.qcow2", DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1: %v", err)
	}

	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "vm1"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	if !strings.Contains(xml, "data1.qcow2") {
		t.Fatalf("hotplug-added disk dropped from redefine:\n%s", xml)
	}
	if !strings.Contains(xml, "root.qcow2") {
		t.Fatalf("root disk missing from redefine:\n%s", xml)
	}
}

// seedOwnedPCI inserts an unassigned host_pci_devices inventory row (IOMMU group
// -1 so it has no siblings that would expand a single-address resolve into extra
// members) and claims it for vmName — the ownership state CreateVM or a legacy
// SR-IOV/type attach leaves behind, with NO accompanying vm_pci_intent.
func seedOwnedPCI(t *testing.T, ctx context.Context, s *Server, addr, vmName string) {
	t.Helper()
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: addr, Type: "gpu", IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("observe %s: %v", addr, err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, "test-host", addr, vmName); err != nil || !ok {
		t.Fatalf("claim %s: ok=%v err=%v", addr, ok, err)
	}
}

// xmlAttrPresent reports whether attr=val (either quote style) appears in the XML;
// GenerateDomainXML marshals double-quoted, the patch path preserves single quotes.
func xmlAttrPresent(xmlText, attr, val string) bool {
	return strings.Contains(xmlText, attr+`="`+val+`"`) || strings.Contains(xmlText, attr+`='`+val+`'`)
}

// TestReconcile_MixedIntentAndOwnershipPCIPreservesBoth is the union regression: a
// VM that owns one passthrough device via an OWNERSHIP row ALONE (a legacy
// SR-IOV/type or CreateVM attach — NO vm_pci_intent) AND carries a journaled
// concrete-address intent (+realization) for a DIFFERENT device must keep BOTH
// hostdevs in its reconciled definition. The old PCI section was mutually
// exclusive: any intent made it resolve ONLY intents and ignore ownership, so the
// legacy device was silently dropped on the next intent-branch reconcile (a VM
// losing its GPU on next boot). checkRealizationCardinality can't catch it (the
// dropped device has no realization). The device that carries BOTH an intent and
// an ownership row (same BDF, the normal post-backfill state) is emitted once.
func TestReconcile_MixedIntentAndOwnershipPCIPreservesBoth(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "mix", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "mix", Cpu: 4, MemoryMib: 4096, Machine: "q35"}))

	const legacyBDF = "0000:02:00.0" // owned-only, NO intent (the drop-prone device)
	const intentBDF = "0000:41:00.0" // journaled: intent + realization + ownership row

	// (a) Legacy ownership-only device — observed + claimed, NO vm_pci_intent.
	seedOwnedPCI(t, ctx, s, legacyBDF, "mix")
	// (b) Journaled device — ALSO owned (the normal post-backfill state), so its
	// intent and its ownership row resolve to the SAME BDF, exercising dedup.
	seedOwnedPCI(t, ctx, s, intentBDF, "mix")

	const deviceID = "dev-intent"
	ek := intentBDF
	if err := corrosion.UpsertPCIIntent(ctx, s.db, corrosion.PCIIntentRecord{
		VMName: "mix", DeviceID: deviceID, HostName: "test-host",
		SelectorKind: "address", ExclusiveKey: &ek,
		SelectorPayload: `{"address":"` + intentBDF + `"}`,
	}); err != nil {
		t.Fatalf("upsert intent: %v", err)
	}
	if err := corrosion.UpsertPCIRealization(ctx, s.db, corrosion.PCIRealizationRecord{
		VMName: "mix", DeviceID: deviceID, MemberID: "m0", HostName: "test-host",
		ResolvedAddress: intentBDF, XMLAlias: pciMemberAlias(deviceID, "m0"), Ordinal: 0,
	}); err != nil {
		t.Fatalf("upsert realization: %v", err)
	}

	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "mix"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("mix")

	// The legacy owned-only device MUST survive the union (RED before the fix:
	// the intent branch dropped it).
	if !xmlAttrPresent(xml, "bus", "0x02") {
		t.Fatalf("legacy ownership-only PCI device %s dropped from reconciled XML:\n%s", legacyBDF, xml)
	}
	// The journaled device is present too, carrying its intent alias.
	alias := pciMemberAlias(deviceID, "m0")
	if !hostdevAliasInXML(xml, alias) {
		t.Fatalf("journaled intent hostdev alias %s absent from reconciled XML:\n%s", alias, xml)
	}
	if !xmlAttrPresent(xml, "bus", "0x41") {
		t.Fatalf("journaled intent PCI device %s absent from reconciled XML:\n%s", intentBDF, xml)
	}
	// Dedup: the device with BOTH an intent and an ownership row is emitted ONCE
	// (its alias appears a single time), not duplicated.
	if n := strings.Count(xml, alias); n != 1 {
		t.Fatalf("intent+ownership device duplicated: alias %s appears %d times, want 1:\n%s", alias, n, xml)
	}
	// Exactly two <hostdev>s total (legacy + journaled), no phantom third.
	if n := strings.Count(xml, "<hostdev"); n != 2 {
		t.Fatalf("want exactly 2 hostdevs (legacy + journaled), got %d:\n%s", n, xml)
	}
}

// TestReconcile_NoopPreservesTopology asserts the topology-preserving patch path:
// a stopped VM whose inactive XML already has libvirt-assigned addresses/aliases,
// reconciled against the SAME desired device set, keeps those addresses and
// aliases byte-for-byte (only <source> may be rewritten — here it's unchanged).
func TestReconcile_NoopPreservesTopology(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "topo", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "topo", Cpu: 2, MemoryMib: 4096}))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "topo", DiskName: "root", HostName: "test-host",
		Path: "/d/topo-root.qcow2", DeviceKind: "disk", Bus: "virtio", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root: %v", err)
	}

	// Prior inactive XML with an assigned PCI address + a stable alias on the disk.
	prior := `<domain type='kvm'>
  <name>topo</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/d/topo-root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      <alias name='ua-disk-root'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x09' function='0x0'/>
    </disk>
  </devices>
</domain>`
	if err := s.virt.DefineDomain(prior); err != nil {
		t.Fatalf("seed prior domain: %v", err)
	}

	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "topo"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := s.virt.(*libvirtfake.Fake).DefinedXML("topo")
	if !strings.Contains(got, "slot='0x09' function='0x0'") {
		t.Fatalf("PatchInactiveDevices reshuffled the PCI address (should be preserved verbatim):\n%s", got)
	}
	if !strings.Contains(got, "ua-disk-root") {
		t.Fatalf("PatchInactiveDevices dropped the disk alias (should be preserved verbatim):\n%s", got)
	}
	if !strings.Contains(got, "/d/topo-root.qcow2") {
		t.Fatalf("disk source lost on no-op reconcile:\n%s", got)
	}
}
