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
