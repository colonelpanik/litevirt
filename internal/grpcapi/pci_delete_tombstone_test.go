package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-21: a VM delete whose strict whole-VM PCI release cannot unbind a device must FAIL
// BEFORE tombstoning — never log-and-complete. Completing tombstoned the vms row while
// host_pci_devices.vm_name still referenced the now-deleted VM: a stale owner that blocks
// every future ClaimPCIDevice CAS on that BDF forever (a manual driver_override reset does
// NOT clear the DB ownership). releaseDevices stays strict all-or-nothing (never leaves an
// unowned-but-vfio-bound device); the delete just no longer proceeds over its error, so it
// is fully retryable — the only prior destructive step is DestroyDomain (VM stopped), which
// a retry tolerates.

// TestDeleteVM_PCIReleaseFails_FailsBeforeTombstone: a VM owning a vfio-bound device whose
// unbind is stuck. The delete must return an error, leave the vms row intact (not tombstoned),
// leave the device OWNED by the still-existing VM (no stale owner of a deleted VM, no unowned+
// bound orphan), and leave the domain still defined (nothing irreversible ran before the
// release). RED before the fix (delete logged the unbind failure, completed, and tombstoned
// the row → stale owner of a deleted VM).
func TestDeleteVM_PCIReleaseFails_FailsBeforeTombstone(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	fs.setBound(addr)
	fs.setFailUnbind(addr)

	// (a) The delete FAILS (never completes over an unreleasable device). A normal
	// (non-keep-disks) delete so the whole tombstone/undefine/disk-teardown tail is what
	// the fix must skip.
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("delete must FAIL when a PCI device cannot be released (never tombstone over it)")
	}

	// (b) The vms row is NOT tombstoned — the delete is retryable.
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil {
		t.Fatal("a failed PCI release must NOT tombstone the VM row (delete must be retryable)")
	}
	// (c) The device is still OWNED by the (still-existing) VM AND bound — no stale owner of
	// a deleted VM, and no unowned-but-vfio-bound orphan.
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("device must stay OWNED by vm1 (no stale owner, no unowned+bound), got owner %q", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound (owned + bound, recoverable)")
	}
	// (d) The domain was NOT undefined — nothing irreversible ran before the PCI release.
	if !s.virt.(*libvirtfake.Fake).DomainExists("vm1") {
		t.Fatal("delete must NOT undefine the domain before the PCI release succeeds")
	}
}

// TestDeleteVM_PCIReleaseSucceedsOnRetry_Completes (convergence): after a delete that FAILED
// because a device could not be unbound, clearing the stuck condition and retrying must now
// COMPLETE — the strict release succeeds, ownership is cleared, the device is unbound, and the
// vms row is tombstoned. Proves the fail-before-tombstone semantics are fully retryable.
func TestDeleteVM_PCIReleaseSucceedsOnRetry_Completes(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	fs.setBound(addr)
	fs.setFailUnbind(addr)

	// First delete fails on the stuck unbind (row retained, device still owned + bound).
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("precondition: the first delete must fail on the stuck unbind")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil {
		t.Fatal("precondition: the failed delete must retain the VM row")
	}

	// Operator resolves the stuck device; retry the delete.
	fs.clearFailUnbind(addr)
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("retry after resolving the device must complete the delete: %v", err)
	}

	// The delete completed: row tombstoned, device released + unbound (no stale owner).
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm != nil {
		t.Fatal("the successful retry must tombstone the VM row")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("the successful retry must release device ownership, got owner %q", o)
	}
	if fs.isBound(addr) {
		t.Fatal("the successful retry must vfio-unbind the device")
	}
}

// TestDeleteVM_PCIReleasable_Completes (happy path): a delete whose PCI device releases cleanly
// still completes normally — releaseDevices unbinds + releases and the vms row is tombstoned.
// Guards that the fail-before-tombstone gate does not block the ordinary delete path.
func TestDeleteVM_PCIReleasable_Completes(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	fs.setBound(addr) // bound but releasable (no unbind fault)

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("a releasable-PCI delete must complete: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm != nil {
		t.Fatal("delete must tombstone the VM row")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("delete must release the device, got owner %q", o)
	}
	if fs.isBound(addr) {
		t.Fatal("delete must vfio-unbind the released device")
	}
}
