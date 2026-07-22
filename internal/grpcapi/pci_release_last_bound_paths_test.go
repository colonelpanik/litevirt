package grpcapi

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// TestDetachPCI_LegacyUnbindFails_NotUnownedBound is FIX-18 ESCAPE 1: the legacy
// running-detach path (detachPCIDevice), reached when a PCI address backs no live
// address-kind intent — an SR-IOV/type/vendor/mapping-selected or CreateVM-owned
// device — must NOT release ownership when the post-detach vfio unbind fails. The
// device is vfio-bound at detach, so a warn-only unbind + unconditional
// ReleasePCIDevice left it UNOWNED-but-vfio-BOUND (an orphan). The strict primitive
// must instead retain ownership (still bound) and fail the RPC so a retry converges.
// RED before the fix: ReleasePCIDevice fired regardless of the unbind outcome.
func TestDetachPCI_LegacyUnbindFails_NotUnownedBound(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1) // single-member device

	// A TYPE selector routes through the legacy attachPCIDevice path (no address-kind
	// intent is written), which vfio-binds + owner-claims the resolved device.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("legacy type attach: %v", err)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("precondition: a type selector must NOT create an address intent, got %d", len(in))
	}
	if !fs.isBound(addr) {
		t.Fatal("precondition: the legacy attach must vfio-bind the device")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("precondition: the legacy attach must own the device, got owner %q", o)
	}

	// Force the vfio unbind to fail (the live DetachHostdev still succeeds), so the
	// device cannot be confirmed unbound during release.
	fs.setFailUnbind(addr)

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a failed vfio unbind on the legacy detach path must fail the RPC (recoverable), not report success")
	}

	// The invariant: ownership RETAINED and the device is still bound — owned + bound
	// (recoverable), NEVER unowned + bound.
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("a failed unbind must RETAIN ownership (never unowned+bound), got owner %q, want vm1", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound (owned + bound, recoverable)")
	}
}

// TestMigrateVM_VFUnbindFails_NotUnownedBound is FIX-18 ESCAPE 2: the SR-IOV VF
// pre-migration detach must NOT release a VF whose post-detach vfio unbind fails.
// The VF is vfio-bound on the source, so a warn-only unbind + unconditional
// ReleasePCIDevice left it UNOWNED-but-vfio-BOUND on the source host. The strict
// primitive must retain ownership (still bound) and ABORT the migration rather than
// proceed leaving an orphan. RED before the fix: the VF was released regardless of
// the unbind outcome and migration continued.
func TestMigrateVM_VFUnbindFails_NotUnownedBound(t *testing.T) {
	const vfAddr = "0000:41:10.0"
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	// If the fix is NOT in place the migration proceeds past the VF loop; make the
	// libvirt migration itself fail so the RED run terminates deterministically (the
	// VF is still released — unowned+bound — which is what the assertions catch).
	fake.FailMigrateToTarget = func(_, _ string) error { return errors.New("injected migrate failure") }
	s.virt = fake

	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	insertTestVMWithSpec(t, ctx, s.db, "pci-vm", "test-host", "running", "")
	insertTestHost(t, ctx, s.db, "target-host", "active")

	// Seed the VF in host inventory owned by the VM, mark it a VF + vfio-bound, and
	// force its unbind to fail.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: vfAddr, Type: "net", VendorID: "8086", VMName: "pci-vm",
	}); err != nil {
		t.Fatalf("seed VF: %v", err)
	}
	fs.setVF(vfAddr)
	fs.setBound(vfAddr)
	fs.setFailUnbind(vfAddr)

	stream := &mockMigrateStream{ctx: ctx}
	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "pci-vm",
		TargetHost: "target-host",
		Strategy:   pb.MigrateStrategy_MIGRATE_COLD,
	}, stream)
	if err == nil {
		t.Fatal("a VF whose unbind fails before migration must abort the migration, not succeed")
	}

	// The invariant: the VF stays OWNED by the VM on the source and still bound —
	// owned + bound (the migration aborts), NEVER unowned + bound.
	if o := pciOwnerOf(t, ctx, s, vfAddr); o != "pci-vm" {
		t.Fatalf("a failed VF unbind must RETAIN ownership on the source (never unowned+bound), got owner %q, want pci-vm", o)
	}
	if !fs.isBound(vfAddr) {
		t.Fatal("a failed VF unbind must leave the VF still bound (owned + bound on the source)")
	}
	// The abort comes from the strict release site (not a downstream libvirt failure).
	if !strings.Contains(err.Error(), "release VF") {
		t.Fatalf("the migration should abort at the VF release site; got %v", err)
	}
}
