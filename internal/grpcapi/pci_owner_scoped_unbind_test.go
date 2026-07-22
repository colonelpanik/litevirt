package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-23 closes invariant (c) — "no PCI path unbinds another VM's device" — at the SOLE
// release primitive, unbindAndReleaseOwnership. Its unbind loop used to be ownership-BLIND
// (it unbound any addr the vfio ground truth reported bound; only the DB release was owner-
// scoped), so the legacy operator-driven detachPCIDevice — which forwards an operator-
// supplied raw BDF to the primitive — could unbind a device a DIFFERENT live VM owns.
// These tests pin the primitive to: (1) skip any addr owned by another non-empty VM, and
// (2) fail closed if the ownership read errors (release nothing rather than act blind).

// TestUnbindAndReleaseOwnership_SkipsOtherVMOwned: an addr owned + bound by a DIFFERENT live
// VM must be SKIPPED — never unbound, never released — even when a caller passes it in for
// some other VM. The call is a clean no-op (nothing of the caller's to act on). RED before
// the fix (the ownership-blind unbind tore down the other VM's live passthrough).
func TestUnbindAndReleaseOwnership_SkipsOtherVMOwned(t *testing.T) {
	const foreignAddr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	// The addr is owned + bound by another live VM ("vm2").
	seedPCIGPU(t, s, foreignAddr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", foreignAddr, "vm2"); err != nil {
		t.Fatalf("assign foreign addr to vm2: %v", err)
	}
	fs.setBound(foreignAddr)

	// "vm1" asks the primitive to release the foreign addr — it is NOT vm1's.
	if err := s.unbindAndReleaseOwnership(ctx, "vm1", []string{foreignAddr}); err != nil {
		t.Fatalf("releasing a foreign-owned addr must be a clean no-op, got %v", err)
	}

	// THE INVARIANT: the other VM's device is untouched.
	if n := fs.unbindCount(foreignAddr); n != 0 {
		t.Fatalf("a foreign-owned addr must NOT be unbound, got %d unbinds", n)
	}
	if !fs.isBound(foreignAddr) {
		t.Fatal("a foreign-owned addr must stay bound to vfio-pci (its owner is still using it)")
	}
	if o := pciOwnerOf(t, ctx, s, foreignAddr); o != "vm2" {
		t.Fatalf("a foreign-owned addr must stay owned by vm2, got %q", o)
	}
}

// TestDetachPCI_LegacyForeignBDF_DoesNotUnbindOtherVM is the end-to-end reproduction: a
// running VM (vm1) with NO concrete-address intent for the passed BDF takes the legacy
// running-only detach path (detachPCIDevice → unbindAndReleaseOwnership). If the operator
// passes a raw BDF that is owned + bound by a DIFFERENT live VM (vm2), vm2's passthrough
// must be untouched. RED before the fix (the primitive's blind unbind tore down vm2's device).
func TestDetachPCI_LegacyForeignBDF_DoesNotUnbindOtherVM(t *testing.T) {
	const foreignAddr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	// NOT enableHardwareV2: the legacy running-only path is the pre-latch detach path.
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// vm1 is running and has a live domain with NO hostdevs (so detachHostdevIfPresent is a
	// no-op and control reaches the release primitive with the operator-supplied foreign BDF).
	seedNICVM(t, s, "vm1", "running")
	fake.SetState("vm1", libvirtfake.StateRunning)
	fake.SetActiveXML("vm1", "<domain><name>vm1</name></domain>")

	// The foreign addr is owned + bound by another live VM (vm2). vm1 has NO intent for it,
	// so DetachDevice(vm1, foreignAddr) routes to the legacy path.
	seedPCIGPU(t, s, foreignAddr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", foreignAddr, "vm2"); err != nil {
		t.Fatalf("assign foreign addr to vm2: %v", err)
	}
	fs.setBound(foreignAddr)

	// Precondition: no concrete-address intent for the BDF on vm1 → legacy branch.
	if _, journaled, err := s.liveAddressIntent(ctx, "vm1", foreignAddr); err != nil || journaled {
		t.Fatalf("precondition: foreign BDF must have no address intent on vm1 (journaled=%v, err=%v)", journaled, err)
	}

	// Detach the foreign BDF from vm1 via the legacy path.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: foreignAddr}); err != nil {
		t.Fatalf("legacy detach of a foreign BDF should be a no-op for vm1, got %v", err)
	}

	// THE INVARIANT: vm2's device is untouched.
	if n := fs.unbindCount(foreignAddr); n != 0 {
		t.Fatalf("a legacy detach must NOT unbind another VM's device, got %d unbinds", n)
	}
	if !fs.isBound(foreignAddr) {
		t.Fatal("another VM's device must stay bound after a foreign-BDF legacy detach")
	}
	if o := pciOwnerOf(t, ctx, s, foreignAddr); o != "vm2" {
		t.Fatalf("another VM's device must stay owned by vm2, got %q", o)
	}
}

// TestUnbindAndReleaseOwnership_OwnershipReadFails_FailsClosed: when the ownership read
// errors the primitive cannot determine which addrs are the caller's, so it must FAIL CLOSED
// — release nothing, unbind nothing, return an error — rather than act blind on an empty
// owner map. Here the addr IS vm1's own (so absent the read failure it WOULD be unbound +
// released); the forced read error must prevent any action. RED before the fix (the read
// error was discarded and the primitive proceeded with an empty owner map → unbound the addr).
func TestUnbindAndReleaseOwnership_OwnershipReadFails_FailsClosed(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()

	// The addr is the caller's own, bound — the "would be released absent the fault" baseline.
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(adminCtx(), s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("assign addr to vm1: %v", err)
	}
	fs.setBound(addr)

	// Force the ownership read (corrosion.ListPCIDevices → QueryContext) to error by passing an
	// already-cancelled context.
	cancelled, cancel := context.WithCancel(adminCtx())
	cancel()

	if err := s.unbindAndReleaseOwnership(cancelled, "vm1", []string{addr}); err == nil {
		t.Fatal("an ownership-read failure must fail closed (return an error), got nil")
	}

	// Fail closed = release NOTHING, unbind NOTHING (a fresh context reads the untouched state).
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("a failed ownership read must NOT unbind anything, got %d unbinds", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed ownership read must leave the device still bound")
	}
	if o := pciOwnerOf(t, adminCtx(), s, addr); o != "vm1" {
		t.Fatalf("a failed ownership read must release nothing (owner retained), got %q", o)
	}
}
