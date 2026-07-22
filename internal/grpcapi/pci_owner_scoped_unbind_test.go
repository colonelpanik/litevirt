package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-23 closed invariant (c) — "no PCI path unbinds another VM's device" — at the SOLE
// release primitive, unbindAndReleaseOwnership. FIX-25 tightens the NORMAL contract further:
// the primitive now ACTS ONLY on addrs owned by the caller's own vmName, SKIPS an unowned/
// absent addr (idempotent no-op — nothing proven ours to touch), and ERRORS on a foreign-
// owned addr (a foreign BDF handed to a normal release is a caller/operator bug, not a
// silent success). These tests pin: (1) an unowned+bound addr is NEVER unbound (returns nil,
// nothing of ours), (2) a foreign owner is NOT unbound AND returns a non-nil error, and (3)
// the primitive fails closed if the ownership read errors (release nothing rather than act
// blind). The durable-lease-authorized reclaim of a genuinely leaked unowned device lives in
// the SEPARATE reclaimLeasedDevices primitive.

// TestUnbindAndReleaseOwnership_UnownedBoundAddr_SkipsNoUnbind: an UNOWNED addr (vm_name
// empty) that happens to be vfio-bound must be SKIPPED — never unbound, never released —
// because the primitive can only prove an addr is the caller's when owner == vmName. In
// every legitimate normal flow the caller acts on its own owned members; an unowned addr was
// already released (idempotent retry) or was never ours, so unbinding it would tear down a
// device we cannot prove is ours. The call is a clean no-op (returns nil). RED before the fix
// (the old disposition treated unowned as reclaimable and unbound the device).
func TestUnbindAndReleaseOwnership_UnownedBoundAddr_SkipsNoUnbind(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	// The addr is present in inventory but UNOWNED (vm_name empty), yet bound to vfio-pci.
	seedPCIGPU(t, s, addr, -1)
	fs.setBound(addr)

	// "vm1" asks the normal primitive to release it — it is NOT proven vm1's.
	if err := s.unbindAndReleaseOwnership(ctx, "vm1", []string{addr}); err != nil {
		t.Fatalf("releasing an unowned addr must be a clean no-op for the normal primitive, got %v", err)
	}

	// THE INVARIANT: an unowned device the caller cannot prove is theirs is untouched.
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("an unowned addr must NOT be unbound by the normal primitive, got %d unbinds", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("an unowned addr must stay bound (the normal primitive never reclaims it)")
	}
}

// TestUnbindAndReleaseOwnership_ForeignOwner_ReturnsError: an addr owned + bound by a
// DIFFERENT live VM must NOT be unbound AND the call must RETURN a non-nil error — a foreign
// BDF handed to a normal release is a caller/operator bug, so the whole call fails (all-or-
// nothing) and the caller leaves the op failed/recoverable rather than reporting a bogus
// success. RED before the fix (a foreign owner was a silent skip + nil return).
func TestUnbindAndReleaseOwnership_ForeignOwner_ReturnsError(t *testing.T) {
	const foreignAddr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	// The addr is owned + bound by another live VM ("vm-b").
	seedPCIGPU(t, s, foreignAddr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", foreignAddr, "vm-b"); err != nil {
		t.Fatalf("assign foreign addr to vm-b: %v", err)
	}
	fs.setBound(foreignAddr)

	// "vm-a" asks the primitive to release the foreign addr — it is NOT vm-a's.
	if err := s.unbindAndReleaseOwnership(ctx, "vm-a", []string{foreignAddr}); err == nil {
		t.Fatal("a foreign-owned addr handed to the normal release must return a non-nil error, got nil")
	}

	// THE INVARIANT (preserved from FIX-23): the other VM's device is untouched.
	if n := fs.unbindCount(foreignAddr); n != 0 {
		t.Fatalf("a foreign-owned addr must NOT be unbound, got %d unbinds", n)
	}
	if !fs.isBound(foreignAddr) {
		t.Fatal("a foreign-owned addr must stay bound to vfio-pci (its owner is still using it)")
	}
	if o := pciOwnerOf(t, ctx, s, foreignAddr); o != "vm-b" {
		t.Fatalf("a foreign-owned addr must stay owned by vm-b, got %q", o)
	}
}

// TestDetachPCI_LegacyForeignBDF_DoesNotUnbindOtherVM is the end-to-end reproduction: a
// running VM (vm-a) with NO concrete-address intent for the passed BDF takes the legacy
// running-only detach path (detachPCIDevice → unbindAndReleaseOwnership). If the operator
// passes a raw BDF that is owned + bound by a DIFFERENT live VM (vm-b), vm-b's passthrough
// must be untouched AND (FIX-25) the RPC must now surface an ERROR — a foreign BDF handed to
// a normal detach is an operator bug, not a silent success. RED before FIX-25 (the primitive
// skipped the foreign owner and returned nil, so the RPC reported success).
func TestDetachPCI_LegacyForeignBDF_DoesNotUnbindOtherVM(t *testing.T) {
	const foreignAddr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	// NOT enableHardwareV2: the legacy running-only path is the pre-latch detach path.
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// vm-a is running and has a live domain with NO hostdevs (so detachHostdevIfPresent is a
	// no-op and control reaches the release primitive with the operator-supplied foreign BDF).
	seedNICVM(t, s, "vm-a", "running")
	fake.SetState("vm-a", libvirtfake.StateRunning)
	fake.SetActiveXML("vm-a", "<domain><name>vm-a</name></domain>")

	// The foreign addr is owned + bound by another live VM (vm-b). vm-a has NO intent for it,
	// so DetachDevice(vm-a, foreignAddr) routes to the legacy path.
	seedPCIGPU(t, s, foreignAddr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", foreignAddr, "vm-b"); err != nil {
		t.Fatalf("assign foreign addr to vm-b: %v", err)
	}
	fs.setBound(foreignAddr)

	// Precondition: no concrete-address intent for the BDF on vm-a → legacy branch.
	if _, journaled, err := s.liveAddressIntent(ctx, "vm-a", foreignAddr); err != nil || journaled {
		t.Fatalf("precondition: foreign BDF must have no address intent on vm-a (journaled=%v, err=%v)", journaled, err)
	}

	// Detach the foreign BDF from vm-a via the legacy path: the RPC must ERROR now.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm-a", PciAddress: foreignAddr}); err == nil {
		t.Fatal("legacy detach of a foreign BDF must surface an error, got nil (bogus success)")
	}

	// THE INVARIANT (preserved from FIX-23): vm-b's device is untouched.
	if n := fs.unbindCount(foreignAddr); n != 0 {
		t.Fatalf("a legacy detach must NOT unbind another VM's device, got %d unbinds", n)
	}
	if !fs.isBound(foreignAddr) {
		t.Fatal("another VM's device must stay bound after a foreign-BDF legacy detach")
	}
	if o := pciOwnerOf(t, ctx, s, foreignAddr); o != "vm-b" {
		t.Fatalf("another VM's device must stay owned by vm-b, got %q", o)
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
