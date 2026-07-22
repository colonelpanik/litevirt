package grpcapi

import (
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// TestDetachPCI_RunningPartialDetachFails_LeavesRecoverable is FIX-16 Fix B: a RUNNING
// detach of a multi-member device whose live DetachHostdev succeeds for an earlier
// member but FAILS for a later one must roll FORWARD (leave the op recovery-required,
// barrier retained), NOT terminalize via failPCIDetachClean — whose contract is
// "nothing applied". Once a member's hostdev has left the live domain that contract is
// violated, and terminalizing would clear the barrier over a half-applied live domain
// with no recovery. RED before the fix (the loop routed ANY failure to
// failPCIDetachClean → terminal, barrier cleared). Recovery re-detaches only the
// still-present members (idempotent via hostdevAliasInXML).
func TestDetachPCI_RunningPartialDetachFails_LeavesRecoverable(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "running")
	// Two devices in one IOMMU group → a 2-member device.
	seedPCIGPU(t, s, "0000:41:00.0", 20)
	seedPCIGPU(t, s, "0000:41:00.1", 20)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 2 {
		t.Fatalf("precondition: want 2 realized members, got %d", len(rs))
	}

	// Make the SECOND live DetachHostdev call fail regardless of member order: the first
	// member detaches (live domain mutated), the second fails → partial live detach.
	var detachCalls int
	fake.FailDetachHostdev = func(_, _ string) error {
		detachCalls++
		if detachCalls >= 2 {
			return fmt.Errorf("injected detach failure on the second member")
		}
		return nil
	}

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: "0000:41:00.0"})
	if derr == nil {
		t.Fatal("a partial live detach must fail the detach (recoverable), not report success")
	}

	// LEFT RECOVERABLE (NOT terminal via failPCIDetachClean): the barrier is retained so
	// recovery re-detaches the remaining member. failPCIDetachClean would have cleared it.
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("a partial live detach must leave the barrier set (recovery-required), not terminalize via failPCIDetachClean")
	}
	// Rows survive (roll-forward incomplete) — a retry / recovery re-detaches + tombstones.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("partial detach must NOT tombstone the intent, got %d", len(in))
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 2 {
		t.Fatalf("partial detach must NOT tombstone realizations, got %d", len(rs))
	}
}

// TestDetachPCI_RunningFirstMemberDetachFails_CleanTerminal guards the clean-terminal
// case Fix B must preserve: when the VERY FIRST member's live DetachHostdev fails,
// nothing has been applied to the live domain, so failPCIDetachClean's "nothing
// applied" contract still holds — the op terminalizes cleanly (barrier CLEARED),
// ownership is retained, and no row is tombstoned. (This must remain GREEN both before
// and after the fix.)
func TestDetachPCI_RunningFirstMemberDetachFails_CleanTerminal(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1) // single-member device

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// The first (and only) member's live detach fails → nothing applied.
	fake.FailDetachHostdev = func(_, _ string) error { return fmt.Errorf("injected first-member detach failure") }

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a first-member detach failure must fail the detach")
	}

	// CLEAN TERMINAL: the barrier is cleared (the VM is mutable again).
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op != "" {
		t.Fatalf("a first-member detach failure must terminalize cleanly (barrier cleared), got %q", op)
	}
	// failPCIDetachClean never touches host inventory/hardware: ownership retained, device
	// still bound, rows intact.
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("clean-terminal detach must retain ownership, got owner %q", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("clean-terminal detach must not unbind the device")
	}
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("clean-terminal detach must not vfio-unbind, got %d unbinds", n)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("clean-terminal detach must NOT tombstone the intent, got %d", len(in))
	}
}

// TestDetachPCI_RunningUnbindFails_LeavesRecoverable is FIX-16 Fix C: a RUNNING detach
// whose live DetachHostdev succeeds but whose vfio.Unbind then FAILS must leave the op
// recovery-required — ownership retained, intent + realizations NOT tombstoned, barrier
// retained — rather than releasing ownership + tombstoning + completing (which the old
// the old fire-and-forget release did, leaving an unowned-but-vfio-bound orphan). RED before
// the fix (the old release logged the unbind failure then released + tombstoned + completed).
func TestDetachPCI_RunningUnbindFails_LeavesRecoverable(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatal("precondition: running attach must vfio-bind the device")
	}

	// Force the vfio unbind to fail (the live DetachHostdev still succeeds).
	fs.setFailUnbind(addr)

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a failed vfio unbind must fail the detach (recoverable), not report success")
	}

	// The live detach DID run (roll forward), but the strict release rolled nothing back.
	if n := fake.DetachHostdevCount(); n != 1 {
		t.Fatalf("live DetachHostdev should have run once, got %d", n)
	}
	// Ownership RETAINED (not released despite the unbind failure).
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("unbind failure must RETAIN ownership, got owner %q, want vm1", o)
	}
	// The device is still bound (the unbind never succeeded) — owned + bound is safe.
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound (owned + bound, recoverable)")
	}
	// Nothing tombstoned.
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("unbind failure must NOT tombstone realizations, got %d", len(rs))
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("unbind failure must NOT tombstone the intent, got %d", len(in))
	}
	// Barrier still set → the operation is recovery-required.
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("unbind failure must leave the operation barrier set (recovery-required)")
	}
}

// TestDetachPCI_EmptyMemberSet_LeavesRecoverable is FIX-16 Fix A: a detach whose member
// set cannot be resolved (no realizations, and the intent-resolve fails — here a
// since-regrouped IOMMU sibling now owned by ANOTHER VM trips checkIOMMUConflict on the
// primary) must leave the op recovery-required — the intent is NOT tombstoned and the
// VM's ownership is NOT touched — rather than journaling + running a no-op release and
// tombstoning the intent while the device stays owned (a leak that COMPLETES). The guard
// sits BEFORE the running/stopped split so it protects both paths. RED before the fix
// (an empty member set completed: the intent was tombstoned while ownership leaked).
func TestDetachPCI_EmptyMemberSet_LeavesRecoverable(t *testing.T) {
	const primary = "0000:41:00.0"
	const sibling = "0000:41:00.1"
	const deviceID = "pcidev-empty"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "stopped")
	fake.SetState("vm1", libvirtfake.StateDefined)
	// The primary + a same-IOMMU-group sibling. vm1 OWNS the primary; the sibling is owned
	// by ANOTHER VM, so re-resolving the intent trips checkIOMMUConflict → the resolve
	// ERRORS → the member set is empty. No realizations exist (never started).
	seedPCIGPU(t, s, primary, 20)
	seedPCIGPU(t, s, sibling, 20)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", primary, "vm1"); err != nil {
		t.Fatalf("assign primary to vm1: %v", err)
	}
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", sibling, "vm2"); err != nil {
		t.Fatalf("assign sibling to vm2: %v", err)
	}
	seedAddressIntent(t, s, "vm1", deviceID, primary)

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: primary})
	if derr == nil {
		t.Fatal("an unresolvable member set must fail the detach (recoverable), not complete")
	}

	// LEFT RECOVERABLE: the intent is NOT tombstoned and vm1 still owns the primary.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("an empty member set must NOT tombstone the intent, got %d", len(in))
	}
	if o := pciOwnerOf(t, ctx, s, primary); o != "vm1" {
		t.Fatalf("an empty member set must NOT touch ownership, primary owner = %q, want vm1", o)
	}
	if n := fs.unbindCount(primary); n != 0 {
		t.Fatalf("an empty member set must NOT vfio-unbind, got %d unbinds", n)
	}
	// Barrier still set → the operation is recovery-required (it runs past BeginVMOperation).
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("an empty member set must leave the operation barrier set (recovery-required)")
	}
}
