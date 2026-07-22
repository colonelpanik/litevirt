package grpcapi

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-17 closes the invariant across every PCI release site: unbindAndReleaseOwnership
// is the SOLE release primitive, so NO path may clear host_pci_devices ownership while
// a member is still bound to vfio-pci. These tests exercise the attach/start-rollback,
// lease-recovery, and whole-VM-teardown callers the old fire-and-forget release paths
// previously left able to produce an unowned-but-vfio-bound orphan.

// TestAttachPCI_RollbackUnbindFails_OwnedNotUnowned (Part 1 A/B): a RUNNING attach whose
// vfio bind fails on a later member AND whose bind-failure rollback cannot unbind the
// earlier (already-bound) member must NEVER leave that member unowned-but-vfio-bound. The
// strict primitive is all-or-nothing: the failed unbind means it releases NOTHING, so the
// earlier member stays OWNED + bound (recoverable) rather than unowned + bound, the attach
// fails, and the durable device-lease is RETAINED for RecoverDeviceLeases. RED before the
// fix (acquireDeviceLeases's rollback logged the unbind failure, released ownership anyway,
// and cleared the lease → unowned + bound orphan with no recovery record).
func TestAttachPCI_RollbackUnbindFails_OwnedNotUnowned(t *testing.T) {
	const primary = "0000:41:00.0"
	const sibling = "0000:41:00.1"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "running")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateRunning)
	// Two devices in one IOMMU group → a 2-member device. acquireDeviceLeases binds them
	// in order (primary first, then sibling): the primary binds, the sibling's bind fails,
	// and the rollback unbind of the (now bound) primary is forced to fail.
	seedPCIGPU(t, s, primary, 20)
	seedPCIGPU(t, s, sibling, 20)
	fs.setFailBind(sibling)   // the later member never binds → acquire fails
	fs.setFailUnbind(primary) // the earlier member cannot be unbound during rollback

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: primary},
	})
	if err == nil {
		t.Fatal("a bind failure must fail the attach")
	}

	// THE INVARIANT: the earlier member stays OWNED by vm1 AND still bound — never
	// unowned-but-vfio-bound.
	if o := pciOwnerOf(t, ctx, s, primary); o != "vm1" {
		t.Fatalf("primary must stay OWNED by vm1 (never unowned+bound), got owner %q", o)
	}
	if !fs.isBound(primary) {
		t.Fatal("primary's failed unbind must leave it still bound (owned + bound is safe)")
	}
	// The sibling never bound; it is retained owned (all-or-nothing released nothing) but is
	// NOT bound → also not an unowned+bound orphan.
	if fs.isBound(sibling) {
		t.Fatal("the sibling never bound successfully; it must not be bound")
	}
	// Op recoverable: the durable device-lease survives so RecoverDeviceLeases retries the
	// release (never cleared over a member still bound to vfio-pci).
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm1")); !found {
		t.Fatal("a release that could not unbind must RETAIN the device lease for recovery")
	}
}

// TestStartPreflight_RollbackUnbindFails_Recoverable (Part 1 D): a start-preflight rollback
// (here a post-bind reconcile failure) whose unbind of the freshly-claimed member fails must
// leave the member OWNED + bound (recoverable), NOT finish() the durable lease, and fail the
// start. RED before the fix (the rollback's old release cleared ownership despite the failed
// unbind → unowned + bound, and finish() cleared the lease regardless).
func TestStartPreflight_RollbackUnbindFails_Recoverable(t *testing.T) {
	const addr = "0000:41:00.0"
	const deviceID = "dev-fresh"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	// NOT pre-owned → start-preflight CAS-claims it fresh this start (it IS freshly claimed).
	seedAddressIntent(t, s, "vm1", deviceID, addr)
	fs.setFailUnbind(addr) // the rollback unbind cannot complete

	// Force the post-acquire reconcile define (the one carrying the device's hostdev alias)
	// to FAIL — after the vfio bind + realization write — so the rollback runs.
	alias := pciMemberAlias(deviceID, "m0")
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(xml string) error {
		if hostdevAliasInXML(xml, alias) {
			return fmt.Errorf("injected reconcile define failure")
		}
		return nil
	}

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("a post-acquire reconcile failure whose rollback unbind fails must fail the start")
	}

	// The freshly-claimed member stays OWNED + bound (never unowned+bound).
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("a rollback that could not unbind must RETAIN ownership, got %q, want vm1", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed rollback unbind must leave the device still bound")
	}
	// The lease was NOT finish()'d → it survives for recovery.
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm1")); !found {
		t.Fatal("a rollback that could not unbind must NOT clear the durable device lease")
	}
	// The VM did not start.
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st == "running" {
		t.Fatalf("VM must not be running after a failed start, state=%s", st)
	}
}

// TestRecoverDeviceLeases_UnbindFails_RetainsJournal (Part 1 F): startup lease recovery for
// an orphaned lease (VM gone) whose device cannot be unbound must release NOTHING and RETAIN
// the journal entry so the next pass retries — never remove the entry over a device still
// bound to vfio-pci (which would silently orphan it unowned-but-bound with no backstop). RED
// before the fix (the old release cleared ownership despite the failed unbind, then the
// entry was removed unconditionally).
func TestRecoverDeviceLeases_UnbindFails_RetainsJournal(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	j, _ := opjournal.Open(t.TempDir())
	s.SetOpJournal(j)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()

	const addr = "0000:01:00.0"
	// Orphaned: device claimed to a VM that never finalized, still vfio-bound, stuck unbind.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: addr, Type: "gpu", VMName: "ghost-vm",
	}); err != nil {
		t.Fatalf("seed ghost device: %v", err)
	}
	fs.setBound(addr)
	fs.setFailUnbind(addr)
	if err := j.Write(opjournal.Entry{OperationID: deviceLeaseOpID("ghost-vm"), ResourceID: "ghost-vm",
		Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": addr}}); err != nil {
		t.Fatalf("write ghost lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	// Ownership RETAINED (released nothing over a device that could not be unbound).
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	owner := ""
	for _, d := range devs {
		if d.Address == addr {
			owner = d.VMName
		}
	}
	if owner != "ghost-vm" {
		t.Fatalf("a failed unbind must RETAIN ownership, got owner %q, want ghost-vm", owner)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound")
	}
	// The journal entry is RETAINED for a later retry.
	if _, found, _ := j.Read(deviceLeaseOpID("ghost-vm")); !found {
		t.Fatal("a failed release must RETAIN the lease journal entry for retry (not remove it)")
	}
}

// TestReleaseDevices_StopUnbindFails_Recoverable (Part 2, pre-latch stop caller): a pre-latch
// stop whose whole-VM release cannot unbind an owned device must leave the stop RECOVERABLE —
// ownership retained, the VM NOT marked stopped-clean, an error surfaced — so a retry re-drives.
// RED before the fix (releaseDevices unbound (failed, logged), released ownership anyway, and
// returned nothing → the stop completed with the device unowned + bound).
func TestReleaseDevices_StopUnbindFails_Recoverable(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // operation_protocol active, hardware_v2 NOT latched → pre-latch stop
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "running")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateRunning)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	fs.setBound(addr)
	fs.setFailUnbind(addr)

	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err == nil {
		t.Fatal("a stuck unbind during a pre-latch stop must fail the stop (recoverable)")
	}

	// Ownership RETAINED (released nothing).
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("a failed release must RETAIN ownership, got %q, want vm1", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound")
	}
	// The VM is NOT marked stopped-clean → the stop is recovery-required.
	if vm := mustGetVM(t, s, "vm1"); vm.State == "stopped" {
		t.Fatalf("a failed release must NOT mark the VM stopped-clean (recoverable), state=%s", vm.State)
	}
}

// TestReleaseDevices_DeleteUnbindFails_NoUnownedBound (Part 2, VM-delete caller): a VM delete
// whose whole-VM release cannot unbind a residual device must NEVER produce an unowned-but-
// vfio-bound device. The VM row is going away (no future op to be recoverable against), so the
// chosen semantics are: leave the device OWNED-by-the-(deleted)-VM + bound (a benign, operator-
// cleanable stale owner row) over unowned + bound, log loudly, and let the delete COMPLETE
// (never wedge). RED before the fix (releaseDevices released ownership despite the failed
// unbind → the device was left unowned + bound after the VM record vanished).
func TestReleaseDevices_DeleteUnbindFails_NoUnownedBound(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
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

	// The delete still COMPLETES despite the stuck unbind (never wedges). KeepDisks avoids
	// the disk-store teardown (unrelated to the PCI release exercised here).
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1", KeepDisks: true}); err != nil {
		t.Fatalf("delete must complete even when a residual device cannot be unbound: %v", err)
	}

	// THE INVARIANT: the device is NEVER unowned-but-bound. It stays owned by the (deleted)
	// VM + bound — the chosen "prefer owned+bound over unowned+bound" semantics.
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("a residual unbind failure must leave the device OWNED by the deleted VM (never unowned+bound), got owner %q", o)
	}
	// The delete completed: the VM record is gone.
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm != nil {
		t.Fatal("delete must remove the VM record")
	}
}

// TestRecoverPCIDetach_StoppedEmptySet_Recoverable (Part 3): a pre-fix-shaped stopped-detach
// recovery journal entry (no member_addresses) whose intent re-resolution yields an EMPTY set
// — here a since-regrouped IOMMU sibling now owned by another VM trips checkIOMMUConflict on
// the primary → the resolve errors — must leave the op RECOVERABLE (barrier retained, op NOT
// completed, intent NOT tombstoned, ownership untouched), mirroring the live-detach empty-set
// guard (FIX-16 Fix A). RED before the fix (an empty set ran a no-op release then tombstoned
// the intent + completed while the VM still owned the device — a leak that COMPLETES).
func TestRecoverPCIDetach_StoppedEmptySet_Recoverable(t *testing.T) {
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
	fake.SetState("vm1", libvirtfake.StateDefined) // positively shut off → stopped recovery path
	// primary owned by vm1; the same-IOMMU-group sibling owned by ANOTHER VM → re-resolving
	// the intent trips checkIOMMUConflict on the primary → the resolve ERRORS → empty set. No
	// realizations exist (never started).
	seedPCIGPU(t, s, primary, 20)
	seedPCIGPU(t, s, sibling, 20)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", primary, "vm1"); err != nil {
		t.Fatalf("assign primary to vm1: %v", err)
	}
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", sibling, "vm2"); err != nil {
		t.Fatalf("assign sibling to vm2: %v", err)
	}
	seedAddressIntent(t, s, "vm1", deviceID, primary)

	// Pre-fix-shaped journal: device_id + pci_address but NO member_addresses.
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachPCIRequestHash("vm1", primary),
		[]string{corrosion.OpStepReserved},
		map[string]string{"device_id": deviceID, "pci_address": primary})

	s.RecoverHardwareOperations(ctx)

	// LEFT RECOVERABLE: barrier retained, op NOT completed, intent NOT tombstoned, ownership untouched.
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID == "" {
		t.Fatal("an empty resolved set must leave the operation barrier set (recovery-required)")
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("an empty resolved set must NOT tombstone the intent, got %d", len(in))
	}
	if o := pciOwnerOf(t, ctx, s, primary); o != "vm1" {
		t.Fatalf("an empty resolved set must NOT touch ownership, got %q, want vm1", o)
	}
	if n := fs.unbindCount(primary); n != 0 {
		t.Fatalf("an empty resolved set must NOT vfio-unbind, got %d unbinds", n)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state == corrosion.OpStepCompleted {
		t.Fatal("recovery must NOT complete a stopped detach whose resolved member set is empty")
	}
}
