package grpcapi

import (
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-26: a retained legacy-attach lease must be a real recovery anchor.
//
// FIX-20's legacy attachPCIDevice incomplete-rollback path RETAINS the device lease
// to signal "device(s) left owned + bound". Fix A marks that retained lease
// rollback_incomplete so Fix B's restart recovery can tell it apart from a completed
// allocation (Stage "bound") and membership-aware-reclaim its members instead of
// silently clearing the entry (which would leak the owned + bound device forever).

// TestAttachPCI_LegacyRollbackIncomplete_MarksLeaseRollbackIncomplete (Fix A): when
// the legacy running-attach rollback is INCOMPLETE — either the strict release cannot
// confirm the unbind, or the inverse guest-detach fails — the retained device lease is
// rewritten to Stage rollback_incomplete (a recovery anchor), NOT left at "bound" and
// NOT removed. RED against current code: the lease stays Stage "bound".
func TestAttachPCI_LegacyRollbackIncomplete_MarksLeaseRollbackIncomplete(t *testing.T) {
	const primary = "0000:00:00.0"
	const sibling = "0000:00:00.1"

	// firstThenFail models a 2-member device whose first live attach lands and whose
	// second fails, so exactly one member is in the guest when the rollback runs.
	firstThenFail := func(fake *libvirtfake.Fake) {
		attachN := 0
		fake.FailAttachHostdev = func(_, _, _ string) error {
			attachN++
			if attachN == 1 {
				return nil
			}
			return errors.New("injected second-member attach failure")
		}
	}

	// strict release fails: the inverse-detach of the attached member succeeds, but the
	// strict release cannot confirm the unbind → the SECOND incomplete-rollback return.
	t.Run("strict_release_fails", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s) // operation_protocol latched → the durable device lease IS written
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)

		seedNICVM(t, s, "vm-a", "running")
		fake.SetState("vm-a", libvirtfake.StateRunning)
		seedPCIGPU(t, s, primary, 20)
		seedPCIGPU(t, s, sibling, 20)

		firstThenFail(fake)
		// Neither bound member can be confirmed unbound → the strict release fails.
		fs.setFailUnbind(primary)
		fs.setFailUnbind(sibling)

		if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
		}); err == nil {
			t.Fatal("a later-member attach failure with a failed release must fail the attach")
		}

		assertLeaseRollbackIncomplete(t, s, "vm-a")
	})

	// inverse-detach fails: the guest inverse-detach itself errors → the FIRST
	// incomplete-rollback return, before any release is attempted.
	t.Run("inverse_detach_fails", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)

		seedNICVM(t, s, "vm-a", "running")
		fake.SetState("vm-a", libvirtfake.StateRunning)
		seedPCIGPU(t, s, primary, 20)
		seedPCIGPU(t, s, sibling, 20)

		firstThenFail(fake)
		// The inverse-detach of the already-attached member cannot be confirmed.
		fake.FailDetachHostdev = func(_, _ string) error {
			return errors.New("injected inverse-detach failure")
		}

		if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
		}); err == nil {
			t.Fatal("a failed inverse-detach must fail the attach")
		}

		assertLeaseRollbackIncomplete(t, s, "vm-a")
	})
}

// assertLeaseRollbackIncomplete reads vmName's durable device lease back and asserts it
// is still present and now carries Stage rollback_incomplete.
func assertLeaseRollbackIncomplete(t *testing.T, s *Server, vmName string) {
	t.Helper()
	entries, _, err := s.opJournal.List()
	if err != nil {
		t.Fatalf("list journal: %v", err)
	}
	var lease *opjournal.Entry
	for i := range entries {
		if entries[i].Kind == deviceLeaseKind && entries[i].ResourceID == vmName {
			lease = &entries[i]
		}
	}
	if lease == nil {
		t.Fatal("an incomplete rollback must RETAIN the device lease (a recovery anchor), got none")
	}
	if lease.Stage != deviceLeaseStageRollbackIncomplete {
		t.Fatalf("retained lease stage = %q, want %q", lease.Stage, deviceLeaseStageRollbackIncomplete)
	}
}

// TestRecoverDeviceLeases_RollbackIncompleteVMExists_Reclaims (Fix B): an existing VM
// with a rollback_incomplete lease recording a device it still owns + has bound + still
// carries in its live guest must, at startup recovery, have that device FIRST
// membership-detached from the guest, THEN unbound + owner-released, and the lease entry
// removed. RED against current code: the vm!=nil branch clears the entry WITHOUT
// releasing, so the device stays owned + bound (leaked).
func TestRecoverDeviceLeases_RollbackIncompleteVMExists_Reclaims(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// The VM exists and owns the leased device, which is bound to vfio-pci and present in
	// the live guest as a PCI hostdev (its source address matches addr).
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-a", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)
	fake.SetActiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")

	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageRollbackIncomplete, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write rollback_incomplete lease: %v", err)
	}

	// Record the guest-detach count observed AT the unbind, to prove detach ran BEFORE unbind.
	var detachAtUnbind int
	fs.onUnbind = func(string) { detachAtUnbind = fake.DetachHostdevCount() }

	s.RecoverDeviceLeases(ctx)

	if fake.DetachHostdevCount() != 1 {
		t.Fatalf("recovery must membership-detach the device from the live guest, got %d", fake.DetachHostdevCount())
	}
	if detachAtUnbind != 1 {
		t.Fatal("the guest detach must run BEFORE the vfio unbind (never unbind a device still in a live guest)")
	}
	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("recovery must unbind the leaked device once, got %d", n)
	}
	if fs.isBound(addr) {
		t.Fatal("recovery must leave the reclaimed device unbound (no owned+bound leak)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("recovery must owner-release the reclaimed device, got %q", o)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("recovery must remove the reclaimed rollback_incomplete lease entry")
	}
}

// TestRecoverDeviceLeases_CompletedAllocationVMExists_ClearsNoRelease (Fix B regression
// guard): an existing VM with a NORMAL Stage "bound" lease (a completed allocation whose
// finish() didn't run before the crash) must have its entry cleared WITHOUT tearing down
// the device — a completed allocation is not a leak. Protects the unchanged path so Fix B
// does not over-reach and release completed allocations.
func TestRecoverDeviceLeases_CompletedAllocationVMExists_ClearsNoRelease(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-a", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)
	fake.SetActiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")

	// A completed-allocation lease: Stage "bound".
	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: "bound", Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write completed-allocation lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	// The lease is cleared...
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("a completed-allocation lease must be cleared")
	}
	// ...but the device is NOT torn down (a completed allocation must survive recovery).
	if fake.DetachHostdevCount() != 0 {
		t.Fatalf("a completed allocation must NOT be guest-detached, got %d detaches", fake.DetachHostdevCount())
	}
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("a completed allocation must NOT be unbound, got %d unbinds", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("a completed allocation must stay bound to vfio-pci")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm-a" {
		t.Fatalf("a completed allocation must retain ownership, got %q", o)
	}
}
