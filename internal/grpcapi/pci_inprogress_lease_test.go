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

// FIX-29: a crash during a LEGACY PCI attach must not look like a completed allocation.
//
// The legacy running-attach path (attachPCIDevice → allocateDevices → acquireDeviceLeases
// → beginDeviceLease) is UNJOURNALED: the device lease is its ONLY crash anchor, and the
// VM ALWAYS already exists (it is a running-VM hotplug). If the initial lease stage is
// "bound", a process crash during the vfio bind or the guest-attach loop leaves Stage
// "bound" + VM exists → RecoverDeviceLeases misreads it as a COMPLETED allocation and
// clears the lease, leaking the owned + bound device. So the legacy attach records its
// initial lease at Stage in_progress, which restart recovery reclaims (like
// rollback_incomplete) instead of clearing.

// TestAttachPCI_LegacyAttach_WritesInProgressLease: the legacy attach's INITIAL durable
// lease (written by beginDeviceLease before the guest attach loop) is Stage in_progress,
// NOT "bound". Captured at the first guest AttachHostdev — after beginDeviceLease has
// recorded the claim and before any success-finish or rollback rewrites the entry. RED
// against current code: the initial stage is "bound".
func TestAttachPCI_LegacyAttach_WritesInProgressLease(t *testing.T) {
	const addr = "0000:00:00.0"

	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // operation_protocol latched → the durable device lease IS written
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm-a", "running")
	fake.SetState("vm-a", libvirtfake.StateRunning)
	seedPCIGPU(t, s, addr, -1) // single-member device (no IOMMU siblings)

	// Read the lease Stage back at the moment the live guest attach begins — after
	// beginDeviceLease durably recorded the claim (inside allocateDevices) and BEFORE any
	// success-finish or rollback rewrites it. This is the initial durable stage a
	// mid-attach crash would leave behind. Then fail the attach so the RPC returns.
	var stageAtAttach string
	var leaseFound bool
	fake.FailAttachHostdev = func(_, _, _ string) error {
		if e, ok, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); ok {
			leaseFound = true
			stageAtAttach = e.Stage
		}
		return errors.New("injected attach failure to inspect the initial lease stage")
	}

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err == nil {
		t.Fatal("the injected guest-attach failure must fail the attach")
	}

	if !leaseFound {
		t.Fatal("the legacy attach must durably record a device lease before the guest attach")
	}
	if stageAtAttach != deviceLeaseStageInProgress {
		t.Fatalf("legacy attach initial lease stage = %q, want %q (a mid-attach crash must be reclaimable, not misread as a completed allocation)",
			stageAtAttach, deviceLeaseStageInProgress)
	}
}

// TestRecoverDeviceLeases_InProgressVMExists_Reclaims: an existing VM with an in_progress
// lease recording a device it still owns + has bound + still carries in its live guest
// must, at startup recovery, have that device FIRST membership-detached from the guest,
// THEN unbound + owner-released, and the lease entry removed — treated EXACTLY like a
// rollback_incomplete lease. RED against current code: with no in_progress handling the
// vm!=nil branch falls to the else and clears the entry WITHOUT releasing, so the device
// stays owned + bound (leaked).
func TestRecoverDeviceLeases_InProgressVMExists_Reclaims(t *testing.T) {
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
	fake.SetState("vm-a", libvirtfake.StateRunning) // live domain running → dispRunning → LIVE reclaim
	fake.SetActiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")

	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageInProgress, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write in_progress lease: %v", err)
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
		t.Fatal("recovery must remove the reclaimed in_progress lease entry")
	}
}

// TestRecoverDeviceLeases_InProgressReclaimedEvenIfMarkNeverRan: the crash-before-mark
// case. markDeviceLeaseRollbackIncomplete never ran (the crash happened during the bind
// or guest-attach loop, before any compensation), so the lease is still at its raw
// initial Stage in_progress. Recovery must STILL reclaim it — proving the mark is a
// refinement, not the safety anchor: the initial in_progress stage is itself the reclaim
// trigger. RED against current code: an unmarked in_progress lease falls to the else
// branch and is cleared without release, leaking the device.
func TestRecoverDeviceLeases_InProgressReclaimedEvenIfMarkNeverRan(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// A running VM that owns + has bound the leased device, but whose live guest does NOT
	// carry the hostdev — the crash hit during the bind loop, AFTER owning + vfio-binding the
	// device but BEFORE the guest AttachHostdev landed. So the guest detach is a clean no-op
	// and the reclaim is purely unbind + owner-release. The domain XML must still resolve so
	// the membership-aware guest detach can fail-closed-read it (and find nothing to detach).
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
	fake.SetState("vm-a", libvirtfake.StateRunning) // live domain running → dispRunning → LIVE reclaim
	fake.SetActiveXML("vm-a", "<domain><name>vm-a</name><devices></devices></domain>")

	// The raw initial lease: Stage in_progress, never upgraded to rollback_incomplete.
	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageInProgress, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write in_progress lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("recovery must reclaim (unbind) the leaked device even though the mark never ran, got %d unbinds", n)
	}
	if fs.isBound(addr) {
		t.Fatal("recovery must leave the reclaimed device unbound (no owned+bound leak)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("recovery must owner-release the reclaimed device, got %q", o)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("recovery must remove the reclaimed in_progress lease entry")
	}
}
