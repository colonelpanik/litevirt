package grpcapi

import (
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-34: a legacy attach must NOT acknowledge success when completion could not be
// durably recorded.
//
// completeDeviceLease transitions the in_progress lease to bound, then best-effort removes
// it. Those two journal ops are NOT independent: one PERSISTENT filesystem fault (ENOSPC, a
// read-only remount, a journal-dir I/O error) fails BOTH. When both fail the original
// in_progress lease survives, yet the RPC used to ACK success anyway — so startup recovery
// misread the surviving in_progress as an incomplete attach and tore down the acknowledged,
// working device. Fix A makes completeDeviceLease report whether a SAFE outcome (durably
// bound OR durably removed) was established; Fix B makes the attach drive a rollback and NOT
// ACK success on that error.

// TestAttachPCI_LegacySuccess_JournalPersistentlyDegraded_RollsBackNoAck (Fix B): a legacy
// running-attach whose live guest attaches ALL succeed, but whose completion cannot be
// durably recorded (a persistent journal fault fails the bound-transition Write AND the
// Remove), must NOT acknowledge success — it rolls the attach back (guest-detach + vfio
// unbind + owner-release) so the returned error matches reality, and the surviving
// in_progress lease becomes a harmless no-op reclaim (the device is already unbound +
// unowned). RED against current code: the success path ACKs while the in_progress lease
// survives → recovery would reclaim the ACK'd device.
func TestAttachPCI_LegacySuccess_JournalPersistentlyDegraded_RollsBackNoAck(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // operation_protocol latched → the durable device lease IS written
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm-a", "running")
	fake.SetState("vm-a", libvirtfake.StateRunning) // running domain → live hotplug path
	seedPCIGPU(t, s, addr, -1)                      // single-member device (no IOMMU siblings)

	// A PERSISTENT journal fault that begins AFTER the pre-bind lease is durably written: the
	// begin Write (#1, in_progress) still succeeds — so the attach binds + guest-attaches —
	// but the completion's bound-transition Write (#2) AND its best-effort Remove BOTH fail,
	// exactly as one FS fault (ENOSPC / read-only remount) fails both.
	var writeN int
	s.opJournal.FailWrite = func(opID string) error {
		if opID != deviceLeaseOpID("vm-a") {
			return nil
		}
		writeN++
		if writeN >= 2 { // #1 = begin (in_progress); #2 = completion transition (bound)
			return errors.New("injected persistent journal write fault")
		}
		return nil
	}
	s.opJournal.FailRemove = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected persistent journal remove fault")
		}
		return nil
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	})

	// (a) The attach must NOT acknowledge success — a surviving in_progress lease + an ACK is
	// exactly the P1: recovery would reclaim (tear down) the acknowledged, working device.
	if err == nil {
		t.Fatal("a legacy attach whose completion could not be durably recorded must NOT ACK success")
	}

	// (b) The device was rolled back: inverse-detached from the live guest, then unbound +
	// owner-released. The rollback uses libvirt/vfio/corrosion (NOT the journal), so it works
	// even with a degraded journal.
	if n := fake.DetachHostdevCount(); n != 1 {
		t.Fatalf("the attached device must be inverse-detached from the guest on rollback, got %d detaches", n)
	}
	if guestHasHostdev(t, s, "vm-a", addr) {
		t.Fatal("the device must not remain attached to the live guest after rollback")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("the device must be owner-released on rollback, still owned by %q", o)
	}
	if fs.isBound(addr) {
		t.Fatal("the device must be vfio-unbound on rollback")
	}
	// The lease that could not be cleared survives at in_progress — a HARMLESS no-op reclaim on
	// restart now (the device is already unbound + unowned), never a reclaim of an ACK'd device
	// (no success was ACK'd).
	if e, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found && e.Stage != deviceLeaseStageInProgress {
		t.Fatalf("the degraded-journal lease should survive at in_progress, got stage %q", e.Stage)
	}
}

// seedInProgressLease writes a fresh in_progress device lease for vmName carrying addr, the
// state a successful legacy attach reaches completeDeviceLease in. Written BEFORE any failure
// hooks are installed so the seed itself never trips them.
func seedInProgressLease(t *testing.T, s *Server, vmName, addr string) {
	t.Helper()
	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID(vmName), ResourceID: vmName, Kind: deviceLeaseKind,
		Stage: deviceLeaseStageInProgress, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write in_progress lease: %v", err)
	}
}

// TestCompleteDeviceLease_WriteAndRemoveBothFail_ReturnsError (Fix A): the single-root-cause
// degraded-journal case. When BOTH the bound-transition Write AND the best-effort Remove fail
// (one FS fault fails both), completeDeviceLease must return an error — NEITHER safe outcome
// was established, so the surviving in_progress lease would make recovery reclaim the ACK'd
// device. RED against pre-fix code: completeDeviceLease returned nothing (no way to signal).
func TestCompleteDeviceLease_WriteAndRemoveBothFail_ReturnsError(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	restore := vfio.SetFS(newPCIUnbindRecordingFS())
	defer restore()

	seedInProgressLease(t, s, "vm-a", addr)

	s.opJournal.FailWrite = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected bound-transition write fault")
		}
		return nil
	}
	s.opJournal.FailRemove = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected removal fault")
		}
		return nil
	}

	if err := s.completeDeviceLease("vm-a"); err == nil {
		t.Fatal("completeDeviceLease must return an error when NEITHER a bound-transition nor a removal persisted")
	}

	// The surviving lease is still the reclaim-triggering in_progress (nothing safe persisted).
	s.opJournal.FailRead = nil
	e, found, err := s.opJournal.Read(deviceLeaseOpID("vm-a"))
	if err != nil {
		t.Fatalf("read surviving lease: %v", err)
	}
	if !found {
		t.Fatal("with both journal ops failing the in_progress lease must survive")
	}
	if e.Stage != deviceLeaseStageInProgress {
		t.Fatalf("the surviving lease stage = %q, want %q (neither safe outcome persisted)", e.Stage, deviceLeaseStageInProgress)
	}
}

// TestCompleteDeviceLease_WriteFailsRemoveOK_ReturnsNil (Fix A): exactly ONE op fails — the
// bound-transition Write fails but the Remove SUCCEEDS. A safe outcome persisted (the lease is
// durably removed → recovery has nothing to reclaim), so completeDeviceLease returns nil.
func TestCompleteDeviceLease_WriteFailsRemoveOK_ReturnsNil(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	restore := vfio.SetFS(newPCIUnbindRecordingFS())
	defer restore()

	seedInProgressLease(t, s, "vm-a", addr)

	s.opJournal.FailWrite = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected bound-transition write fault")
		}
		return nil
	}
	// Remove is NOT injected → it succeeds.

	if err := s.completeDeviceLease("vm-a"); err != nil {
		t.Fatalf("a successful removal is a safe outcome; completeDeviceLease must return nil, got %v", err)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("the lease must be durably removed (recovery then has nothing to reclaim)")
	}
}

// TestCompleteDeviceLease_WriteOKRemoveFails_ReturnsNil (Fix A): exactly ONE op fails — the
// bound-transition Write SUCCEEDS but the Remove fails. A safe outcome persisted (the lease is
// durably bound → recovery clears it WITHOUT reclamation), so completeDeviceLease returns nil.
func TestCompleteDeviceLease_WriteOKRemoveFails_ReturnsNil(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	restore := vfio.SetFS(newPCIUnbindRecordingFS())
	defer restore()

	seedInProgressLease(t, s, "vm-a", addr)

	s.opJournal.FailRemove = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected removal fault")
		}
		return nil
	}
	// Write is NOT injected → the bound transition persists.

	if err := s.completeDeviceLease("vm-a"); err != nil {
		t.Fatalf("a durably bound lease is a safe outcome; completeDeviceLease must return nil, got %v", err)
	}
	e, found, err := s.opJournal.Read(deviceLeaseOpID("vm-a"))
	if err != nil {
		t.Fatalf("read surviving lease: %v", err)
	}
	if !found {
		t.Fatal("a lease whose removal failed must survive so recovery can reason about it")
	}
	if e.Stage != deviceLeaseStageBound {
		t.Fatalf("the surviving lease must be bound (recovery clears it, no reclaim), got %q", e.Stage)
	}
}

// TestAttachPCI_LegacySuccess_RemoveFails_StillSucceeds (regression — the FIX-32 Fix B case):
// when only the best-effort Remove fails, the bound transition persists → a safe outcome →
// completeDeviceLease returns nil → the legacy attach SUCCEEDS and the surviving lease is
// bound (recovery clears it, no reclaim). Fix A must NOT over-report an error here, and Fix B
// must NOT over-roll-back a durably-completed attach.
func TestAttachPCI_LegacySuccess_RemoveFails_StillSucceeds(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm-a", "running")
	fake.SetState("vm-a", libvirtfake.StateRunning) // running domain → live hotplug path
	seedPCIGPU(t, s, addr, -1)                      // single-member device (no IOMMU siblings)

	// Only the best-effort lease removal fails; the bound-transition Write succeeds.
	s.opJournal.FailRemove = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected device-lease removal failure")
		}
		return nil
	}

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("a durably-bound completion is a safe outcome; the attach must SUCCEED, got %v", err)
	}

	// NOT rolled back: the device stays in the guest, owned, and vfio-bound.
	if n := fake.DetachHostdevCount(); n != 0 {
		t.Fatalf("a durably-completed attach must NOT be rolled back, got %d guest detaches", n)
	}
	if !guestHasHostdev(t, s, "vm-a", addr) {
		t.Fatal("a successful attach must leave the device attached to the live guest")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm-a" {
		t.Fatalf("a successful attach must retain ownership, got %q", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("a successful attach must leave the device vfio-bound")
	}
	// The surviving lease is bound → recovery clears it without reclamation.
	e, found, err := s.opJournal.Read(deviceLeaseOpID("vm-a"))
	if err != nil {
		t.Fatalf("read surviving lease: %v", err)
	}
	if !found {
		t.Fatal("a lease whose removal failed must survive so recovery can reason about it")
	}
	if e.Stage != deviceLeaseStageBound {
		t.Fatalf("a successful attach must transition the lease to %q before removal, got %q", deviceLeaseStageBound, e.Stage)
	}
}
