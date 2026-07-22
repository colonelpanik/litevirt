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

// FIX-32: the device lease must be fail-CLOSED at both ends of its lifetime.
//
// Fix A — a failed durable pre-bind lease write must abort BEFORE the vfio bind, releasing
// the ownership already CAS-claimed. A crash after a bind with no recovery record is exactly
// the leak the lease exists to prevent.
//
// Fix B — a SUCCESSFUL legacy running-attach must durably transition its (in_progress,
// reclaim-triggering) lease to a completed (bound) stage BEFORE the best-effort removal, so
// that even if the removal fails the surviving lease is cleared-not-reclaimed by recovery and
// the working device is never torn down.

// TestAcquireDeviceLeases_BeginLeaseWriteFails_ReleasesClaimsAndAborts (Fix A): when the
// durable pre-bind device-lease Write cannot be recorded, acquireDeviceLeases must FAIL
// CLOSED — release the ownership it CAS-claimed and abort BEFORE the vfio bind. RED against
// pre-fix code: beginDeviceLease logged the write error and returned a no-op closure, so the
// bind loop ran and left the device owned + vfio-bound with NO recovery record.
func TestAcquireDeviceLeases_BeginLeaseWriteFails_ReleasesClaimsAndAborts(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // operation_protocol active → the durable lease IS attempted
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedPCIGPU(t, s, addr, -1)

	// The durable device-lease Write fails for THIS VM's lease op-id.
	s.opJournal.FailWrite = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected device-lease journal write failure")
		}
		return nil
	}

	_, _, err := s.acquireDeviceLeases(ctx, "vm-a", []ResolvedMember{{Address: addr}}, deviceLeaseStageBound)
	if err == nil {
		t.Fatal("a failed durable device-lease write must fail the acquire (fail closed), got nil error")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("the CAS-claimed ownership must be released on abort, still owned by %q", o)
	}
	if n := fs.bindCount(); n != 0 {
		t.Fatalf("no vfio bind must happen when the pre-bind lease could not be recorded, got %d bind(s)", n)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("no device lease should survive a failed begin")
	}
}

// TestAttachPCI_LegacySuccess_RemoveFails_LeaseBoundNotInProgress (Fix B): a legacy
// running-attach that SUCCEEDS must durably transition its in_progress lease to a completed
// (bound) stage BEFORE the best-effort removal, so a failed removal leaves a lease recovery
// CLEARS rather than reclaims. RED against pre-fix code: the success path called the
// remove-only finish(), so a failed remove left the lease at Stage in_progress → startup
// recovery would DETACH/RELEASE the successfully-attached device.
func TestAttachPCI_LegacySuccess_RemoveFails_LeaseBoundNotInProgress(t *testing.T) {
	const addr = "0000:00:00.0"
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

	// The best-effort lease removal on the success path fails.
	s.opJournal.FailRemove = func(opID string) error {
		if opID == deviceLeaseOpID("vm-a") {
			return errors.New("injected device-lease removal failure")
		}
		return nil
	}

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm-a", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("the legacy attach must SUCCEED (all guest attaches ok), got %v", err)
	}

	e, found, err := s.opJournal.Read(deviceLeaseOpID("vm-a"))
	if err != nil {
		t.Fatalf("read surviving lease: %v", err)
	}
	if !found {
		t.Fatal("a lease whose removal failed must survive so recovery can reason about it")
	}
	if e.Stage != deviceLeaseStageBound {
		t.Fatalf("a successful attach must transition the lease to %q before removal, got %q (a surviving in_progress lease would make recovery tear down the working device)",
			deviceLeaseStageBound, e.Stage)
	}
}

// TestRecoverDeviceLeases_SurvivedCompletedLease_ClearsNoReclaim (Fix B end-to-end): a
// surviving Stage bound lease (written by completeDeviceLease before a removal that did not
// complete) for a running VM whose device is attached must be CLEARED at startup recovery
// WITHOUT reclaiming — the ownership + realization rows are the durable record now, so the
// working device is not torn down. Protects the completed path.
func TestRecoverDeviceLeases_SurvivedCompletedLease_ClearsNoReclaim(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-a", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr) // the device is attached + vfio-bound (a completed allocation)

	// A surviving completed lease: Stage bound (completeDeviceLease ran, its removal did not).
	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageBound, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write bound lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("a completed (bound) lease must NOT be reclaimed, got %d unbind(s)", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("recovery must leave the successfully-attached device bound (not torn down)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm-a" {
		t.Fatalf("recovery must retain ownership of a completed allocation, got %q", o)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("recovery must clear the completed (bound) lease entry")
	}
}
