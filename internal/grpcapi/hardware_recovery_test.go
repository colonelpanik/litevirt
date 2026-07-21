package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// rootOnlyDomainXML is a minimal persistent definition carrying ONLY the root
// disk (target vda), so a stopped VM has a readable inactive definition that a
// data-disk attach/detach can diverge from.
func rootOnlyDomainXML(name string) string {
	return "<domain type='kvm'><name>" + name + "</name><devices>" +
		"<disk type='file' device='disk'><source file='/x/" + name + "-root.qcow2'/><target dev='vda' bus='virtio'/></disk>" +
		"</devices></domain>"
}

// beginWedgedDeviceOp reproduces the on-disk state a crash leaves mid device
// operation: it claims the VM's mutation barrier for a NON-TERMINAL device
// operation (via the real BeginVMOperation, which bumps spec_generation and
// records the 'planned' step), appends the extra happy-path steps the crash had
// recorded, and writes the matching host-local opjournal entry. It returns the
// operation id + the owner epoch / (bumped) spec generation so the test can read
// the operation's reduced state afterward.
func beginWedgedDeviceOp(t *testing.T, ctx context.Context, s *Server, vmName string,
	kind corrosion.OperationKind, reqHash string, extraSteps []string, artifacts map[string]string) (opID string, epoch, newGen int64) {
	t.Helper()
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): err=%v nil=%v", vmName, err, vm == nil)
	}
	method := "AttachDevice"
	journalKind := "device_attach"
	if kind == corrosion.OpDeviceDetach {
		method, journalKind = "DetachDevice", "device_detach"
	}
	opID = "wedged-" + vmName + "-" + string(kind)
	op := corrosion.OperationRecord{
		ID: opID, Method: method, Principal: "admin@local", Project: "_default",
		ResourceKind: "vm", ResourceID: vmName, OperationKind: string(kind), RequestHash: reqHash,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil || !applied {
		t.Fatalf("BeginVMOperation(%s): applied=%v err=%v", vmName, applied, err)
	}
	epoch = vm.OwnerEpoch
	newGen = vm.SpecGeneration + 1
	for _, st := range extraSteps {
		if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
			OperationID: opID, OwnerEpoch: epoch, StepName: st,
		}); err != nil {
			t.Fatalf("append step %q: %v", st, err)
		}
	}
	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: opID, OwnerEpoch: epoch, SpecGeneration: newGen, ResourceID: vmName,
		Kind: journalKind, Stage: "planned", Artifacts: artifacts,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("write journal entry: %v", err)
	}
	return opID, epoch, newGen
}

// TestRecoverHardwareOperations_AttachRollsBack: a device_attach wedged
// mid-attach (op-owned backing file created, no row committed, not verified)
// converges by ROLLING BACK — the op-owned file is deleted, no row survives, the
// operation is terminal (failed), and the barrier is cleared.
func TestRecoverHardwareOperations_AttachRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "stopped")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetInactiveXML("vm1", rootOnlyDomainXML("vm1"))

	// Partial: the op exclusively created its backing file, but crashed before
	// committing the row / reconciling the definition.
	diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned partial"), 0o644); err != nil {
		t.Fatalf("write partial file: %v", err)
	}

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
			"prior_inactive_xml":        rootOnlyDomainXML("vm1"),
		})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared after recovery: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if !corrosion.IsOperationTerminal(state) {
		t.Fatalf("operation not terminal after rollback: state=%q", state)
	}
	if state != corrosion.OpStepFailed {
		t.Errorf("operation state = %q, want failed", state)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatalf("rolled-back attach left a data1 row: %+v", disks)
	}
	if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
		t.Fatalf("rollback must delete the op-owned backing file %s (stat err=%v)", diskPath, statErr)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed rollback")
	}
}

// TestRecoverHardwareOperations_AttachCompletes: a device_attach wedged at the
// 'attached' step (all side effects applied + verified, only CompleteVMOperation
// missing) converges by COMPLETING — the device stays present and the operation
// reaches the completed terminal with the barrier cleared.
func TestRecoverHardwareOperations_AttachCompletes(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "stopped")
	fake := s.virt.(*libvirtfake.Fake)
	// Full side effects: the data1 row is committed and the persistent definition
	// carries it (target vdb).
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1 row: %v", err)
	}
	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"<disk type='file' device='disk'><source file='/x/vm1-data1.qcow2'/><target dev='vdb' bus='virtio'/></disk>"+
		"</devices></domain>")

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed, corrosion.OpStepBound, corrosion.OpStepAttached},
		map[string]string{"disk_name": "data1", "target_dev": "vdb", "bus": "virtio"})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared after recovery: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepCompleted {
		t.Fatalf("operation state = %q, want completed", state)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if !hasDiskName(disks, "data1") {
		t.Fatalf("completed attach dropped the data1 row: %+v", disks)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after completion")
	}
}

// TestRecoverHardwareOperations_DetachRollsForward: a device_detach wedged
// mid-detach converges by rolling FORWARD — the device is removed from the live
// domain AND the persistent definition, the row is soft-deleted, the operation
// completes, and it is NEVER re-attached.
func TestRecoverHardwareOperations_DetachRollsForward(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	// Fully attach data1 so there is a real row + live source + persistent config.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	td := diskTargetDev(t, ctx, s, "vm1", "data1")
	attachN := fake.AttachDiskCount()

	// Wedge a detach that crashed after claiming the barrier but before the live
	// detach / row soft-delete.
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachDiskRequestHash("vm1", "data1"),
		[]string{corrosion.OpStepReserved},
		map[string]string{"disk_name": "data1", "target_dev": td})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared after recovery: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepCompleted {
		t.Fatalf("detach recovery state = %q, want completed", state)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatalf("forward detach left the data1 row: %+v", disks)
	}
	if srcs, _ := fake.DomainDiskSources("vm1"); func() bool { _, ok := srcs[td]; return ok }() {
		t.Fatalf("disk %s still present in the live domain after forward detach", td)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); diskDevInXML(inactive, td) {
		t.Fatalf("disk %s still present in the persistent definition after forward detach:\n%s", td, inactive)
	}
	if n := fake.AttachDiskCount(); n != attachN {
		t.Fatalf("recovery re-attached the disk: AttachDisk count %d -> %d", attachN, n)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed detach")
	}
}

// TestRecoverHardwareOperations_Idempotent: running recovery twice is safe — the
// second pass is a no-op on the now-terminal operation (no re-detach, no error).
func TestRecoverHardwareOperations_Idempotent(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	td := diskTargetDev(t, ctx, s, "vm1", "data1")
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachDiskRequestHash("vm1", "data1"),
		[]string{corrosion.OpStepReserved},
		map[string]string{"disk_name": "data1", "target_dev": td})

	s.RecoverHardwareOperations(ctx)
	detachAfterFirst := fake.DetachDiskCount()
	state1, _, _ := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if state1 != corrosion.OpStepCompleted {
		t.Fatalf("first recovery did not complete the detach: state=%q", state1)
	}

	// Second pass: must not touch the domain again nor change the terminal state.
	s.RecoverHardwareOperations(ctx)
	if n := fake.DetachDiskCount(); n != detachAfterFirst {
		t.Fatalf("second recovery re-ran the detach: count %d -> %d", detachAfterFirst, n)
	}
	state2, _, _ := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if state2 != corrosion.OpStepCompleted {
		t.Fatalf("second recovery changed the terminal state: %q", state2)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier reappeared after the second pass: %q", vm.ActiveOperationID)
	}
}

// TestRecoverHardwareOperations_UnrecoverableLeftNonTerminal: when a compensation
// step cannot complete (here the inverse live-detach fails), the operation is
// left NON-TERMINAL (recovery-required) rather than force-completed.
func TestRecoverHardwareOperations_UnrecoverableLeftNonTerminal(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	// The just-attached disk is live-present but the persistent config never got
	// it (a live/config divergence) — so an attach recovery must roll BACK, and the
	// inverse live-detach it performs is injected to fail.
	fake.SetInactiveXML("vm1", rootOnlyDomainXML("vm1")) // readable, WITHOUT vdb
	fake.SetDiskSource("vm1", "vdb", filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"))
	diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	fake.FailDetachDisk = func(_, _ string) error { return status.Error(codes.Internal, "inverse-detach boom") }

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed, corrosion.OpStepBound},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
		})

	s.RecoverHardwareOperations(ctx)

	// Barrier still held, op still NON-TERMINAL (recovery-required), not force-completed.
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != opID {
		t.Fatalf("barrier cleared despite incomplete compensation: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if corrosion.IsOperationTerminal(state) {
		t.Fatalf("operation was force-terminated on an incomplete rollback: state=%q", state)
	}
	if _, found, _ := s.opJournal.Read(opID); !found {
		t.Fatal("journal entry must be retained while the operation is still recovery-required")
	}
}

// TestRecoverDeviceLeases_SkipsDeviceOps confirms RecoverDeviceLeases leaves
// device_attach / device_detach journal entries untouched (distinct Kind) — they
// are recovered by RecoverHardwareOperations, not the device-lease path.
func TestRecoverDeviceLeases_SkipsDeviceOps(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	j, _ := opjournal.Open(t.TempDir())
	s.SetOpJournal(j)

	if err := j.Write(opjournal.Entry{
		OperationID: "op-attach", ResourceID: "vm1", Kind: "device_attach", Stage: "planned",
		Artifacts: map[string]string{"disk_name": "data1", "target_dev": "vdb"},
	}); err != nil {
		t.Fatalf("write device_attach entry: %v", err)
	}
	if err := j.Write(opjournal.Entry{
		OperationID: "op-detach", ResourceID: "vm1", Kind: "device_detach", Stage: "planned",
		Artifacts: map[string]string{"mac": "52:54:00:aa:bb:cc"},
	}); err != nil {
		t.Fatalf("write device_detach entry: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	if _, found, _ := j.Read("op-attach"); !found {
		t.Fatal("RecoverDeviceLeases must NOT remove a device_attach entry")
	}
	if _, found, _ := j.Read("op-detach"); !found {
		t.Fatal("RecoverDeviceLeases must NOT remove a device_detach entry")
	}
}
