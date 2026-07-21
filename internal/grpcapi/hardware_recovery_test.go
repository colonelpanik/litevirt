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
	"github.com/litevirt/litevirt/internal/vfio"
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
	fake.SetState("vm1", libvirtfake.StateShutdown) // the domain is POSITIVELY shut off
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
	fake.SetState("vm1", libvirtfake.StateShutdown) // the domain is POSITIVELY shut off
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

// TestCompleteRecoveredOp_CASNotApplied_KeepsJournal calls completeRecoveredOp
// directly with a stale owner epoch — as if ownership moved underneath the
// wedged op between the recovery scan and this completion (a fence/migrate) —
// so CompleteVMOperation's terminal CAS does not match the VM's real
// (unbumped) owner_epoch and applied=false. The bug: completeRecoveredOp
// discarded `applied` and removed the journal unconditionally whenever
// CompleteVMOperation returned err==nil, even when applied==false, stranding
// the VM with an active barrier and no journal to converge it. The fix must
// retain the journal and leave the barrier held.
func TestCompleteRecoveredOp_CASNotApplied_KeepsJournal(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "stopped")

	opID, epoch, newGen := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed, corrosion.OpStepBound, corrosion.OpStepAttached},
		map[string]string{"disk_name": "data1", "target_dev": "vdb", "bus": "virtio"})

	view := &corrosion.VMOperationView{
		VMName: "vm1", OwnerEpoch: epoch + 1, SpecGeneration: newGen, ActiveOperationID: opID,
	}
	s.completeRecoveredOp(ctx, "vm1", view, corrosion.OpDeviceAttach)

	if _, found, err := s.opJournal.Read(opID); err != nil || !found {
		t.Fatalf("op-journal entry must be RETAINED when the completion CAS did not apply: found=%v err=%v", found, err)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != opID {
		t.Fatalf("mutation barrier cleared despite a non-applied completion CAS: active_operation_id=%q, want %q",
			vm.ActiveOperationID, opID)
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
	fake.SetState("vm1", libvirtfake.StateRunning) // live domain is up (recovery reads live state, not vm.State)

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
	fake.SetState("vm1", libvirtfake.StateRunning) // live domain is up (recovery reads live state, not vm.State)

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
	fake.SetState("vm1", libvirtfake.StateRunning) // live domain is up (recovery reads live state, not vm.State)

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

// TestRecoverDiskAttach_UnknownDomainState_NoCompensation: when the live domain
// state is INDETERMINATE (DomainState errors), recovery must perform NO
// compensation this pass — it must NOT take the stopped rollback path (which would
// delete the backing file out from under a possibly-running VM and tombstone the
// desired-state row). The op is left recovery-required (barrier + journal intact)
// so a later pass retries once the state is legible.
func TestRecoverDiskAttach_UnknownDomainState_NoCompensation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	// The live domain state is UNREADABLE — the exact condition the bug mistook for
	// "stopped" and used to justify the destructive file-delete rollback. Recovery
	// classifies via DomainStateReason, so fail THAT to exercise the indeterminate path.
	fake.FailDomainStateReason = func(string) error {
		return status.Error(codes.Internal, "libvirt connection lost")
	}

	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"<disk type='file' device='disk'><source file='/x/vm1-data1.qcow2'/><target dev='vdb' bus='virtio'/></disk>"+
		"</devices></domain>")
	fake.SetDiskSource("vm1", "vdb", filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1 row: %v", err)
	}
	diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned; a running VM may be using it"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
		})

	s.RecoverHardwareOperations(ctx)

	// No compensation: the backing file survives, the row survives, and the op is
	// left recovery-required (barrier held + non-terminal + journal retained).
	if _, statErr := os.Stat(diskPath); statErr != nil {
		t.Fatalf("indeterminate state must NOT delete the backing file (stat err=%v)", statErr)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1"); !hasDiskName(disks, "data1") {
		t.Fatalf("indeterminate state must NOT tombstone the desired-state row: %+v", disks)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != opID {
		t.Fatalf("barrier must stay held while the domain state is indeterminate: active_operation_id=%q, want %q",
			vm.ActiveOperationID, opID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if corrosion.IsOperationTerminal(state) {
		t.Fatalf("op must be left non-terminal on an indeterminate domain state: state=%q", state)
	}
	if _, found, _ := s.opJournal.Read(opID); !found {
		t.Fatal("journal entry must be retained while the operation is recovery-required")
	}
}

// seedRecoverableDiskAttach reproduces a disk-attach wedged mid-attach: the data
// disk (vdb) is present in the inactive definition + live sources, its row is
// written, its op-owned backing file exists, and the mutation barrier points at a
// non-terminal device_attach carrying the post-create ownership artifact. It
// returns the backing-file path, the op id, and the owner epoch.
func seedRecoverableDiskAttach(t *testing.T, ctx context.Context, s *Server) (diskPath, opID string, epoch int64) {
	t.Helper()
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"<disk type='file' device='disk'><source file='/x/vm1-data1.qcow2'/><target dev='vdb' bus='virtio'/></disk>"+
		"</devices></domain>")
	fake.SetDiskSource("vm1", "vdb", filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1 row: %v", err)
	}
	diskPath, _ = libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned; a live guest may be using it"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	opID, epoch, _ = beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
		})
	return diskPath, opID, epoch
}

// assertDiskAttachDeferred asserts recovery performed NO compensation: the backing
// file survives, the desired-state row survives, the barrier stays held, the op is
// non-terminal, and the journal entry is retained (recovery-required, retry later).
func assertDiskAttachDeferred(t *testing.T, ctx context.Context, s *Server, diskPath, opID string, epoch int64) {
	t.Helper()
	if _, statErr := os.Stat(diskPath); statErr != nil {
		t.Fatalf("deferred recovery must NOT delete the backing file (stat err=%v)", statErr)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1"); !hasDiskName(disks, "data1") {
		t.Fatalf("deferred recovery must NOT tombstone the desired-state row: %+v", disks)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != opID {
		t.Fatalf("barrier must stay held while recovery defers: active_operation_id=%q, want %q", vm.ActiveOperationID, opID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if corrosion.IsOperationTerminal(state) {
		t.Fatalf("op must be left non-terminal when recovery defers: state=%q", state)
	}
	if _, found, _ := s.opJournal.Read(opID); !found {
		t.Fatal("journal entry must be retained while the operation is recovery-required")
	}
}

// TestRecoverDiskAttach_Paused_NoCompensation: a PAUSED domain reads coarse
// "stopped" (DomainState collapses paused/shut-off/pm-suspended together), but it is
// still ACTIVE with its disks attached. Recovery must NOT take the destructive
// stopped rollback (delete backing file, tombstone row) — it must DEFER on the
// "paused" reason and leave the op recovery-required.
func TestRecoverDiskAttach_Paused_NoCompensation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateShutdown) // coarse "stopped"
	fake.SetStateReason("vm1", "paused")            // …but the domain is PAUSED (active)

	diskPath, opID, epoch := seedRecoverableDiskAttach(t, ctx, s)
	s.RecoverHardwareOperations(ctx)
	assertDiskAttachDeferred(t, ctx, s, diskPath, opID, epoch)
}

// TestRecoverDiskAttach_PMSuspended_NoCompensation: a PM-suspended (S3) domain also
// reads coarse "stopped" while still holding its disks. Recovery must DEFER on the
// "pmsuspended" reason, performing no compensation.
func TestRecoverDiskAttach_PMSuspended_NoCompensation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateShutdown) // coarse "stopped"
	fake.SetStateReason("vm1", "pmsuspended")       // …but the domain is PM-suspended (active)

	diskPath, opID, epoch := seedRecoverableDiskAttach(t, ctx, s)
	s.RecoverHardwareOperations(ctx)
	assertDiskAttachDeferred(t, ctx, s, diskPath, opID, epoch)
}

// TestRecoverDiskAttach_Shutoff_RollsBack guards that the tri-state gating did NOT
// break legitimate stopped recovery: a POSITIVELY shut-off domain still takes the
// stopped rollback path (file deleted, row tombstoned, barrier cleared).
func TestRecoverDiskAttach_Shutoff_RollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running") // vm.State survives a host reboot as "running"
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateShutdown) // the domain is POSITIVELY shut off

	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"<disk type='file' device='disk'><source file='/x/vm1-data1.qcow2'/><target dev='vdb' bus='virtio'/></disk>"+
		"</devices></domain>")
	fake.SetDiskSource("vm1", "vdb", filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1 row: %v", err)
	}
	diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
		})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("shut-off rollback must clear the barrier: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepFailed {
		t.Fatalf("op state = %q, want failed", state)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1"); hasDiskName(disks, "data1") {
		t.Fatalf("shut-off rollback must tombstone the row: %+v", disks)
	}
	if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
		t.Fatalf("shut-off rollback must delete the op-owned backing file (stat err=%v)", statErr)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); diskDevInXML(inactive, "vdb") {
		t.Fatalf("shut-off rollback must reconcile data1 (vdb) OUT of the persistent definition:\n%s", inactive)
	}
}

// TestRecoverDiskAttach_FileOwnership_OnlyPostCreateArtifact: final-path ownership is
// keyed on the PRESENCE of the post-publish journal artifact, never os.Stat.
// executeDiskAttach records "file_created_by_operation" only AFTER staging succeeds and
// BEFORE publishing, and only for a final path it verified was free, so a crash that
// aborts before publishing leaves no ownership claim over a pre-existing/foreign file
// and recovery never deletes it.
func TestRecoverDiskAttach_FileOwnership_OnlyPostCreateArtifact(t *testing.T) {
	// Case 1 (RED→GREEN): a FOREIGN file already at the final path aborts the attach
	// before it claims ownership → the retained planned entry asserts NO ownership, and
	// recovery does NOT delete the foreign file.
	t.Run("planned_stage_records_no_ownership_no_wrongful_delete", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		ctx := adminCtx()
		seedDiskVM(t, s, "vm1", "stopped")
		fake := s.virt.(*libvirtfake.Fake)
		fake.SetState("vm1", libvirtfake.StateShutdown)
		fake.SetInactiveXML("vm1", rootOnlyDomainXML("vm1"))

		vm, err := corrosion.GetVM(ctx, s.db, "vm1")
		if err != nil || vm == nil {
			t.Fatalf("GetVM: err=%v nil=%v", err, vm == nil)
		}

		diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
		if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// A FOREIGN file materializes at the exact path the op would use — created by
		// ANOTHER actor, NOT by this operation. It must survive recovery untouched.
		const foreign = "FOREIGN FILE — not created by this operation"
		if err := os.WriteFile(diskPath, []byte(foreign), 0o644); err != nil {
			t.Fatalf("write foreign file: %v", err)
		}

		// Claim the barrier, then drive the REAL executeDiskAttach. The foreign file makes
		// the pre-staging final-path check fail (before any ownership is journaled); a
		// stale spec generation makes the terminal-failure CAS not apply, so the PLANNED
		// journal entry + barrier are RETAINED for recovery — the state a real crash leaves.
		opID := "own-vm1-attach"
		reqHash := attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"})
		op := corrosion.OperationRecord{
			ID: opID, Method: "AttachDevice", Principal: "admin@local", Project: "_default",
			ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(corrosion.OpDeviceAttach), RequestHash: reqHash,
		}
		applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
		if err != nil || !applied {
			t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
		}
		epoch := vm.OwnerEpoch
		staleGen := vm.SpecGeneration + 100 // never matches the real (bumped) spec_generation

		_, _ = s.executeDiskAttach(ctx, vm, &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}, "virtio",
			diskPath, 5<<30, 5<<30, "vdb", opID, epoch, staleGen, false)

		// The retained PLANNED entry must NOT claim ownership of a file never created.
		entry, found, err := s.opJournal.Read(opID)
		if err != nil || !found {
			t.Fatalf("planned journal entry must be retained: found=%v err=%v", found, err)
		}
		if got := entry.Artifacts["file_created_by_operation"]; got != "" {
			t.Fatalf("planned journal must NOT assert file ownership before create; got %q", got)
		}

		s.RecoverHardwareOperations(ctx)

		// The foreign file must survive untouched.
		if _, statErr := os.Stat(diskPath); statErr != nil {
			t.Fatalf("recovery wrongly deleted a file this op did not create (stat err=%v)", statErr)
		}
		if b, _ := os.ReadFile(diskPath); string(b) != foreign {
			t.Fatalf("recovery modified a foreign file: %q", string(b))
		}
		// Recovery still converged the op (proving it ran the rollback path, not skipped).
		vm2 := mustGetVM(t, s, "vm1")
		if vm2.ActiveOperationID != "" {
			t.Fatalf("recovery must clear the barrier: %q", vm2.ActiveOperationID)
		}
	})

	// Case 2 (guard): once the post-create ownership artifact IS present, the op-owned
	// backing file IS deleted on rollback — the fix must not disable legitimate cleanup.
	t.Run("post_create_ownership_artifact_deletes_op_owned_file", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		ctx := adminCtx()
		seedDiskVM(t, s, "vm1", "stopped")
		fake := s.virt.(*libvirtfake.Fake)
		fake.SetState("vm1", libvirtfake.StateShutdown)
		fake.SetInactiveXML("vm1", rootOnlyDomainXML("vm1"))

		diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
		if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(diskPath, []byte("op-owned"), 0o644); err != nil {
			t.Fatalf("write op file: %v", err)
		}

		opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
			attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
			[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
			map[string]string{
				"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
				"prior_inactive_xml":        rootOnlyDomainXML("vm1"),
				"file_created_by_operation": diskPath, // ownership recorded post-create
			})

		s.RecoverHardwareOperations(ctx)

		if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
			t.Fatalf("rollback must delete the op-owned backing file (stat err=%v)", statErr)
		}
		vm := mustGetVM(t, s, "vm1")
		if vm.ActiveOperationID != "" {
			t.Fatalf("barrier not cleared: %q", vm.ActiveOperationID)
		}
		state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
		if err != nil {
			t.Fatalf("read op state: %v", err)
		}
		if state != corrosion.OpStepFailed {
			t.Fatalf("op state = %q, want failed", state)
		}
	})
}

// TestRecoverDiskAttach_StagedTempCleaned: a disk attach that crashed AFTER staging
// the backing file at its op-specific temp but BEFORE publishing to the final path
// leaves a PLANNED journal entry carrying "creating_temp" (the staged path) and NO
// "file_created_by_operation" (ownership of the final path is never journaled before
// publish). Recovery must delete the op-specific temp (always safe — unique to this
// op), leave the FINAL path free (it was never published), and terminally resolve the
// op (barrier cleared). The current code has no creating_temp handling → the staged
// temp is leaked forever.
func TestRecoverDiskAttach_StagedTempCleaned(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running") // vm.State survives a host reboot as "running"
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateShutdown) // the domain is POSITIVELY shut off
	fake.SetInactiveXML("vm1", rootOnlyDomainXML("vm1"))

	// The crash left the backing file only at the OP-SPECIFIC temp; the FINAL path was
	// never published (never linked). opID is deterministic in beginWedgedDeviceOp.
	opID := "wedged-vm1-" + string(corrosion.OpDeviceAttach)
	finalPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	tempPath := finalPath + ".creating." + opID
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(tempPath, []byte("staged, not yet published"), 0o644); err != nil {
		t.Fatalf("write staged temp: %v", err)
	}

	gotOpID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"prior_inactive_xml": rootOnlyDomainXML("vm1"),
			"creating_temp":      tempPath, // staged, ownership of the final NOT yet journaled
		})
	if gotOpID != opID {
		t.Fatalf("opID mismatch: got %q want %q (temp-path derivation would be wrong)", gotOpID, opID)
	}

	s.RecoverHardwareOperations(ctx)

	// The op-specific temp is deleted (always safe — unique to this op).
	if _, statErr := os.Stat(tempPath); !os.IsNotExist(statErr) {
		t.Fatalf("recovery must delete the staged op-specific temp %s (stat err=%v)", tempPath, statErr)
	}
	// The FINAL path is free (never published) → the disk name is reusable.
	if _, statErr := os.Stat(finalPath); !os.IsNotExist(statErr) {
		t.Fatalf("final path must be free after recovering an unpublished attach (stat err=%v)", statErr)
	}
	// The op is terminally resolved and the barrier cleared.
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared after recovery: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepFailed {
		t.Fatalf("op state = %q, want failed (rolled back)", state)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed rollback")
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

// ── NIC recovery ──────────────────────────────────────────────────────────────

// TestRecoverHardwareOperations_NICAttachRollsBackTombstonesLegacyAfterLatchFlip:
// a NIC attach wedged mid-attach (authoritative vm_nics row + the pre-latch legacy
// vm_interfaces row + live-attached) converges by ROLLING BACK. The legacy row must
// be tombstoned based on its ACTUAL presence — even though hardware_v2 LATCHED
// between the crash and recovery (so a latched-flag reconstruction would wrongly
// skip it).
func TestRecoverHardwareOperations_NICAttachRollsBackTombstonesLegacyAfterLatchFlip(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // LATCHED now, at recovery time
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning) // live domain is up

	const mac = "52:54:00:aa:bb:01"
	nicID := corrosion.DeterministicNICID("vm1", mac)
	// The crash left BOTH rows written (pre-latch dual-write) and the NIC live.
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
		VMName: "vm1", ID: nicID, NetworkName: "lan", Model: "virtio", MAC: mac, Ordinal: 0,
	}); err != nil {
		t.Fatalf("seed vm_nics row: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "vm1", NetworkName: "lan", Ordinal: 0, MAC: mac,
	}); err != nil {
		t.Fatalf("seed legacy vm_interfaces row: %v", err)
	}
	if err := fake.AttachNIC("vm1", "br0", "virtio", mac); err != nil {
		t.Fatalf("seed live nic: %v", err)
	}

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachNICRequestHash("vm1", &pb.NetworkAttachment{Name: "lan", Mac: mac}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{"mac": mac, "network_name": "lan", "nic_id": nicID})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared after rollback: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepFailed {
		t.Fatalf("op state = %q, want failed", state)
	}
	if nics := liveNICRows(t, ctx, s, "vm_nics", "vm1"); len(nics) != 0 {
		t.Fatalf("rolled-back attach left a live vm_nics row: %+v", nics)
	}
	if legacy := liveNICRows(t, ctx, s, "vm_interfaces", "vm1"); len(legacy) != 0 {
		t.Fatalf("rollback must tombstone the legacy vm_interfaces row despite the latch flip: %+v", legacy)
	}
	if live, _ := fake.DumpXML("vm1"); nicMacInXML(live, mac) {
		t.Fatalf("live nic %s not inverse-detached on rollback", mac)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed rollback")
	}
}

// TestRecoverHardwareOperations_NICDetachRollsForward: a NIC detach wedged
// mid-detach converges by rolling FORWARD — the NIC leaves the live domain AND the
// persistent definition, the row is tombstoned, the op completes, and it is NEVER
// re-attached.
func TestRecoverHardwareOperations_NICDetachRollsForward(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning)

	const mac = "52:54:00:aa:bb:02"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	nicID := corrosion.DeterministicNICID("vm1", mac)

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachNICRequestHash("vm1", mac),
		[]string{corrosion.OpStepReserved},
		map[string]string{"mac": mac, "nic_id": nicID})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepCompleted {
		t.Fatalf("detach recovery state = %q, want completed", state)
	}
	if nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1"); hasNICMac(nics, mac) {
		t.Fatalf("forward detach left the NIC row: %+v", nics)
	}
	if live, _ := fake.DumpXML("vm1"); nicMacInXML(live, mac) {
		t.Fatalf("nic %s still present in the live domain after forward detach", mac)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); nicMacInXML(inactive, mac) {
		t.Fatalf("nic %s still present in the persistent definition after forward detach", mac)
	}
	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("recovery must not re-attach the NIC: AttachNIC count = %d, want 1", n)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed detach")
	}
}

// ── PCI recovery ──────────────────────────────────────────────────────────────

// TestRecoverHardwareOperations_PCIAttachClaimedWindowReleasesLease: a PCI attach
// that crashed in the CLAIMED WINDOW — after acquireDeviceLeases owner-assigned the
// device but BEFORE any vm_pci_realizations row was written — followed by a host
// reboot (domain shut off, vm.State still "running"). Recovery reconstructs the held
// lease from the op's own journal member_addresses artifact and RELEASES it, so the
// device is not stranded owner-assigned to a VM not using it.
func TestRecoverHardwareOperations_PCIAttachClaimedWindowReleasesLease(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)

	const addr = "0000:41:00.0"
	const deviceID = "pcidev-claimed"
	// Lease acquired (device owner-assigned) but crash before any realization row.
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("assign device: %v", err)
	}
	// Host reboot: domain shut off while vm.State still reads "running".
	fake.SetState("vm1", libvirtfake.StateShutdown)

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachPCIRequestHash("vm1", addr),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{"device_id": deviceID, "pci_address": addr, "member_addresses": addr})

	s.RecoverHardwareOperations(ctx)

	// The lease is released — the device is no longer owner-assigned to vm1.
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.Address == addr && d.VMName == "vm1" {
			t.Fatalf("claimed-window recovery must release the lease; %s still owned by vm1", addr)
		}
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepFailed {
		t.Fatalf("op state = %q, want failed", state)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed rollback")
	}
}

// TestRecoverHardwareOperations_PCIDetachRollsForward: a PCI detach wedged
// mid-detach converges by rolling FORWARD — the hostdev leaves both definitions,
// realizations + intent are tombstoned, ownership is released, the op completes, and
// the device is NEVER re-attached.
func TestRecoverHardwareOperations_PCIDetachRollsForward(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning)

	const addr = "0000:41:00.0"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	deviceID := liveIntents(t, ctx, s, "vm1")[0].DeviceID
	alias := pciMemberAlias(deviceID, "m0")

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachPCIRequestHash("vm1", addr),
		[]string{corrosion.OpStepReserved},
		map[string]string{"device_id": deviceID, "pci_address": addr, "member_addresses": addr})

	s.RecoverHardwareOperations(ctx)

	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepCompleted {
		t.Fatalf("detach recovery state = %q, want completed", state)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("realizations not tombstoned: %+v", rs)
	}
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName == "vm1" {
			t.Fatalf("device %s still owned by vm1 after forward detach", d.Address)
		}
	}
	live, _ := fake.DumpXML("vm1")
	inactive, _ := fake.DumpXMLInactive("vm1")
	if hostdevAliasInXML(live, alias) || hostdevAliasInXML(inactive, alias) {
		t.Fatalf("alias %s still present after forward detach", alias)
	}
	if _, found, _ := s.opJournal.Read(opID); found {
		t.Fatal("journal entry must be cleared after a completed detach")
	}
}

// ── host reboot: live domain shut off while vm.State still "running" ─────────────

// TestRecoverHardwareOperations_HostRebootAttachTakesStoppedPath: after a host
// reboot vm.State still reads "running" but the libvirt domain is SHUT OFF. An
// attach wedged mid-flight (data1 in the persistent definition + a committed row +
// the op-owned file) must recover down the STOPPED path — reconciling data1 OUT of
// the persistent definition from the authoritative tables — NOT the running path,
// which would issue a LIVE-flagged detach a shut-off domain rejects, wedge the
// barrier, and strand data1 orphaned in the persistent config.
func TestRecoverHardwareOperations_HostRebootAttachTakesStoppedPath(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running") // vm.State survives a host reboot as "running"
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateShutdown) // the domain is actually shut off

	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"<disk type='file' device='disk'><source file='/x/vm1-data1.qcow2'/><target dev='vdb' bus='virtio'/></disk>"+
		"</devices></domain>")
	fake.SetDiskSource("vm1", "vdb", filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data1", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", "vm1-data1.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vdb", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert data1 row: %v", err)
	}
	diskPath, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(diskPath, []byte("op-owned"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Model libvirt rejecting a LIVE-flagged detach on a shut-off domain — the exact
	// failure the buggy running-path rollback hits; the stopped path never issues it.
	fake.FailDetachDisk = func(_, _ string) error {
		return status.Error(codes.Internal, "requested operation is not valid: domain is not running")
	}

	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach,
		attachDiskRequestHash("vm1", &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}),
		[]string{corrosion.OpStepReserved, corrosion.OpStepClaimed},
		map[string]string{
			"disk_name": "data1", "target_dev": "vdb", "bus": "virtio",
			"file_created_by_operation": diskPath,
		})

	s.RecoverHardwareOperations(ctx)

	// Converged cleanly (NOT wedged on a LIVE detach): barrier cleared, op failed.
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared — recovery took the running path and wedged: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceAttach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepFailed {
		t.Fatalf("op state = %q, want failed", state)
	}
	// data1 reconciled OUT of the persistent definition — no orphan (the bug).
	if inactive, _ := fake.DumpXMLInactive("vm1"); diskDevInXML(inactive, "vdb") {
		t.Fatalf("data1 (vdb) left orphaned in the persistent definition:\n%s", inactive)
	}
	// Row gone and the op-owned backing file removed — file/row consistent.
	if disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1"); hasDiskName(disks, "data1") {
		t.Fatalf("rolled-back attach left a data1 row: %+v", disks)
	}
	if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
		t.Fatalf("rollback must delete the op-owned backing file (stat err=%v)", statErr)
	}
}
