package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// hotplugDiskServer builds a Server wired for the journaled disk path: a real
// (in-memory) DB + schema, a libvirtfake backend, a dataDir for backing files, a
// host-local operation journal, and per-VM locks. It does NOT latch any capability
// — callers use setDeviceGate / enableHardwareV2 to control the gates.
func hotplugDiskServer(t *testing.T) *Server {
	t.Helper()
	s := reconfigServer(t) // testServer + libvirtfake
	s.dataDir = t.TempDir()
	s.vmLocks = make(map[string]*sync.Mutex)
	j, err := opjournal.Open(filepath.Join(t.TempDir(), "opjournal"))
	if err != nil {
		t.Fatalf("opjournal.Open: %v", err)
	}
	s.SetOpJournal(j)
	return s
}

// setDeviceGate latches operation_protocol_v1 and/or hardware_v2 for the disk path.
func setDeviceGate(s *Server, protocol, hardware bool) {
	s.gate = fakeServerGate{enforcedTok: map[string]bool{
		capabilities.OperationProtocolV1: protocol,
		capabilities.HardwareV2:          hardware,
	}}
	s.SetOperationProtocol(protocol)
}

// enableHardwareV2 latches BOTH operation_protocol_v1 and hardware_v2 — the state a
// stopped-VM hardware mutation requires.
func enableHardwareV2(t *testing.T, s *Server) {
	t.Helper()
	setDeviceGate(s, true, true)
}

// seedDiskVM inserts a stopped/running VM with a spec (cpu/mem + root disk) and the
// matching vm_disks root row, so a reconcile has a realistic base to build from.
func seedDiskVM(t *testing.T, s *Server, name, state string) {
	t.Helper()
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, name, "test-host", state,
		seedSpecJSON(t, &pb.VMSpec{
			Name: name, Cpu: 2, MemoryMib: 4096,
			Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		}))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: name, DiskName: "root", HostName: "test-host",
		Path:       filepath.Join(s.dataDir, "disks", name+"-root.qcow2"),
		DeviceKind: "disk", Bus: "virtio", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root disk: %v", err)
	}
}

func hasDiskName(disks []corrosion.DiskRecord, name string) bool {
	for _, d := range disks {
		if d.DiskName == name {
			return true
		}
	}
	return false
}

// diskTargetDev resolves the target-dev the attach allocated for a named disk (robust
// to the historical vda/target-dev scheme instead of hard-coding "vdb").
func diskTargetDev(t *testing.T, ctx context.Context, s *Server, vm, disk string) string {
	t.Helper()
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vm)
	for _, d := range disks {
		if d.DiskName == disk {
			return d.TargetDev
		}
	}
	t.Fatalf("disk %q row not found on %q: %+v", disk, vm, disks)
	return ""
}

// ── attach: stopped realizes ────────────────────────────────────────────────

func TestAttachDevice_StoppedDiskRealized(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "stopped")

	out, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "10G", Bus: "virtio"},
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if out == nil {
		t.Fatal("nil VM returned")
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if !hasDiskName(disks, "data1") {
		t.Fatalf("vm_disks row for data1 not written: %+v", disks)
	}
	// The disk must appear in the reconciled inactive definition.
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	if !strings.Contains(xml, "data1") {
		t.Fatalf("attached disk absent from reconciled XML:\n%s", xml)
	}
	// Bus persisted (contract (e)): the data1 row carries its bus.
	for _, d := range disks {
		if d.DiskName == "data1" && d.Bus != "virtio" {
			t.Fatalf("vm_disks.bus not persisted: got %q", d.Bus)
		}
	}
}

// ── attach: running makes a live call + commits the row ──────────────────────

func TestAttachDevice_RunningDiskLiveAttach(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if n := fake.AttachDiskCount(); n != 1 {
		t.Fatalf("live AttachDisk called %d times, want 1", n)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if !hasDiskName(disks, "data1") {
		t.Fatalf("row not committed after running attach: %+v", disks)
	}
}

// ── protocol prerequisite ────────────────────────────────────────────────────

func TestAttachDevice_ProtocolInactiveRejected(t *testing.T) {
	s := hotplugDiskServer(t) // no gate → operation_protocol_v1 inactive
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

// ── hardware_v2 gate for stopped mutations ───────────────────────────────────

func TestAttachDevice_StoppedRejectedWithoutHardwareV2(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // protocol active, hardware_v2 NOT latched
	ctx := adminCtx()

	// Stopped → rejected.
	seedDiskVM(t, s, "stopped-vm", "stopped")
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "stopped-vm", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped attach without hardware_v2: code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "hardware_v2") {
		t.Fatalf("expected a hardware_v2 message, got: %v", err)
	}

	// Running still works (protocol active is enough for live hotplug).
	seedDiskVM(t, s, "running-vm", "running")
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "running-vm", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	}); err != nil {
		t.Fatalf("running attach with protocol active should succeed: %v", err)
	}
}

// ── mutation error → operation failure + rollback ────────────────────────────

func TestAttachDevice_MutationErrorRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailAttachDisk = func(_, _, _, _ string) error { return status.Error(codes.Internal, "boom") }

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	})
	if err == nil {
		t.Fatal("expected the live-attach failure to surface as an RPC error")
	}
	// No row committed.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatalf("row must not survive a failed attach: %+v", disks)
	}
	// The op-owned backing file was deleted by rollback.
	p, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("rollback must delete the op-owned backing file %s (stat err=%v)", p, statErr)
	}
	// Barrier released (op reached a terminal failure).
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after clean rollback: %q", vm.ActiveOperationID)
	}
}

// ── DB error is surfaced, not silently logged ────────────────────────────────

func TestAttachDevice_DBErrorSurfaced(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	// Drop vm_disks so the row INSERT fails while the operation tables stay intact.
	if err := s.db.Execute(ctx, `DROP TABLE vm_disks`); err != nil {
		t.Fatalf("drop vm_disks: %v", err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a vm_disks INSERT error must surface as Internal, got: %v", err)
	}
	// The op-owned backing file was removed by rollback even though the DB failed.
	p, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("rollback must delete the op-owned file after a DB error (stat err=%v)", statErr)
	}
}

// ── existing target path is never modified ───────────────────────────────────

func TestAttachDevice_ExistingPathNotModified(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")

	// Pre-create a NON-op-owned file at the target path with sentinel content.
	p, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sentinel := []byte("PRE-EXISTING DATA — MUST NOT BE TOUCHED")
	if err := os.WriteFile(p, sentinel, 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G"},
	})
	if err == nil {
		t.Fatal("attach onto an existing path must fail")
	}
	// The pre-existing file must be byte-for-byte untouched (never modified, never
	// deleted by rollback — it is not op-owned).
	got, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("pre-existing file was removed by rollback: %v", rerr)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("pre-existing file was modified: %q", string(got))
	}
	// No row was written for the failed attach.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatal("no row should exist for an attach that failed on an existing path")
	}
}

// ── concurrency: same idempotency key → at-most-once ─────────────────────────

func TestAttachDevice_SameKeyConcurrentAtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const key = "fixed-key-123"
	var wg sync.WaitGroup
	var okCount int32
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: "vm1", IdempotencyKey: key,
				Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
			})
			if err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()

	if n := fake.AttachDiskCount(); n != 1 {
		t.Fatalf("at-most-once violated: live AttachDisk called %d times, want exactly 1", n)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	count := 0
	for _, d := range disks {
		if d.DiskName == "data1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate/absent row: %d data1 rows, want 1", count)
	}
	if okCount < 1 {
		t.Fatal("at least one concurrent attach must succeed")
	}
}

// TestAttachDevice_SameKeyReplaysCompleted: a second call with the same key after
// the first completed replays the recorded result WITHOUT a second live attach.
func TestAttachDevice_SameKeyReplaysCompleted(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const key = "replay-key"
	req := &pb.AttachDeviceRequest{
		VmName: "vm1", IdempotencyKey: key,
		Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("replay attach: %v", err)
	}
	if n := fake.AttachDiskCount(); n != 1 {
		t.Fatalf("replay re-executed: AttachDisk called %d times, want 1", n)
	}
}

// TestAttachDiskOwner_AtMostOnce exercises the OWNER-side at-most-once claim
// directly (§7.3), bypassing the entry idempotency layer: two owner calls with the
// SAME operation id must produce exactly ONE live attach — the second reconstructs
// the completed outcome from the replicated operation, never re-runs.
func TestAttachDiskOwner_AtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	req := &pb.AttachDeviceRequest{VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}}
	opID := corrosion.DeterministicOperationID("AttachDevice", "admin@local", "_default", "vm1", "owner-key")
	reqHash := attachDiskRequestHash("vm1", req.Disk)

	if _, err := s.attachDiskOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("first owner attach: %v", err)
	}
	if _, err := s.attachDiskOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("second owner attach (should replay completed): %v", err)
	}
	if n := fake.AttachDiskCount(); n != 1 {
		t.Fatalf("owner at-most-once violated: AttachDisk called %d times, want 1", n)
	}
	// A DIFFERENT request hash on the SAME key is a conflict → InvalidArgument.
	_, err := s.attachDiskOwner(ctx, req, "vm1", opID, "different-hash", "owner-key")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("same op id + different hash: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestDiskAttach_CompletionCASFails_RetainsJournal drives a disk attach whose
// device side effects fully land (live attach + row committed + verified), but
// whose terminal CompleteVMOperation CAS does NOT apply — modeling the VM's
// spec_generation having moved underneath the op (a fence/migrate mid-operation).
// The bug: the caller discarded `applied` and unconditionally removed the
// host-local op-journal entry + reported fake success, leaving the mutation
// barrier held with NO journal to recover it — the VM wedges forever. The fix
// must retain the journal, keep the barrier held, and return an error (never a
// fake success) so a later recovery pass converges it.
func TestDiskAttach_CompletionCASFails_RetainsJournal(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	vm, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: err=%v nil=%v", err, vm == nil)
	}
	spec := &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"}
	diskPath, err := libvirt.SafeDiskPath(s.dataDir, "vm1", spec.Name)
	if err != nil {
		t.Fatalf("disk path: %v", err)
	}
	sizeGB, err := parseDiskSize(spec.Size)
	if err != nil {
		t.Fatalf("parse size: %v", err)
	}
	disks, err := corrosion.ListDisks(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("list disks: %v", err)
	}
	targetDev := allocateDiskTargetDev(len(disks), spec.Bus)

	opID := "cas-fail-disk-attach-vm1"
	reqHash := attachDiskRequestHash("vm1", spec)
	op := corrosion.OperationRecord{
		ID: opID, Method: "AttachDevice", Principal: "admin@local", Project: vm.Project,
		ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(corrosion.OpDeviceAttach),
		RequestHash: reqHash, IdempotencyKey: "cas-fail-key",
	}
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil || !applied {
		t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
	}
	epoch := vm.OwnerEpoch
	realNewGen := vm.SpecGeneration + 1
	// A generation the terminal CAS will NOT match — as if a concurrent operation
	// (or the fence/migrate path) had already advanced spec_generation past what
	// this in-flight attach expects.
	staleNewGen := realNewGen + 1

	_, err = s.executeDiskAttach(ctx, vm, spec, spec.Bus, diskPath,
		uint64(sizeGB)*1024*1024*1024, int64(sizeGB)*1024*1024*1024, targetDev, opID, epoch, staleNewGen, true)
	if err == nil {
		t.Fatal("expected an error when the terminal completion CAS does not apply — got fake success")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (left recoverable)", status.Code(err))
	}

	// The device side effects DID land (this is the whole point: don't lie about it).
	if n := fake.AttachDiskCount(); n != 1 {
		t.Fatalf("live AttachDisk called %d times, want 1 (side effect should have applied)", n)
	}
	gotDisks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if !hasDiskName(gotDisks, "data1") {
		t.Fatalf("disk row should be committed even though completion could not be committed: %+v", gotDisks)
	}

	// The op-journal entry must be RETAINED (recovery-required), never removed.
	_, found, jerr := s.opJournal.Read(opID)
	if jerr != nil {
		t.Fatalf("journal read: %v", jerr)
	}
	if !found {
		t.Fatal("op-journal entry must be RETAINED when the terminal CAS did not apply")
	}

	// The mutation barrier must still be held — the op is left recoverable, not
	// force-completed.
	got := mustGetVM(t, s, "vm1")
	if got.ActiveOperationID != opID {
		t.Fatalf("mutation barrier cleared despite a non-applied completion CAS: active_operation_id=%q, want %q",
			got.ActiveOperationID, opID)
	}
}

// ── detach preserves the backing file ────────────────────────────────────────

func TestDetachDevice_PreservesBackingFile(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")

	// Attach a disk so there is a real backing file + row to detach.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	p, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("backing file missing after attach: %v", err)
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", DiskName: "data1",
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	// Row soft-deleted.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatalf("row not soft-deleted after detach: %+v", disks)
	}
	// Backing file PRESERVED (§12 — never deleted on detach).
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("detach must NOT delete the backing file %s: %v", p, err)
	}
}

// ── running mutation verifies BOTH live and persistent config (§7) ────────────

// TestAttachDevice_RunningVerifiesLiveAndPersistent asserts a running attach is
// verified present in BOTH the live domain AND the persistent (inactive) definition.
// AttachDisk applies live+config, so completing on a live-only landing would let the
// disk silently (dis)appear on the next VM start.
func TestAttachDevice_RunningVerifiesLiveAndPersistent(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	td := diskTargetDev(t, ctx, s, "vm1", "data1")

	// Live view.
	srcs, _ := fake.DomainDiskSources("vm1")
	if _, ok := srcs[td]; !ok {
		t.Fatalf("disk %s absent from the live domain: %v", td, srcs)
	}
	// Persistent (inactive) config.
	inactive, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("dump inactive: %v", err)
	}
	if !diskDevInXML(inactive, td) {
		t.Fatalf("disk %s absent from the persistent definition:\n%s", td, inactive)
	}
}

// TestAttachDevice_RunningConfigDivergenceRollsBack models a live-succeeded-but-
// config-not-applied divergence on a running attach: the disk lands in the live domain
// but never reaches the persistent config. The both-state verify must catch it and
// roll the attach back to a clean state (no row, op-owned file removed, barrier
// cleared) rather than complete an inconsistent attach.
func TestAttachDevice_RunningConfigDivergenceRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	// A running domain always has a persistent definition; give it one (with only the
	// root disk) so a live-only attach is a genuine reads-succeed-but-membership-wrong
	// divergence — not an unreadable-definition case (which is left recoverable).
	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices>"+
		"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>"+
		"</devices></domain>")
	fake.SkipConfigOnDiskMutation = true // live lands, persistent config does NOT

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	})
	if err == nil {
		t.Fatal("a config-vs-live divergence on a running attach must fail verification, not complete")
	}
	// Rolled back: no committed row.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data1") {
		t.Fatalf("row must not survive a rolled-back attach: %+v", disks)
	}
	// Op-owned backing file removed by rollback.
	p, _ := libvirt.SafeDiskPath(s.dataDir, "vm1", "data1")
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("rollback must delete the op-owned backing file %s (stat err=%v)", p, statErr)
	}
	// Barrier released (op reached a terminal failure via compensation).
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after rollback: %q", vm.ActiveOperationID)
	}
}

// TestDetachDevice_RunningConfigDivergenceCaught models a live-succeeded-but-config-
// retained divergence on a running detach: the disk leaves the live domain but lingers
// in the persistent config. The both-state verify must catch it (never
// CompleteVMOperation) so the disk cannot silently reappear on the next VM start.
func TestDetachDevice_RunningConfigDivergenceCaught(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	td := diskTargetDev(t, ctx, s, "vm1", "data1")

	// The live detach lands but the persistent config keeps the disk.
	fake.SkipConfigOnDiskMutation = true
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", DiskName: "data1"})
	if err == nil {
		t.Fatal("a config-vs-live divergence on a running detach must fail verification, not complete")
	}
	// The disk really did leave the live domain (forward progress) but still lingers in
	// the persistent config — proving the both-state check, not a live-only check,
	// caught the divergence.
	srcs, _ := fake.DomainDiskSources("vm1")
	if _, ok := srcs[td]; ok {
		t.Fatalf("disk %s should be gone from the live domain: %v", td, srcs)
	}
	inactive, _ := fake.DumpXMLInactive("vm1")
	if !diskDevInXML(inactive, td) {
		t.Fatalf("test setup: persistent config should still list %s (the modeled divergence)", td)
	}
}
