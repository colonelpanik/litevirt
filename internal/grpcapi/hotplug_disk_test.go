package grpcapi

import (
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
