package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// firmwareTestServer builds a test server with a fake libvirt + a firmware VM
// record (Secure Boot + vTPM) in the given state.
func firmwareTestServer(t *testing.T, vmName, vmState string) (*Server, *libvirtfake.Fake, context.Context) {
	t.Helper()
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	spec := `{"name":"` + vmName + `","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"u-` + vmName + `"}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: vmName, HostName: s.hostName, Spec: spec, State: vmState,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return s, fake, ctx
}

// A running disk-only snapshot of an SB/vTPM VM has no consistent firmware-capture
// point and must be refused (require --with-memory).
func TestCreateSnapshot_RunningDiskOnlySBTPMRefused(t *testing.T) {
	s, fake, ctx := firmwareTestServer(t, "vm1", "running")
	fake.SetState("vm1", libvirtfake.StateRunning)

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "vm1", Name: "snap1", WithMemory: false})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for running disk-only SB/vTPM snapshot, got %v", err)
	}
	if !strings.Contains(err.Error(), "--with-memory") {
		t.Errorf("error should mention --with-memory, got: %v", err)
	}
}

// Reverting an SB/vTPM VM whose snapshot captured NO firmware sidecar must be
// refused (don't pair reverted disks with stale/missing TPM state).
func TestRestoreSnapshot_MissingFirmwareSidecarRefused(t *testing.T) {
	s, fake, ctx := firmwareTestServer(t, "vm2", "running")
	fake.SetState("vm2", libvirtfake.StateRunning)
	// Register a disk snapshot in both the fake + the cluster store, with NO
	// firmware sidecar on disk (simulates a pre-G1 or lost-sidecar snapshot).
	if _, err := fake.CreateSnapshot("vm2", "snap1"); err != nil {
		t.Fatalf("fake CreateSnapshot: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName: "vm2", HostName: s.hostName, Name: "snap1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "vm2", SnapshotName: "snap1"})
	if err == nil {
		t.Fatal("expected refusal restoring an SB/vTPM snapshot with no captured firmware, got nil")
	}
	if !strings.Contains(err.Error(), "no captured firmware state") {
		t.Errorf("error should explain the missing firmware capture, got: %v", err)
	}
}

func hasOp(log []libvirtfake.Event, op, domain string) bool {
	for _, e := range log {
		if e.Op == op && e.Domain == domain {
			return true
		}
	}
	return false
}

// A --with-memory snapshot whose RAM save fails AFTER the disk overlay cut over
// must (a) record the snapshot ERRORED rather than vanish, and (b) be flattened
// on delete even though it's memory-typed — otherwise the VM is stranded on an
// untracked overlay chain.
func TestCreateSnapshot_FailedLiveCaptureRecordsErrorAndFlattens(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "lvm", HostName: s.hostName, Spec: `{"name":"lvm"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("lvm", libvirtfake.StateRunning)
	fake.FailCreateLiveSnapshot = func(_, _ string) error { return errors.New("ram save boom") }

	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "lvm", Name: "s1", WithMemory: true}); err == nil {
		t.Fatal("expected CreateSnapshot to fail when the RAM save fails")
	}
	// The errored snapshot must be recorded (visible + deletable), not dropped.
	snap, _ := corrosion.GetSnapshot(ctx, s.db, "lvm", "s1")
	if snap == nil || snap.State != "error" {
		t.Fatalf("expected an errored snapshot record, got %+v", snap)
	}

	// Deleting it must flatten the overlay (not a metadata-only delete).
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "lvm", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if !hasOp(fake.EventLog(), "snapshot-flatten", "lvm") {
		t.Errorf("deleting an errored live snapshot must flatten the overlay; events=%v", fake.EventLog())
	}
}

// cutoverNextServer stages a pending "<vmName>-next" Secure-Boot/vTPM VM owned by
// host, with a dumpable libvirt domain + a name-keyed NVRAM file on disk.
func cutoverNextServer(t *testing.T, vmName, host string) (*Server, *libvirtfake.Fake, context.Context) {
	t.Helper()
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	next := vmName + "-next"
	spec := `{"name":"` + next + `","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"u-` + next + `"}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: next, HostName: host, Spec: spec, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if host == s.hostName {
		if err := fake.DefineDomain(`<domain type='kvm'><name>` + next + `</name><uuid>u-` + next + `</uuid></domain>`); err != nil {
			t.Fatalf("DefineDomain: %v", err)
		}
		fake.SetState(next, libvirtfake.StateRunning)
		nv := lv.NvramPath(s.dataDir, next)
		if err := os.MkdirAll(filepath.Dir(nv), 0o755); err != nil {
			t.Fatalf("mkdir nvram: %v", err)
		}
		if err := os.WriteFile(nv, []byte("vars"), 0o600); err != nil {
			t.Fatalf("write nvram: %v", err)
		}
	}
	return s, fake, ctx
}

// Cutover of a firmware VM whose -next domain lives on another host must FORWARD
// to that host (so its name-keyed NVRAM is renamed on the real host), not rename
// the DB record locally and leave the remote domain mismatched.
func TestCutover_FirmwareRemoteHostForwards(t *testing.T) {
	s, _, ctx := cutoverNextServer(t, "cv", "remote-host")
	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cv"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable forwarding cutover to the owning host, got %v", err)
	}
	// No local mutation may have happened — the -next record stands, no renamed VM.
	if n, _ := corrosion.GetVM(ctx, s.db, "cv-next"); n == nil {
		t.Error("forwarded cutover must not delete/rename the -next record locally")
	}
	if c, _ := corrosion.GetVM(ctx, s.db, "cv"); c != nil {
		t.Error("forwarded cutover must not create the renamed VM locally")
	}
}

// A redefine failure during a firmware cutover is HARD — mark the VM errored and
// return, don't report success and rely on the reconciler (a fresh redefine would
// mint new firmware).
func TestCutover_FirmwareRedefineFailureMarksError(t *testing.T) {
	s, fake, ctx := cutoverNextServer(t, "cv", "test-host")
	fake.FailDefineDomain = func(string) error { return errors.New("redefine boom") }
	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cv"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on firmware cutover redefine failure, got %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "cv"); vm == nil || vm.State != "error" {
		t.Fatalf("expected cv state=error after cutover redefine failure, got %+v", vm)
	}
}

// A start failure during a firmware cutover is HARD too.
func TestCutover_FirmwareStartFailureMarksError(t *testing.T) {
	s, fake, ctx := cutoverNextServer(t, "cv", "test-host")
	fake.FailStartDomain = func(string) error { return errors.New("start boom") }
	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cv"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on firmware cutover start failure, got %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "cv"); vm == nil || vm.State != "error" {
		t.Fatalf("expected cv state=error after cutover start failure, got %+v", vm)
	}
}

// If the preserve-undefine of the -next domain fails, cutover must NOT rename the
// NVRAM out from under a still-defined domain — it must hard-fail first.
func TestCutover_FirmwareUndefineFailureKeepsNvram(t *testing.T) {
	s, fake, ctx := cutoverNextServer(t, "cv", "test-host")
	fake.FailUndefinePreserv = func(string) error { return errors.New("undefine boom") }
	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cv"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on firmware cutover undefine failure, got %v", err)
	}
	if _, e := os.Stat(lv.NvramPath(s.dataDir, "cv-next")); e != nil {
		t.Errorf("NVRAM must stay at the -next path after a failed undefine, stat err=%v", e)
	}
	if _, e := os.Stat(lv.NvramPath(s.dataDir, "cv")); e == nil {
		t.Error("NVRAM must NOT be renamed when the preserve-undefine failed")
	}
}

// The legacy raw-stream backup can't carry firmware state, so it must refuse an
// SB/vTPM VM (a restore would boot a fresh-TPM VM and brick BitLocker).
func TestBackupVM_RefusesFirmwareVM(t *testing.T) {
	s, _, ctx := firmwareTestServer(t, "fwvm", "stopped")
	err := s.BackupVM(&pb.BackupVMRequest{VmName: "fwvm"}, &fakeBackupStream{ctx: ctx})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented refusing raw-stream backup of an SB/vTPM VM, got %v", err)
	}
	if !strings.Contains(err.Error(), "snapshot backup") {
		t.Errorf("error should point at snapshot backup, got: %v", err)
	}
}

// Backing up a firmware VM whose firmware state is absent on this host must
// refuse rather than store an un-restorable-as-firmware backup.
func TestCaptureFirmwareBundle_MissingStateRefused(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	// No NVRAM / swtpm files exist under dataDir → capture must refuse.
	spec := `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"u1"}`
	_, err = s.captureFirmwareBundle(repo, "fwvm", spec)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition capturing absent firmware state, got %v", err)
	}
	// A non-firmware VM yields no refs and no error.
	refs, err := s.captureFirmwareBundle(repo, "plain", `{"name":"plain"}`)
	if err != nil || refs != nil {
		t.Fatalf("non-firmware capture should be a no-op, got refs=%v err=%v", refs, err)
	}
}

// Restoring an SB/vTPM VM from a backup that captured NO firmware state must
// refuse (booting a fresh-TPM VM would brick BitLocker).
func TestRestore_FirmwareVMWithoutCapturedStateRefused(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	ctx := adminCtx()
	manifest := &pbsstore.Manifest{VMName: "win", DiskName: "root", TotalSize: 1 << 20} // no FirmwareChunks
	req := &pb.RestoreLiveRequest{
		VmName: "win",
		Spec:   &pb.VMSpec{Name: "win", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi", SecureBoot: true},
	}
	_, _, err = s.autoDefineRestoredVM(ctx, req, repo, manifest, "/tmp/overlay.qcow2", "_default", func(*pb.RestoreLiveProgress) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition restoring an SB VM with no captured firmware, got %v", err)
	}
	if !strings.Contains(err.Error(), "no firmware state") {
		t.Errorf("error should explain the missing captured firmware, got: %v", err)
	}
}

// A running SB/vTPM VM can't be captured at the disk point-in-time without a
// pause window, so snapshot-backup of one must refuse (back it up stopped).
func TestCaptureFirmwareBundle_RunningRefused(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	fake.SetState("fwvm", libvirtfake.StateRunning)
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	_, err = s.captureFirmwareBundle(repo, "fwvm", `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"u1"}`)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition capturing a running firmware VM, got %v", err)
	}
	if !strings.Contains(err.Error(), "stop") {
		t.Errorf("error should tell the operator to stop the VM, got: %v", err)
	}
}

// If the VM's libvirt state can't be determined, a firmware backup must fail
// closed (never fall through to a capture that might be of a running VM).
func TestCaptureFirmwareBundle_UnknownStateFailsClosed(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	fake.FailDomainState = func(string) error { return errors.New("libvirt unreachable") }
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	_, err = s.captureFirmwareBundle(repo, "fwvm", `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"u1"}`)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition when state is unknown, got %v", err)
	}
	if !strings.Contains(err.Error(), "cannot determine") {
		t.Errorf("error should explain the unknown state, got: %v", err)
	}
}

// A partial bundle (NVRAM present but swtpm missing for a vTPM VM) must be
// refused — restoring it would boot a fresh TPM.
func TestCaptureFirmwareBundle_PartialBundleRefused(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	// NVRAM exists, but there's no swtpm state for the (made-up) uuid.
	nv := lv.NvramPath(s.dataDir, "fwvm")
	if err := os.MkdirAll(filepath.Dir(nv), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(nv, []byte("vars"), 0o600); err != nil {
		t.Fatalf("write nvram: %v", err)
	}
	_, err = s.captureFirmwareBundle(repo, "fwvm", `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"no-such-uuid-xyz"}`)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a partial (NVRAM-only) vTPM bundle, got %v", err)
	}
	if !strings.Contains(err.Error(), "swtpm") {
		t.Errorf("error should name the missing swtpm component, got: %v", err)
	}
}

// A multi-disk firmware VM isn't a consistent single-archive backup set in v1.
func TestCaptureFirmwareBundle_MultiDiskRefused(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	spec := `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"u1","disks":[{"name":"root"},{"name":"data"}]}`
	_, err = s.captureFirmwareBundle(repo, "fwvm", spec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented backing up a multi-disk firmware VM, got %v", err)
	}
}

// The multi-disk firmware refusal must not be bypassable by backing up a
// non-root (data) disk — pushBackup refuses regardless of which disk is targeted.
func TestPushBackup_MultiDiskFirmwareNonRootRefused(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	spec := `{"name":"fwvm","tpm":true,"firmware":"uefi","uuid":"u1","disks":[{"name":"root"},{"name":"data"}]}`
	disk := &corrosion.DiskRecord{VMName: "fwvm", DiskName: "data", Path: "/x/data.qcow2", StorageType: "local"}
	req := &pb.BackupSnapshotRequest{VmName: "fwvm", DiskName: "data", RepoPath: "/tmp/repo"}
	_, err = s.pushBackup(context.Background(), repo, disk, req, "2026-01-01T00:00:00Z", func(*pb.BackupSnapshotProgress) error { return nil }, spec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented backing up a data disk of a multi-disk firmware VM, got %v", err)
	}
}

// A firmware restore that fails after materialization (here: define fails) must
// wipe the materialized NVRAM/swtpm so a retry re-materializes cleanly and
// lifecycle never sees orphaned state.
func TestRestore_FirmwareMaterializeRollbackOnDefineFailure(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	repo, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init repo: %v", err)
	}
	// Build a real NVRAM-only firmware bundle (Secure Boot, no TPM → no swtpm) and
	// store it so materialization succeeds before the (forced) define failure.
	src := lv.NvramPath(s.dataDir, "src")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte("secure-boot-vars"), 0o600); err != nil {
		t.Fatalf("write src nvram: %v", err)
	}
	var buf bytes.Buffer
	has, err := lv.WriteFirmwareBundle(s.dataDir, "src", "", &buf)
	if err != nil || !has {
		t.Fatalf("WriteFirmwareBundle: has=%v err=%v", has, err)
	}
	refs, err := repo.PutBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}

	fake.FailDefineDomain = func(string) error { return errors.New("define boom") }
	manifest := &pbsstore.Manifest{VMName: "win", DiskName: "root", TotalSize: 1 << 20, FirmwareChunks: refs}
	req := &pb.RestoreLiveRequest{
		VmName: "win",
		Spec:   &pb.VMSpec{Name: "win", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi", SecureBoot: true},
	}
	_, _, err = s.autoDefineRestoredVM(adminCtx(), req, repo, manifest, "/tmp/o.qcow2", "_default", func(*pb.RestoreLiveProgress) error { return nil })
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal (define failed), got %v", err)
	}
	if lv.HasNvram(s.dataDir, "win") {
		t.Error("materialized NVRAM must be wiped after a failed firmware restore")
	}
}

// fakeBackupStream is a minimal BackupVM server stream for the refusal test
// (the refusal returns before any Send).
type fakeBackupStream struct {
	pb.LiteVirt_BackupVMServer
	ctx context.Context
}

func (f *fakeBackupStream) Context() context.Context  { return f.ctx }
func (f *fakeBackupStream) Send(*pb.BackupChunk) error { return nil }
