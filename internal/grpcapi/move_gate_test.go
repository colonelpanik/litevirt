package grpcapi

import (
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
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// fakeDomainXML builds a minimal (namespace-free) libvirt domain whose single disk
// at target dev `dev` has <source file=srcPath>. The libvirtfake stores it by the
// <name>, so DumpXMLInactive returns it for the cutover gate to rewrite.
func fakeDomainXML(name, dev, srcPath string) string {
	return `<domain type="kvm"><name>` + name + `</name><devices>` +
		`<disk type="file" device="disk"><source file="` + srcPath + `"/>` +
		`<target dev="` + dev + `" bus="virtio"/></disk>` +
		`</devices></domain>`
}

func noopSend(*pb.MoveVolumeProgress) error { return nil }

// offlineMoveServer wires a stopped VM "vm1" with a real qcow2 source, a "warm"
// target pool, and a libvirtfake whose inactive domain points the disk at the source.
func offlineMoveServer(t *testing.T) (s *Server, f *libvirtfake.Fake, srcFile, dstFile string) {
	t.Helper()
	s = testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	srcDir := filepath.Join(s.dataDir, "src")
	dstDir := filepath.Join(s.dataDir, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	srcFile = filepath.Join(srcDir, "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	dstFile = filepath.Join(dstDir, "vm1-root.qcow2")
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})
	st, _ := os.Stat(srcFile)
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: srcFile, SizeBytes: st.Size(), TargetDev: "vda",
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f = libvirtfake.New()
	if err := f.DefineDomain(fakeDomainXML("vm1", "vda", srcFile)); err != nil {
		t.Fatalf("define: %v", err)
	}
	s.virt = f
	return s, f, srcFile, dstFile
}

// TestMoveVolume_Offline_RedefinesPersistentAndAtomic: a successful offline move
// repoints the PERSISTENT domain config to the new path AND writes every disk
// placement field in one shot (path + pool + type change together).
func TestMoveVolume_Offline_RedefinesPersistentAndAtomic(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	xml, _ := f.DumpXMLInactive("vm1")
	if !strings.Contains(xml, dstFile) || strings.Contains(xml, srcFile) {
		t.Fatalf("persistent config not repointed to %q: %s", dstFile, xml)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if len(disks) != 1 || disks[0].Path != dstFile || disks[0].StorageVolume != "warm" || disks[0].StorageType != "local" {
		t.Fatalf("disk row not atomically repointed: %+v", disks)
	}
}

// TestMoveVolume_Offline_RedefineFailureAborts: the redefine is a HARD gate — if it
// fails the move aborts, the copy is removed, and DB + source are untouched.
func TestMoveVolume_Offline_RedefineFailureAborts(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	f.FailDefineDomain = func(string) error { return errors.New("libvirt rejected redefine") }
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on gate failure, got %v", err)
	}
	if exists(dstFile) {
		t.Error("destination copy not cleaned up after gate failure")
	}
	if !exists(srcFile) {
		t.Error("source must be preserved on gate failure")
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if disks[0].Path != srcFile || disks[0].StorageVolume != "hot" {
		t.Fatalf("disk row changed despite gate failure: %+v", disks)
	}
}

// TestMoveVolume_Offline_DBZeroRowAborted: a vanished/soft-deleted disk row makes the
// strict placement commit return zero rows — surfaced as gRPC Aborted, not a silent
// success, with the copy removed and the source preserved.
func TestMoveVolume_Offline_DBZeroRowAborted(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	srcDir := filepath.Join(s.dataDir, "src")
	dstDir := filepath.Join(s.dataDir, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	srcFile := filepath.Join(srcDir, "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})
	// VM exists but there is NO disk row → the placement commit affects zero rows.
	vm := &corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"}
	src := &corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "test-host",
		Path: srcFile, SizeBytes: 1 << 20, StorageType: "local", StorageVolume: "hot",
	}
	// s.virt nil → the gate is skipped, so this isolates the commit's zero-row guard.
	err := s.moveOneVolume(context.Background(), vm, src, "warm", false, noopSend)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted on zero-row commit, got %v", err)
	}
	if exists(filepath.Join(dstDir, "vm1-root.qcow2")) {
		t.Error("destination copy not cleaned up after zero-row commit")
	}
	if !exists(srcFile) {
		t.Error("source must be preserved")
	}
}

// TestMoveVolume_Offline_RedefineOkDBFailRollsBack: redefine succeeds but the commit
// fails (zero rows) → the cutover is rolled back (persistent config restored to the
// source) and the copy removed, so a retry is a clean fresh move.
func TestMoveVolume_Offline_RedefineOkDBFailRollsBack(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	srcDir := filepath.Join(s.dataDir, "src")
	dstDir := filepath.Join(s.dataDir, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	srcFile := filepath.Join(srcDir, "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	dstFile := filepath.Join(dstDir, "vm1-root.qcow2")
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})
	f := libvirtfake.New()
	if err := f.DefineDomain(fakeDomainXML("vm1", "vda", srcFile)); err != nil {
		t.Fatalf("define: %v", err)
	}
	s.virt = f
	vm := &corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"}
	src := &corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "test-host",
		Path: srcFile, SizeBytes: 1 << 20, TargetDev: "vda",
		StorageType: "local", StorageVolume: "hot",
	}
	err := s.moveOneVolume(context.Background(), vm, src, "warm", false, noopSend)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted, got %v", err)
	}
	xml, _ := f.DumpXMLInactive("vm1")
	if !strings.Contains(xml, srcFile) || strings.Contains(xml, dstFile) {
		t.Fatalf("persistent config not rolled back to source: %s", xml)
	}
	if exists(dstFile) {
		t.Error("destination copy not removed after rollback")
	}
}

// TestMoveVolume_Offline_AlreadyAtDstSkipsCopy: if a prior partial cutover already
// repointed the persistent config at dstPath (which may hold newer guest writes than
// the stale source), the retry must NOT re-copy src→dst (clobbering it) — it just
// commits the DB.
func TestMoveVolume_Offline_AlreadyAtDstSkipsCopy(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	srcDir := filepath.Join(s.dataDir, "src")
	dstDir := filepath.Join(s.dataDir, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	srcFile := filepath.Join(srcDir, "vm1-root.qcow2")
	dstFile := filepath.Join(dstDir, "vm1-root.qcow2")
	// dst holds the newer authoritative content; src is stale. A clobber overwrites dst.
	if err := os.WriteFile(srcFile, []byte("STALE-SRC"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstFile, []byte("NEWER-DST"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: srcFile, SizeBytes: 9, TargetDev: "vda",
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Persistent config already boots from dstFile (a prior partial cutover).
	f := libvirtfake.New()
	if err := f.DefineDomain(fakeDomainXML("vm1", "vda", dstFile)); err != nil {
		t.Fatalf("define: %v", err)
	}
	s.virt = f

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if got, _ := os.ReadFile(dstFile); string(got) != "NEWER-DST" {
		t.Fatalf("destination clobbered by stale source: got %q", got)
	}
	for _, fr := range rec.Sent {
		if fr.Phase == pb.MoveVolumeProgress_COPY {
			t.Fatal("a COPY frame was emitted; the copy should have been skipped")
		}
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if disks[0].Path != dstFile || disks[0].StorageVolume != "warm" {
		t.Fatalf("disk row not committed to dest: %+v", disks)
	}
}

// TestMoveVolume_Offline_UnexpectedDomainSourceAborts: if the disk's persistent
// <source> is neither the old nor the new path (ambiguous/unexpected), the gate
// refuses before any DB write.
func TestMoveVolume_Offline_UnexpectedDomainSourceAborts(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	// Repoint the domain disk at a THIRD path the move doesn't recognize.
	if err := f.DefineDomain(fakeDomainXML("vm1", "vda", "/somewhere/else.qcow2")); err != nil {
		t.Fatalf("define: %v", err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal for unexpected domain source, got %v", err)
	}
	if exists(dstFile) {
		t.Error("destination copy not cleaned up")
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if disks[0].Path != srcFile || disks[0].StorageVolume != "hot" {
		t.Fatalf("disk row changed despite gate failure: %+v", disks)
	}
}
