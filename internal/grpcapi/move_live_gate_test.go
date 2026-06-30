package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// liveMoveServerWithVirt extends liveMoveTestServer with a libvirtfake whose INACTIVE
// (persistent) domain points the disk at the source, and whose ACTIVE source is src
// (pivoted=false) or destPath (pivoted=true, simulating libvirt having auto-completed
// the mirror). Returns the fast-poll cleanup too.
func liveMoveServerWithVirt(t *testing.T, pivoted bool) (s *Server, f *libvirtfake.Fake, src, destPath string) {
	t.Helper()
	s, src, dstDir := liveMoveTestServer(t, 4096)
	destPath = filepath.Join(dstDir, "vm-live-root.qcow2")
	f = libvirtfake.New()
	if err := f.DefineDomain(fakeDomainXML("vm-live", "vda", src)); err != nil {
		t.Fatalf("define: %v", err)
	}
	active := src
	if pivoted {
		active = destPath
	}
	f.SetDiskSource("vm-live", "vda", active)
	s.virt = f
	return s, f, src, destPath
}

func fastPoll(t *testing.T) {
	t.Helper()
	prev := LiveMoverPollInterval
	LiveMoverPollInterval = time.Millisecond
	t.Cleanup(func() { LiveMoverPollInterval = prev })
}

// TestMoveVolume_Live_RedefinesPersistentBeforePivot: the happy path moves persistent
// config + DB to dest, THEN pivots, THEN deletes the source — all three agree.
func TestMoveVolume_Live_RedefinesPersistentBeforePivot(t *testing.T) {
	s, f, src, destPath := liveMoveServerWithVirt(t, false)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	fastPoll(t)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.pivotCalls != 1 {
		t.Errorf("pivot = %d, want 1", mover.pivotCalls)
	}
	xml, _ := f.DumpXMLInactive("vm-live")
	if !strings.Contains(xml, destPath) {
		t.Fatalf("persistent config not repointed to dest: %s", xml)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	if disks[0].Path != destPath || disks[0].StorageVolume != "warm" {
		t.Fatalf("disk row not committed to dest: %+v", disks)
	}
	if exists(src) {
		t.Error("source not deleted after a successful live move")
	}
}

// TestMoveVolume_Live_RedefineFailsBeforePivot: a persistent-redefine failure aborts
// BEFORE the pivot — the guest stays on src, DB is untouched, dest is removed.
func TestMoveVolume_Live_RedefineFailsBeforePivot(t *testing.T) {
	s, f, src, destPath := liveMoveServerWithVirt(t, false)
	f.FailDefineDomain = func(string) error { return errors.New("redefine rejected") }
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	fastPoll(t)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	if mover.pivotCalls != 0 {
		t.Errorf("pivot must not be called when the pre-pivot redefine fails, got %d", mover.pivotCalls)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	if disks[0].StorageVolume != "hot" || disks[0].Path != src {
		t.Fatalf("DB changed despite pre-pivot failure: %+v", disks)
	}
	if exists(destPath) {
		t.Error("destination not cleaned up")
	}
}

// TestMoveVolume_Live_DBFailBeforePivot_RollsBack: the placement commit fails (zero
// rows) before the pivot → persistent config is rolled back to src and the pivot is
// never attempted.
func TestMoveVolume_Live_DBFailBeforePivot_RollsBack(t *testing.T) {
	s, f, src, destPath := liveMoveServerWithVirt(t, false)
	// Soft-delete the disk row so the placement commit affects zero rows.
	if err := corrosion.SoftDeleteDisk(context.Background(), s.db, "vm-live", "root"); err != nil {
		t.Fatalf("SoftDeleteDisk: %v", err)
	}
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	fastPoll(t)

	vm := &corrosion.VMRecord{Name: "vm-live", HostName: "host-a", State: "running"}
	srcRec := &corrosion.DiskRecord{
		VMName: "vm-live", DiskName: "root", HostName: "host-a",
		Path: src, SizeBytes: 4096, TargetDev: "vda",
		StorageType: "local", StorageVolume: "hot",
	}
	dstPool := StoragePoolRef{Driver: "local", Target: filepath.Dir(destPath)}
	err := s.liveMoveVolume(context.Background(), vm, srcRec, destPath, "warm", dstPool, false, noopSend)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted on zero-row commit, got %v", err)
	}
	if mover.pivotCalls != 0 {
		t.Errorf("pivot must not run when the pre-pivot commit fails, got %d", mover.pivotCalls)
	}
	xml, _ := f.DumpXMLInactive("vm-live")
	if !strings.Contains(xml, src) || strings.Contains(xml, destPath) {
		t.Fatalf("persistent config not rolled back to src: %s", xml)
	}
	if exists(destPath) {
		t.Error("destination not removed after rollback")
	}
}

// TestMoveVolume_Live_AlreadyPivoted_CatchUp: when the active source is already dest
// (libvirt completed the job itself), the orchestrator catches up persistent + DB
// FORWARD-ONLY and never calls pivot or rolls back.
func TestMoveVolume_Live_AlreadyPivoted_CatchUp(t *testing.T) {
	s, f, _, destPath := liveMoveServerWithVirt(t, true)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	fastPoll(t)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.pivotCalls != 0 {
		t.Errorf("pivot must not be called in the already-pivoted catch-up, got %d", mover.pivotCalls)
	}
	xml, _ := f.DumpXMLInactive("vm-live")
	if !strings.Contains(xml, destPath) {
		t.Fatalf("persistent config not caught up to dest: %s", xml)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	if disks[0].Path != destPath || disks[0].StorageVolume != "warm" {
		t.Fatalf("disk row not caught up: %+v", disks)
	}
}

// TestMoveVolume_Live_MirrorSendFailureRemovesDest: if the very first (MIRROR)
// progress send fails — e.g. the client disconnected right after preallocation — the
// preallocated destination must be cleaned up and no block-copy job may start.
func TestMoveVolume_Live_MirrorSendFailureRemovesDest(t *testing.T) {
	s, _, dstDir := liveMoveTestServer(t, 4096) // s.virt nil → straight to preallocate + MIRROR send
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx(), sendErr: errors.New("client gone")}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); err == nil {
		t.Fatal("expected the MIRROR send failure to surface")
	}
	if mover.startCalls != 0 {
		t.Errorf("no block-copy job should start when the MIRROR send fails, got startCalls=%d", mover.startCalls)
	}
	if exists(filepath.Join(dstDir, "vm-live-root.qcow2")) {
		t.Error("preallocated destination leaked after the MIRROR send failed")
	}
}

// TestMoveVolume_Live_PivotFailsAfterPrep_RollsBackBoth: persistent + DB are moved to
// dest, then the pivot fails → BOTH are rolled back to src, the source is retained,
// and the destination is removed.
func TestMoveVolume_Live_PivotFailsAfterPrep_RollsBackBoth(t *testing.T) {
	s, f, src, destPath := liveMoveServerWithVirt(t, false)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")}
	s.SetLiveMover(mover)
	fastPoll(t)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on pivot failure, got %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	if disks[0].Path != src || disks[0].StorageVolume != "hot" {
		t.Fatalf("DB not rolled back to src after pivot failure: %+v", disks)
	}
	xml, _ := f.DumpXMLInactive("vm-live")
	if !strings.Contains(xml, src) || strings.Contains(xml, destPath) {
		t.Fatalf("persistent config not rolled back to src: %s", xml)
	}
	if exists(destPath) {
		t.Error("destination not removed after pivot failure")
	}
	if !exists(src) {
		t.Error("source must be retained after pivot failure")
	}
	if mover.cancelCalls < 1 {
		t.Errorf("expected the block-copy job to be cancelled after pivot failure, got %d", mover.cancelCalls)
	}
}
