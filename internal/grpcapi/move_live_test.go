package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeLiveMover scripts the BlockJobStatus progression so tests can
// drive the orchestrator's poll loop deterministically.
type fakeLiveMover struct {
	startCalls  int32
	pivotCalls  int32
	cancelCalls int32

	// progressBytesPerPoll is added to Cur each BlockJobStatus call
	// until Cur >= jobEnd, at which point Found stays true for one
	// more call and then flips false (mirroring libvirt's behaviour
	// for transient-job auto-completion).
	jobEnd               uint64
	progressBytesPerPoll uint64
	curBytes             uint64
	finished             bool

	startErr  error
	statusErr error
	pivotErr  error
}

func (f *fakeLiveMover) StartBlockCopy(_, _, _ string, _ uint32) error {
	atomic.AddInt32(&f.startCalls, 1)
	if f.startErr != nil {
		return f.startErr
	}
	if f.progressBytesPerPoll == 0 {
		f.progressBytesPerPoll = f.jobEnd
	}
	return nil
}
func (f *fakeLiveMover) BlockJobStatus(_, _ string) (LiveMoverStatus, error) {
	if f.statusErr != nil {
		return LiveMoverStatus{}, f.statusErr
	}
	if f.finished {
		return LiveMoverStatus{Found: false}, nil
	}
	f.curBytes += f.progressBytesPerPoll
	if f.curBytes >= f.jobEnd {
		f.curBytes = f.jobEnd
		f.finished = true
		// Last in-progress tick — the orchestrator pivots on the next
		// loop iteration once it sees Cur == End.
	}
	return LiveMoverStatus{Found: true, Cur: f.curBytes, End: f.jobEnd}, nil
}
func (f *fakeLiveMover) PivotBlockCopy(_, _ string) error {
	atomic.AddInt32(&f.pivotCalls, 1)
	return f.pivotErr
}
func (f *fakeLiveMover) CancelBlockCopy(_, _ string) error {
	atomic.AddInt32(&f.cancelCalls, 1)
	return nil
}

// liveMoveTestServer builds a server with a running VM, a source
// disk, and a target pool ready for the orchestrator to mirror into.
func liveMoveTestServer(t *testing.T, srcSize int64) (*Server, string, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	srcDir := filepath.Join(s.dataDir, "hot")
	dstDir := filepath.Join(s.dataDir, "warm")
	for _, d := range []string{srcDir, dstDir} {
		if err := mkdir(d); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	src := filepath.Join(srcDir, "disk.qcow2")
	if err := writeFile(src, srcSize); err != nil {
		t.Fatalf("write src: %v", err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: dstDir},
	})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm-live", HostName: "host-a", State: "running"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm-live", DiskName: "root", HostName: "host-a",
			Path: src, SizeBytes: srcSize,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return s, src, dstDir
}

// TestMoveVolume_Live_HappyPath drives the full orchestration:
// preallocate → start → poll → pivot → DB update.
func TestMoveVolume_Live_HappyPath(t *testing.T) {
	s, src, dstDir := liveMoveTestServer(t, 4096)

	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 2048}
	s.SetLiveMover(mover)

	// Speed up the test — default is 250ms.
	prev := LiveMoverPollInterval
	LiveMoverPollInterval = 5 * time.Millisecond
	defer func() { LiveMoverPollInterval = prev }()

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.startCalls != 1 {
		t.Errorf("start = %d, want 1", mover.startCalls)
	}
	if mover.pivotCalls != 1 {
		t.Errorf("pivot = %d, want 1", mover.pivotCalls)
	}
	final := rec.Sent[len(rec.Sent)-1]
	if final.Phase != pb.MoveVolumeProgress_DONE {
		t.Errorf("final phase = %v, want DONE", final.Phase)
	}

	// DB row points at new path.
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk row, got %d", len(disks))
	}
	if disks[0].StorageVolume != "warm" {
		t.Errorf("StorageVolume = %q, want warm", disks[0].StorageVolume)
	}
	if disks[0].Path == src {
		t.Errorf("Path still points at the source: %q", disks[0].Path)
	}
	if !exists(filepath.Join(dstDir, "vm-live-root.qcow2")) {
		t.Error("destination file not created")
	}
}

// TestMoveVolume_Live_StatusErrorCancels is the bug-sweep #5 regression: a
// BlockJobStatus error mid-mirror must cancel the in-flight block-copy job (and
// remove the preallocated dest) instead of orphaning it.
func TestMoveVolume_Live_StatusErrorCancels(t *testing.T) {
	s, _, dstDir := liveMoveTestServer(t, 4096)

	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 2048, statusErr: errors.New("libvirtd hiccup")}
	s.SetLiveMover(mover)
	prev := LiveMoverPollInterval
	LiveMoverPollInterval = 5 * time.Millisecond
	defer func() { LiveMoverPollInterval = prev }()

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm",
	}, rec)
	if err == nil {
		t.Fatal("expected MoveVolume to fail on the injected status error")
	}
	if mover.cancelCalls != 1 {
		t.Errorf("block-copy job was orphaned: cancelCalls = %d, want 1", mover.cancelCalls)
	}
	if exists(filepath.Join(dstDir, "vm-live-root.qcow2")) {
		t.Error("preallocated destination leaked after the failed mirror")
	}
}

// TestMoveVolume_Live_NoMover_Unimplemented covers the "library not
// wired" path that tests using the standalone testServer hit.
func TestMoveVolume_Live_NoMover_Unimplemented(t *testing.T) {
	s, _, _ := liveMoveTestServer(t, 4096)
	// no SetLiveMover call

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for nil LiveMover, got %v", err)
	}
}

// TestMoveVolume_Live_PivotFailure_RollsBack — if the pivot call
// fails after the mirror was in sync, the orchestrator cancels and
// surfaces Internal so the caller knows the original disk is still
// authoritative.
func TestMoveVolume_Live_PivotFailure_RollsBack(t *testing.T) {
	s, _, dstDir := liveMoveTestServer(t, 4096)
	mover := &fakeLiveMover{
		jobEnd: 4096, progressBytesPerPoll: 4096,
		pivotErr: errors.New("guest agent stalled"),
	}
	s.SetLiveMover(mover)
	prev := LiveMoverPollInterval
	LiveMoverPollInterval = 1 * time.Millisecond
	defer func() { LiveMoverPollInterval = prev }()

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on pivot failure, got %v", err)
	}
	if mover.cancelCalls < 1 {
		t.Errorf("expected at least one Cancel after pivot failure, got %d", mover.cancelCalls)
	}
	// A failed pivot must not strand the preallocated destination.
	if exists(filepath.Join(dstDir, "vm-live-root.qcow2")) {
		t.Error("destination file should have been cleaned up after pivot failure")
	}
}

// TestMoveVolume_Live_StartFailure_RemovesDestFile cleans up the
// preallocated destination on failure.
func TestMoveVolume_Live_StartFailure_RemovesDestFile(t *testing.T) {
	s, _, dstDir := liveMoveTestServer(t, 4096)
	mover := &fakeLiveMover{startErr: errors.New("disk full")}
	s.SetLiveMover(mover)

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-live", DiskName: "root", TargetPool: "warm",
	}, rec); err == nil {
		t.Fatal("expected error from failed StartBlockCopy")
	}
	if exists(filepath.Join(dstDir, "vm-live-root.qcow2")) {
		t.Error("destination file should have been cleaned up")
	}
}

// ── helpers ──

func mkdir(p string) error { return os.MkdirAll(p, 0750) }

func writeFile(p string, size int64) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
