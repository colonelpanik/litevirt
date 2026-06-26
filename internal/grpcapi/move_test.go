package grpcapi

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// streamRecorder is a minimal grpc.ServerStreamingServer[pb.MoveVolumeProgress]
// for unit testing — captures every Send into Sent.
type streamRecorder[T any] struct {
	ctx  context.Context
	Sent []*T
}

func (r *streamRecorder[T]) Send(m *T) error              { r.Sent = append(r.Sent, m); return nil }
func (r *streamRecorder[T]) Context() context.Context     { return r.ctx }
func (r *streamRecorder[T]) SetHeader(metadata.MD) error  { return nil }
func (r *streamRecorder[T]) SendHeader(metadata.MD) error { return nil }
func (r *streamRecorder[T]) SetTrailer(metadata.MD)       {}
func (r *streamRecorder[T]) SendMsg(m interface{}) error  { return nil }
func (r *streamRecorder[T]) RecvMsg(m interface{}) error  { return io.EOF }
func (r *streamRecorder[T]) Done() <-chan struct{}        { return nil }
func (r *streamRecorder[T]) Trailer() metadata.MD         { return nil }
func (r *streamRecorder[T]) Header() (metadata.MD, error) { return nil, nil }
func (r *streamRecorder[T]) CloseSend() error             { return nil }

var _ grpc.ServerStreamingServer[pb.MoveVolumeProgress] = (*streamRecorder[pb.MoveVolumeProgress])(nil)

// TestMoveVolume_AlreadyInTargetPool_IsIdempotent verifies that moving a disk
// to the pool it already lives in is a successful no-op (terminal DONE frame),
// not a FailedPrecondition. A repeat/retried move must read as "done", not
// "failed" — that was the confusing "disk already in pool X" UI error.
func TestMoveVolume_AlreadyInTargetPool_IsIdempotent(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/tmp/vm1-root.qcow2", SizeBytes: 1 << 20,
			StorageType: "local", StorageVolume: "warm",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm",
	}, rec); err != nil {
		t.Fatalf("MoveVolume to same pool returned error, want nil: %v", err)
	}
	if len(rec.Sent) == 0 || rec.Sent[len(rec.Sent)-1].Phase != pb.MoveVolumeProgress_DONE {
		t.Fatalf("expected a terminal DONE frame; sent: %+v", rec.Sent)
	}
	// No actual move happened: disk stays in its pool, no disk.moved event.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if len(disks) != 1 || disks[0].StorageVolume != "warm" {
		t.Fatalf("disk pool changed unexpectedly: %+v", disks)
	}
	evs, _ := corrosion.ListVMEvents(ctx, s.db, "vm1", 10, "")
	for _, e := range evs {
		if e.Type == "disk.moved" {
			t.Errorf("a no-op move must not record a disk.moved event")
		}
	}
}

// TestMoveVolume_OfflineFileToFile drives a full offline move from one
// local directory to another, verifying:
//   - the source file is read,
//   - a destination file is written,
//   - the disk record is updated with the new path/pool,
//   - DONE is the final phase emitted,
//   - delete_source removes the original on success.
func TestMoveVolume_OfflineFileToFile(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()

	srcDir := filepath.Join(s.dataDir, "src")
	dstDir := filepath.Join(s.dataDir, "dst")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}

	// Create a real (but tiny) qcow2 so qemu-img convert can actually
	// re-encode it into the destination. We assert "destination exists +
	// disk record updated" rather than byte-for-byte equality, since
	// qemu-img legitimately rewrites cluster headers.
	srcFile := filepath.Join(srcDir, "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	srcStat, err := os.Stat(srcFile)
	if err != nil {
		t.Fatalf("stat src: %v", err)
	}
	srcSize := srcStat.Size()

	// Configure target pool.
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: dstDir},
	})

	// Insert VM + disk records.
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: srcFile, SizeBytes: srcSize,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm", DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}

	// Last phase must be DONE.
	last := rec.Sent[len(rec.Sent)-1]
	if last.Phase != pb.MoveVolumeProgress_DONE {
		t.Errorf("final phase = %v, want DONE; sent: %+v", last.Phase, rec.Sent)
	}

	// Destination file present and non-empty. qemu-img convert may
	// rewrite cluster headers so we don't compare byte-for-byte.
	dstFile := filepath.Join(dstDir, "vm1-root.qcow2")
	dstStat, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if dstStat.Size() == 0 {
		t.Error("destination file is empty")
	}

	// Source removed (delete_source=true).
	if _, err := os.Stat(srcFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected source removed after delete_source=true, stat err = %v", err)
	}

	// Disk record now points at the new path and pool.
	disks, err := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if err != nil || len(disks) != 1 {
		t.Fatalf("GetVMDisks: %v / %d", err, len(disks))
	}
	if disks[0].Path != dstFile {
		t.Errorf("disk.Path = %q, want %q", disks[0].Path, dstFile)
	}
	if disks[0].StorageVolume != "warm" {
		t.Errorf("disk.StorageVolume = %q, want %q", disks[0].StorageVolume, "warm")
	}

	// The move must record a disk.moved event — storage moves were previously
	// invisible in the VM's activity feed.
	evs, err := corrosion.ListVMEvents(ctx, s.db, "vm1", 10, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	var moved *corrosion.VMEventRecord
	for i := range evs {
		if evs[i].Type == "disk.moved" {
			moved = &evs[i]
			break
		}
	}
	if moved == nil {
		t.Fatalf("expected a disk.moved event after move; got %+v", evs)
	}
	if !strings.Contains(moved.Detail, "warm") {
		t.Errorf("disk.moved detail = %q, want it to mention target pool", moved.Detail)
	}
}

// TestMoveVolume_SnapshottedDiskRejected verifies a disk with a snapshot overlay
// is refused (its backing chain can't survive a pool move) — closing the
// move-volume → cross-host-migration backing-chain gap (G1 drill finding).
func TestMoveVolume_SnapshottedDiskRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: t.TempDir()},
	})
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-snap", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm-snap", DiskName: "root", HostName: "test-host",
			Path: filepath.Join(t.TempDir(), "x.qcow2"), SizeBytes: 1,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName: "vm-snap", HostName: "test-host", Name: "snap1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-snap", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a snapshotted disk, got %v", err)
	}
	if !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("error should explain the snapshot backing-chain reason, got: %v", err)
	}
}

// TestMoveVolume_RunningVMRejected verifies that MoveVolume on a
// running VM requires a wired LiveMover. Without one,
// the call returns Unimplemented — same status code as,
// but for a different reason. Tests that wire a LiveMover are in
// move_live_test.go.
func TestMoveVolume_RunningVMRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: t.TempDir()},
	})
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-running", HostName: "test-host", State: "running"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm-running", DiskName: "root", HostName: "test-host",
			Path: filepath.Join(t.TempDir(), "x.qcow2"), SizeBytes: 1,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-running", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for running VM, got %v", err)
	}
}

// TestMoveVolume_UnknownTargetPoolRejected catches the most common
// operator typo.
func TestMoveVolume_UnknownTargetPoolRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-x", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm-x", DiskName: "root", HostName: "test-host",
			Path: filepath.Join(t.TempDir(), "x.qcow2"), SizeBytes: 1,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-x", DiskName: "root", TargetPool: "nonexistent",
	}, rec)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestMoveVolume_BlockDriverSourceUnimplemented(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: t.TempDir()},
	})
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-ceph", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm-ceph", DiskName: "root", HostName: "test-host",
			Path: "rbd:pool/vm-ceph-root", SizeBytes: 1,
			StorageType: "ceph", StorageVolume: "ceph-hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm-ceph", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for block-driver source, got %v", err)
	}
	if len(rec.Sent) != 0 {
		t.Fatalf("block-driver rejection should fail before progress frames, got %+v", rec.Sent)
	}
}
