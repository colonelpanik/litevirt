package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// progressStream is a grpc.ServerStreamingServer test double that
// captures every Send into a slice.
type progressStream[T any] struct {
	ctx  context.Context
	Sent []*T
}

func (p *progressStream[T]) Send(m *T) error              { p.Sent = append(p.Sent, m); return nil }
func (p *progressStream[T]) Context() context.Context     { return p.ctx }
func (p *progressStream[T]) SetHeader(metadata.MD) error  { return nil }
func (p *progressStream[T]) SendHeader(metadata.MD) error { return nil }
func (p *progressStream[T]) SetTrailer(metadata.MD)       {}
func (p *progressStream[T]) SendMsg(interface{}) error    { return nil }
func (p *progressStream[T]) RecvMsg(interface{}) error    { return io.EOF }

var _ grpc.ServerStreamingServer[pb.BackupSnapshotProgress] = (*progressStream[pb.BackupSnapshotProgress])(nil)
var _ grpc.ServerStreamingServer[pb.RestoreFromBackupProgress] = (*progressStream[pb.RestoreFromBackupProgress])(nil)

// TestBackupSnapshot_LocalRoundTrip pushes a real qcow2 into a real
// repo, then restores it back into a different file and asserts a
// matching manifest can be retrieved by the round-tripped TS.
func TestBackupSnapshot_LocalRoundTrip(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()

	// Set up a VM with one disk on this host.
	tmp := t.TempDir()
	diskPath := filepath.Join(tmp, "disk.qcow2")
	if err := qcow2.Create(diskPath, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "host-a",
			Path: diskPath, SizeBytes: 1 << 20, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	repoDir := filepath.Join(tmp, "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}

	// 1. Push a snapshot.
	pushStream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vm1", DiskName: "root", RepoPath: repoDir, Timestamp: "2026-05-10T10:00:00Z",
	}, pushStream); err != nil {
		t.Fatalf("BackupSnapshot: %v", err)
	}
	last := pushStream.Sent[len(pushStream.Sent)-1]
	if last.Phase != pb.BackupSnapshotProgress_DONE {
		t.Fatalf("final phase = %v, want DONE", last.Phase)
	}
	if last.ManifestTs != "2026-05-10T10:00:00Z" {
		t.Errorf("manifest_ts = %q", last.ManifestTs)
	}

	// 2. Restore to a new path; check the file exists and is non-empty.
	restored := filepath.Join(tmp, "restored.qcow2")
	restoreStream := &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()}
	if err := s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root",
		Timestamp:  "2026-05-10T10:00:00Z",
		TargetPath: restored,
	}, restoreStream); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	if st, err := os.Stat(restored); err != nil || st.Size() == 0 {
		t.Errorf("restored file missing or empty: %v / size=%d", err, func() int64 {
			if st != nil {
				return st.Size()
			}
			return 0
		}())
	}
}

// TestBackupSnapshot_VMOnRemoteHost_FailedPrecondition is the
// single-host model regression: callers point at the VM's owning
// daemon explicitly.
func TestBackupSnapshot_VMOnRemoteHost_FailedPrecondition(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vmB", HostName: "host-b", State: "running"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vmB", DiskName: "root", HostName: "host-b", Path: "/x", SizeBytes: 1,
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	stream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vmB", RepoPath: t.TempDir(),
	}, stream)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for cross-host VM, got %v", err)
	}
}

func contains2(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestRestoreFromBackup_RejectsMissingManifest covers the operator
// fat-finger case.
func TestRestoreFromBackup_RejectsMissingManifest(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	repoDir := t.TempDir()
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	stream := &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()}
	err := s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: repoDir, VmName: "ghost", DiskName: "root",
		Timestamp:  "2026-05-10T10:00:00Z",
		TargetPath: filepath.Join(repoDir, "out.bin"),
	}, stream)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for missing manifest, got %v", err)
	}
}
