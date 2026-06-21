package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// TestContainerBackupUnsupported is the shared guard behind the PushFile /
// os.Open backup fallbacks: file-based pools are fine, block/object backends
// are rejected (they have no openable container file).
func TestContainerBackupUnsupported(t *testing.T) {
	ok := []string{"", "local", "dir", "nfs", "btrfs"}
	for _, st := range ok {
		if err := containerBackupUnsupported(&corrosion.DiskRecord{DiskName: "root", StorageType: st}); err != nil {
			t.Errorf("storage %q: want nil, got %v", st, err)
		}
	}
	bad := []string{"ceph", "zfs", "lvm-thin", "iscsi"}
	for _, st := range bad {
		err := containerBackupUnsupported(&corrosion.DiskRecord{DiskName: "root", StorageType: st})
		if status.Code(err) != codes.Unimplemented {
			t.Errorf("storage %q: want Unimplemented, got %v", st, err)
		}
	}
}

// TestBackupSnapshot_NonFileStorageRejected exercises the guard through the real
// BackupSnapshot RPC on the container-fallback path (no backupSource wired): a
// ceph disk is rejected with Unimplemented rather than failing in os.Open.
func TestBackupSnapshot_NonFileStorageRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "cephvm", HostName: "host-a", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "cephvm", DiskName: "root", HostName: "host-a",
			Path: "rbd:litevirt/cephvm-root", StorageType: "ceph",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	repoDir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}

	stream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "cephvm", DiskName: "root", RepoPath: repoDir,
		Timestamp: "2026-06-07T10:00:00Z",
	}, stream)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("want Unimplemented for ceph disk, got %v", err)
	}
}

// TestScheduledBackup_NonFileStorageRejected proves the scheduled runner now
// routes through pushBackup (and therefore the storage guard): a scheduled
// backup of a ceph disk fails with a clear storage-type error instead of a raw
// os.Open failure / silent raw-block read.
func TestScheduledBackup_NonFileStorageRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "cephvm", HostName: "host-a", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "cephvm", DiskName: "root", HostName: "host-a",
			Path: "rbd:litevirt/cephvm-root", StorageType: "ceph",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	repoDir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}

	runner := &backupRunner{server: s, repos: map[string]string{"r": repoDir}}
	err := runner.runBackupInner(ctx,
		corrosion.BackupScheduleRecord{VMName: "cephvm", Repo: "r"},
		time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("want error for scheduled backup of ceph disk, got nil")
	}
	if !strings.Contains(err.Error(), "ceph") {
		t.Errorf("error should name the storage type; got %v", err)
	}
}

// TestScheduledBackup_FileBasedProducesManifest is the #5 positive case: the
// scheduled runner now drives pushBackup, so a file-based disk still produces a
// real manifest (here via the container-PushFile fallback, backupSource being
// nil) — proving the reroute didn't break the common path.
func TestScheduledBackup_FileBasedProducesManifest(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()

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

	runner := &backupRunner{server: s, repos: map[string]string{"r": repoDir}}
	if err := runner.runBackupInner(ctx,
		corrosion.BackupScheduleRecord{VMName: "vm1", Repo: "r"},
		time.Date(2026, 6, 7, 11, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("runBackupInner: %v", err)
	}

	repo, err := pbsstore.Open(repoDir)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	m, ok, err := repo.LatestManifestFor("vm1", "root")
	if err != nil || !ok {
		t.Fatalf("expected a manifest from scheduled backup: ok=%v err=%v", ok, err)
	}
	if m.Timestamp != "2026-06-07T11:00:00Z" {
		t.Errorf("manifest ts = %q, want scheduled runAt", m.Timestamp)
	}
}

// TestCleanupPostMigration_LeavesDiskFilesUntouched locks in the #7 fix: the
// post-migration cleanup removes only the cloud-init ISO and must NOT touch disk
// files (the removed RemoveAll(<dataDir>/disks/<vm>) was a path-wrong foot-gun;
// the real, storage-aware source-disk cleanup happens at the migration site).
func TestCleanupPostMigration_LeavesDiskFilesUntouched(t *testing.T) {
	s := testServerWithLocks(t)

	disksDir := filepath.Join(s.dataDir, "disks")
	legacySubdir := filepath.Join(disksDir, "vm1") // what the old RemoveAll targeted
	if err := os.MkdirAll(legacySubdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	subdirFile := filepath.Join(legacySubdir, "root.qcow2")
	flatFile := filepath.Join(disksDir, "vm1-root.qcow2")
	mustWrite(t, subdirFile)
	mustWrite(t, flatFile)

	isoDir := filepath.Join(s.dataDir, "cloudinit")
	if err := os.MkdirAll(isoDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	iso := filepath.Join(isoDir, "vm1.iso")
	mustWrite(t, iso)

	s.cleanupPostMigration("vm1")

	if exists(iso) {
		t.Error("cloud-init ISO should have been removed")
	}
	if !exists(subdirFile) {
		t.Error("disk file under <dataDir>/disks/vm1/ was wrongly removed (foot-gun regressed)")
	}
	if !exists(flatFile) {
		t.Error("flat disk file was wrongly removed")
	}
}
