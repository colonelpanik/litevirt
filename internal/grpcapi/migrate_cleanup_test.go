package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestCleanupMigrationArtifacts_RefusesStateDB is the regression guard: even
// with a valid VM and admin auth, the cleanup RPC must only remove disk
// artifacts under a real disk-artifact root, never an arbitrary file under the
// data dir such as state.db.
func TestCleanupMigrationArtifacts_RefusesStateDB(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "mig", s.hostName, "running")

	stateDB := filepath.Join(s.dataDir, "state.db")
	if err := os.WriteFile(stateDB, []byte("critical"), 0o600); err != nil {
		t.Fatal(err)
	}
	disksDir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	diskFile := filepath.Join(disksDir, "mig-root.qcow2")
	if err := os.WriteFile(diskFile, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{
		VmName: "mig", DiskPaths: []string{stateDB, diskFile},
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}

	if _, err := os.Stat(stateDB); err != nil {
		t.Errorf("state.db was removed — cleanup must refuse paths outside disk-artifact roots")
	}
	if _, err := os.Stat(diskFile); !os.IsNotExist(err) {
		t.Errorf("legitimate disk artifact under disks/ should have been removed (err=%v)", err)
	}
}

// TestCleanupMigrationArtifacts_RequiresVMMigratePerm verifies a non-admin
// caller without vm.migrate on the VM is denied (requirePermPrecheck alone is
// not authorization).
func TestCleanupMigrationArtifacts_RequiresVMMigratePerm(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVM(t, adminCtx(), s.db, "mig", s.hostName, "running")

	// A viewer holds no vm.migrate; the RPC must deny rather than proceed.
	_, err := s.CleanupMigrationArtifacts(userCtx("v", "viewer"), &pb.CleanupMigrationArtifactsRequest{
		VmName: "mig", DiskPaths: []string{filepath.Join(s.dataDir, "disks", "mig-root.qcow2")},
	})
	if err == nil {
		t.Fatal("viewer without vm.migrate must be denied")
	}
}

// TestIsHostLocalDiskDriver guards the post-migration source-disk cleanup: it
// must fire ONLY for plain host-local file drivers. For shared (nfs/ceph/iscsi)
// or volume-manager (zfs/lvm/btrfs) backends, the source path is the same file
// the target now uses, so deleting it would destroy the live disk.
func TestIsHostLocalDiskDriver(t *testing.T) {
	local := []string{"local", "dir"}
	for _, d := range local {
		if !isHostLocalDiskDriver(d) {
			t.Errorf("driver %q should be treated as host-local (cleanup-eligible)", d)
		}
	}
	notLocal := []string{"", "nfs", "ceph", "iscsi", "zfs", "lvm-thin", "btrfs", "unknown"}
	for _, d := range notLocal {
		if isHostLocalDiskDriver(d) {
			t.Errorf("driver %q must NOT be cleanup-eligible (risk of deleting a shared/live disk)", d)
		}
	}
}
