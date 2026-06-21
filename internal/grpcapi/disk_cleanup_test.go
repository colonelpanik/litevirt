package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// mustWrite creates a non-empty stub file (reusing the package writeFile
// helper from move_live_test.go) and fails the test if it can't.
func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := writeFile(path, 4096); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestDeleteRecordedVMDiskVolumes_FreesDirPoolDisk reproduces the orphaned-disk
// bug: a disk relocated to a non-default pool (here a `dir` pool at a path
// outside the default disk dir, exactly what `lv move-volume` produces) must be
// freed at its RECORDED location, not left behind because the default-dir glob
// never saw it.
func TestDeleteRecordedVMDiskVolumes_FreesDirPoolDisk(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := context.Background()

	poolDir := t.TempDir() // stands in for the nvme-2t dir pool (/docker/litevirt)
	s.addStoragePoolRef("nvme-2t", StoragePoolRef{Driver: "dir", Target: poolDir})

	diskPath := filepath.Join(poolDir, "vm1-root.qcow2")
	mustWrite(t, diskPath)

	insertTestVM(t, ctx, s.db, "vm1", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "test-host",
		Path: diskPath, StorageType: "dir", StorageVolume: "nvme-2t",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	s.deleteRecordedVMDiskVolumes(ctx, "vm1")

	if exists(diskPath) {
		t.Fatal("disk at non-default pool path was NOT freed (orphaned)")
	}
}

// TestDeleteRecordedVMDiskVolumes_FreesBareLocalPathDisk covers a `local`-typed
// disk recorded at a path outside the default disk dir with no named pool — the
// driver still resolves (falls back to the local driver) and the file is freed.
func TestDeleteRecordedVMDiskVolumes_FreesBareLocalPathDisk(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := context.Background()

	diskPath := filepath.Join(t.TempDir(), "vm2-root.qcow2")
	mustWrite(t, diskPath)

	insertTestVM(t, ctx, s.db, "vm2", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm2", DiskName: "root", HostName: "test-host",
		Path: diskPath, StorageType: "local", StorageVolume: "",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	s.deleteRecordedVMDiskVolumes(ctx, "vm2")

	if exists(diskPath) {
		t.Fatal("local disk outside default dir was NOT freed")
	}
}

// TestDeleteRecordedVMDiskVolumes_KeepsSharedDisk asserts the shared-disk guard:
// a path still referenced by another VM (shared volume / backing image) must NOT
// be deleted when one of the referencing VMs is torn down.
func TestDeleteRecordedVMDiskVolumes_KeepsSharedDisk(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := context.Background()

	shared := filepath.Join(t.TempDir(), "shared.qcow2")
	mustWrite(t, shared)

	insertTestVM(t, ctx, s.db, "owner", "test-host", "stopped")
	insertTestVM(t, ctx, s.db, "sibling", "test-host", "stopped")
	for _, vm := range []string{"owner", "sibling"} {
		if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: vm, DiskName: "root", HostName: "test-host",
			Path: shared, StorageType: "local",
		}); err != nil {
			t.Fatalf("InsertDisk(%s): %v", vm, err)
		}
	}

	s.deleteRecordedVMDiskVolumes(ctx, "owner")

	if !exists(shared) {
		t.Fatal("shared disk still referenced by sibling was wrongly deleted")
	}
}

// TestDeleteVM_FreesNonDefaultPoolDisk drives the full DeleteVM RPC and proves
// the wiring: a stopped VM whose root disk lives on a non-default pool is fully
// removed — record gone AND the backing file freed.
func TestDeleteVM_FreesNonDefaultPoolDisk(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir) // default-dir glob fallback target
	if err := s.virt.DefineDomain("<domain><name>vm1</name></domain>"); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	ctx := adminCtx()

	poolDir := t.TempDir()
	s.addStoragePoolRef("nvme-2t", StoragePoolRef{Driver: "dir", Target: poolDir})
	diskPath := filepath.Join(poolDir, "vm1-root.qcow2")
	mustWrite(t, diskPath)

	insertTestVM(t, ctx, s.db, "vm1", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "test-host",
		Path: diskPath, StorageType: "dir", StorageVolume: "nvme-2t",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	if exists(diskPath) {
		t.Error("DeleteVM orphaned the non-default-pool disk")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm != nil {
		t.Errorf("VM record still present after delete: %+v", vm)
	}
}
