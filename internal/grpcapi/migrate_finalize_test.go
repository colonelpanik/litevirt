package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFinalizeMigrationOwnership_CommitFailurePreservesSource reproduces the P0
// migration-cutover bug: after libvirt has already cut the VM over to the target,
// the ownership DB write is committed unchecked and the source disk is deleted
// regardless. If that write fails, the pre-fix code still deletes the source disk
// (data loss) and reports success (stale/dual ownership in Corrosion).
//
// A BEFORE UPDATE trigger on vm_disks forces the disk-ownership write to fail. The
// correct post-condition — the source disk survives and the failure surfaces — must
// hold; this test fails against the pre-fix behavior and passes once the commit is a
// hard gate before the source delete.
func TestFinalizeMigrationOwnership_CommitFailurePreservesSource(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	const vmName = "mig-vm"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")

	// A real host-local source disk file that a --with-storage migration would
	// orphan and then try to delete on the source host.
	diskPath := filepath.Join(t.TempDir(), vmName+"-root.qcow2")
	if err := os.WriteFile(diskPath, []byte("disk-contents"), 0o600); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName,
		Path: diskPath, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	// Snapshot the disks before cutover, exactly as MigrateVM does.
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}

	// Inject a failure of the disk-ownership UPDATE (simulates a Corrosion write
	// error at the post-cutover commit).
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER inject_fail BEFORE UPDATE ON vm_disks BEGIN SELECT RAISE(ABORT, 'inject'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}

	ferr := s.finalizeMigrationOwnership(ctx, vm, "target-host", true, disks)

	if ferr == nil {
		t.Error("finalizeMigrationOwnership returned nil; want an error when the ownership commit cannot land")
	}
	if _, statErr := os.Stat(diskPath); os.IsNotExist(statErr) {
		t.Error("source disk was deleted even though the ownership commit failed (data loss)")
	}
}

// TestFinalizeMigrationOwnership_Success proves the happy path: the VM and every
// disk are repointed to the target, and the orphaned host-local source disk is
// removed only after the commit lands.
func TestFinalizeMigrationOwnership_Success(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-ok"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	diskPath := filepath.Join(t.TempDir(), vmName+"-root.qcow2")
	if err := os.WriteFile(diskPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: diskPath, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, vmName)

	if err := s.finalizeMigrationOwnership(ctx, vm, "target-host", true, disks); err != nil {
		t.Fatalf("finalizeMigrationOwnership: %v", err)
	}

	got, _ := corrosion.GetVM(ctx, s.db, vmName)
	if got.HostName != "target-host" {
		t.Errorf("VM host_name = %q, want target-host", got.HostName)
	}
	after, _ := corrosion.GetVMDisks(ctx, s.db, vmName)
	if len(after) != 1 || after[0].HostName != "target-host" {
		t.Errorf("disk host_name not repointed to target: %+v", after)
	}
	if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
		t.Error("orphaned source disk should have been removed after a successful commit")
	}
}

// TestCommitMigrationOwnership_DriftDeclines proves the guard refuses to clobber a
// concurrent retarget that changed a disk's storage type after the pre-cutover
// snapshot was taken.
func TestCommitMigrationOwnership_DriftDeclines(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-drift"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: "/pool/a.qcow2", StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)

	// A concurrent move changed the disk's storage type after the snapshot.
	if err := s.db.Execute(ctx,
		`UPDATE vm_disks SET storage_type = 'ceph' WHERE vm_name = ? AND disk_name = 'root'`, vmName); err != nil {
		t.Fatalf("mutate disk: %v", err)
	}

	committed, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if committed {
		t.Error("commit succeeded despite disk placement drift; want decline")
	}
	if got, _ := corrosion.GetVM(ctx, s.db, vmName); got.HostName != s.hostName {
		t.Errorf("VM host changed to %q on a declined commit; want %s", got.HostName, s.hostName)
	}
}

// TestCommitMigrationOwnership_Idempotent proves a retry after the move already
// landed (VM + disks on target) returns committed=true, not a precondition failure.
func TestCommitMigrationOwnership_Idempotent(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-idem"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: "/pool/a.qcow2", StorageType: "nfs",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)

	if ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks); err != nil || !ok {
		t.Fatalf("first commit: ok=%v err=%v", ok, err)
	}
	// Retry with the same source/target — now already on target.
	ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks)
	if err != nil {
		t.Fatalf("idempotent retry errored: %v", err)
	}
	if !ok {
		t.Error("idempotent retry returned committed=false; want true (already on target)")
	}
}
