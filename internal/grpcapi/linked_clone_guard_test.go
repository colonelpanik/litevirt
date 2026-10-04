package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedBaseAndLinkedClone puts a base VM's root disk in the DEFAULT disk dir —
// which is what the glob in DeleteVMDisks sweeps — and an overlay VM whose disk
// names it in backing_disk.
func seedBaseAndLinkedClone(t *testing.T, s *Server) string {
	t.Helper()
	ctx := adminCtx()
	basePath := filepath.Join(s.images.DiskDir(""), "base-root.qcow2")
	mustWrite(t, basePath)

	insertTestVM(t, ctx, s.db, "base", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "base", DiskName: "root", HostName: "test-host", Path: basePath,
	}); err != nil {
		t.Fatalf("InsertDisk(base): %v", err)
	}
	insertTestVM(t, ctx, s.db, "clone1", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "clone1", DiskName: "root", HostName: "test-host",
		Path: filepath.Join(s.images.DiskDir(""), "clone1-root.qcow2"), BackingDisk: basePath,
	}); err != nil {
		t.Fatalf("InsertDisk(clone1): %v", err)
	}
	return basePath
}

// TestDeleteVM_KeepsADiskThatStillBacksALinkedClone is part of the #185
// regression.
//
// deleteRecordedVMDiskVolumeRecords asks diskPathReferencedByOtherVM before
// freeing each recorded disk, and that now sees backing_disk. But DeleteVM then
// globs the default disk dir for "debris" and removed everything matching
// <vm>-*.qcow2 with no reference check at all — so the base's file went anyway
// and every overlay's backing chain was destroyed. An overlay without its
// backing file cannot be recovered.
func TestDeleteVM_KeepsADiskThatStillBacksALinkedClone(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("images.Init: %v", err)
	}
	if err := s.virt.DefineDomain("<domain><name>base</name></domain>"); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	basePath := seedBaseAndLinkedClone(t, s)

	// DeleteVM refuses outright while clones exist (the guard above), so drive
	// the disk-removal half directly: this is about what the glob does once the
	// caller has decided to proceed.
	s.deleteRecordedVMDiskVolumes(adminCtx(), "base")
	// sweepVMDiskDebris reports failures by logging them, so there is no error
	// to check here — wrapping it in a closure that can only return nil made the
	// branch unreachable and named a function the line no longer calls.
	s.sweepVMDiskDebris(adminCtx(), "base")

	if !exists(basePath) {
		t.Fatalf("%s still backs clone1 and was deleted by the default-dir glob; "+
			"every overlay's chain is destroyed", basePath)
	}
}

// The glob must still do its job — unreferenced debris for the same VM goes.
func TestDeleteVM_StillSweepsUnreferencedDebris(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("images.Init: %v", err)
	}
	basePath := seedBaseAndLinkedClone(t, s)
	debris := filepath.Join(s.images.DiskDir(""), "base-scratch.qcow2")
	mustWrite(t, debris)

	// sweepVMDiskDebris reports failures by logging them, so there is no error
	// to check here — wrapping it in a closure that can only return nil made the
	// branch unreachable and named a function the line no longer calls.
	s.sweepVMDiskDebris(adminCtx(), "base")
	if exists(debris) {
		t.Error("unreferenced debris survived; the glob stopped working")
	}
	if !exists(basePath) {
		t.Error("the still-referenced base disk was swept")
	}
}

// TestStartVM_RefusesAVMThatStillBacksLinkedClones is the third #185 hole.
//
// StartVM rejected only vm.IsTemplate, while CloneVM accepts any stopped
// non-template VM as a linked source. So a plain VM can back overlays, and
// starting it lets qemu write into the backing file underneath every one of
// them — silent corruption of each overlay, discovered later.
func TestStartVM_RefusesAVMThatStillBacksLinkedClones(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("images.Init: %v", err)
	}
	if err := s.virt.DefineDomain("<domain><name>base</name></domain>"); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	seedBaseAndLinkedClone(t, s)

	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "base"})
	if err == nil {
		t.Fatal("StartVM accepted a VM that still backs a linked clone; qemu will " +
			"write into the backing file under every overlay")
	}
	if !strings.Contains(err.Error(), "linked clone") && !strings.Contains(err.Error(), "clone1") {
		t.Errorf("StartVM error does not say why: %v", err)
	}
}

// A VM with no overlays still starts — the guard must not block ordinary VMs.
func TestStartVM_StartsAVMWithNoLinkedClones(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("images.Init: %v", err)
	}
	if err := s.virt.DefineDomain("<domain><name>solo</name></domain>"); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "solo", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "solo", DiskName: "root", HostName: "test-host",
		Path: filepath.Join(s.images.DiskDir(""), "solo-root.qcow2"),
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "solo"}); err != nil {
		t.Fatalf("StartVM refused an ordinary VM: %v", err)
	}
}
