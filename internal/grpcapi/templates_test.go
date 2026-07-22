package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// TestCloneVM_LinkedAndFull is the end-to-end clone-engine test: real qcow2
// overlay (linked) + convert (full) against a fake libvirt, asserting disk
// files, backing-disk lineage, the refcount guard, and that a clone is a
// startable (non-template) VM.
func TestCloneVM_LinkedAndFull(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	_ = s.virt.DefineDomain("<domain><name>tpl</name></domain>") // so DeleteVM(tpl) reaches the clone guard
	ctx := adminCtx()

	// Source template with a real qcow2 disk on local storage.
	srcDisk := s.images.DiskPath("tpl", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 2, MemoryMib: 2048})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM tpl: %v", err)
	}

	// Linked clone.
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "linked1", Mode: "linked"}); err != nil {
		t.Fatalf("CloneVM linked: %v", err)
	}
	if _, err := os.Stat(s.images.DiskPath("linked1", "root")); err != nil {
		t.Fatalf("linked clone disk missing: %v", err)
	}
	ld, _ := corrosion.GetVMDisks(ctx, s.db, "linked1")
	if len(ld) != 1 || ld[0].BackingDisk != srcDisk {
		t.Errorf("linked clone backing_disk = %q, want %q", diskBacking(ld), srcDisk)
	}
	c, _ := corrosion.GetVM(ctx, s.db, "linked1")
	if c == nil || c.IsTemplate {
		t.Error("a clone must be a normal (non-template) VM")
	}

	// Refcount guard: the template can't be reverted while the linked clone lives.
	if _, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "tpl", Revert: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("revert with a live linked clone: expected FailedPrecondition, got %v", err)
	}

	// Full clone: independent, no backing.
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "full1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM full: %v", err)
	}
	fd, _ := corrosion.GetVMDisks(ctx, s.db, "full1")
	if len(fd) != 1 || fd[0].BackingDisk != "" {
		t.Errorf("full clone must have no backing_disk, got %q", diskBacking(fd))
	}
	if _, err := os.Stat(s.images.DiskPath("full1", "root")); err != nil {
		t.Errorf("full clone disk missing: %v", err)
	}

	// Deleting the template is refused while a linked clone still depends on it.
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "tpl"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("delete template with a live linked clone: want FailedPrecondition, got %v", err)
	}
}

// TestCloneVM_PopulatesHardwareTables verifies a clone populates the v42
// vm_nics table for its (fresh-MAC) network attachment — mirroring CreateVM
// (task 7.1) — and deliberately carries NO vm_pci_intent rows: v1 clones never
// bring PCI passthrough along (the source's device may still be in use by the
// still-running original), so srcSpec.Devices is dropped (templates.go:214)
// before the clone's spec is persisted.
func TestCloneVM_PopulatesHardwareTables(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	ctx := adminCtx()

	srcDisk := s.images.DiskPath("tpl", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "tpl", Cpu: 2, MemoryMib: 2048,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
		Devices: []*pb.DeviceSpec{{Address: "0000:41:00.0"}}, // must NOT survive into the clone
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM tpl: %v", err)
	}

	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "clone1", Mode: "linked"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}

	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, "clone1")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].NetworkName != "lo" {
		t.Fatalf("vm_interfaces = %+v, want 1 row on lo", ifaces)
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "clone1")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(nics) != 1 || nics[0].NetworkName != "lo" || nics[0].Model != "e1000" || nics[0].MAC != ifaces[0].MAC {
		t.Fatalf("vm_nics = %+v, want 1 e1000 row on lo matching vm_interfaces MAC %q", nics, ifaces[0].MAC)
	}
	if nics[0].Ordinal != 0 {
		t.Errorf("vm_nics[0].Ordinal = %d, want 0", nics[0].Ordinal)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "clone1")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 0 {
		t.Fatalf("vm_pci_intent = %+v, want 0 rows (v1 clones drop PCI passthrough)", intents)
	}
}

func diskBacking(d []corrosion.DiskRecord) string {
	if len(d) == 0 {
		return "<none>"
	}
	return d[0].BackingDisk
}

// TestCloneVM_Guards covers the no-libvirt validation paths.
func TestCloneVM_Guards(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "nope", Target: "x"}); status.Code(err) != codes.NotFound {
		t.Errorf("missing source: want NotFound, got %v", err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "a", Target: "bad name"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad target name: want InvalidArgument, got %v", err)
	}
	insertTestVM(t, ctx, s.db, "running-src", "test-host", "running")
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "running-src", Target: "c1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cloning a running non-template: want FailedPrecondition, got %v", err)
	}
}

func TestConvertToTemplate_Flow(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "tpl-src", "test-host", "stopped")

	// Convert.
	if _, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "tpl-src"}); err != nil {
		t.Fatalf("ConvertToTemplate: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "tpl-src")
	if vm == nil || !vm.IsTemplate {
		t.Fatalf("expected is_template after convert, got %+v", vm)
	}

	// A template can't start.
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "tpl-src"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("starting a template: expected FailedPrecondition, got %v", err)
	}

	// Double-convert is rejected.
	if _, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "tpl-src"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("double convert: expected FailedPrecondition, got %v", err)
	}

	// Revert.
	if _, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "tpl-src", Revert: true}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	vm, _ = corrosion.GetVM(ctx, s.db, "tpl-src")
	if vm.IsTemplate {
		t.Error("expected is_template cleared after revert")
	}
}

func TestConvertToTemplate_RunningRejected(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "run-vm", "test-host", "running")
	if _, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "run-vm"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("converting a running VM: expected FailedPrecondition, got %v", err)
	}
}

// A template whose disk backs a live linked clone can't be reverted (reverting
// makes it startable, which would corrupt the clones).
func TestConvertToTemplate_RevertBlockedByLinkedClone(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	// Template with a disk at a known path.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", IsTemplate: true},
		nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: "/disks/tpl-root.qcow2", StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM tpl: %v", err)
	}
	// A linked clone overlay backed by the template's disk.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "clone1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{VMName: "clone1", DiskName: "root", HostName: "test-host", Path: "/disks/clone1-root.qcow2", StorageType: "local", BackingDisk: "/disks/tpl-root.qcow2"}},
	); err != nil {
		t.Fatalf("InsertVM clone1: %v", err)
	}

	_, err := s.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "tpl", Revert: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("revert with a live linked clone: expected FailedPrecondition, got %v", err)
	}
}

func TestCloneMode(t *testing.T) {
	for _, tc := range []struct {
		requested string
		allShared bool
		want      string
	}{
		{"linked", false, "linked"},
		{"full", true, "full"},
		{"", true, "linked"}, // auto + shared → linked
		{"", false, "full"},  // auto + any-local → full (avoid host-pin)
		{"auto", true, "linked"},
		{"auto", false, "full"},
	} {
		if got := cloneMode(tc.requested, tc.allShared); got != tc.want {
			t.Errorf("cloneMode(%q, %v) = %q, want %q", tc.requested, tc.allShared, got, tc.want)
		}
	}
}

func TestAllDisksShared(t *testing.T) {
	shared := []corrosion.DiskRecord{{StorageType: "nfs"}, {StorageType: "ceph"}}
	mixed := []corrosion.DiskRecord{{StorageType: "nfs"}, {StorageType: "local"}}
	if !allDisksShared(shared) {
		t.Error("all-shared disks should report shared")
	}
	if allDisksShared(mixed) {
		t.Error("a local disk makes the set not-all-shared")
	}
	if allDisksShared(nil) {
		t.Error("empty disk set is not all-shared")
	}
}
