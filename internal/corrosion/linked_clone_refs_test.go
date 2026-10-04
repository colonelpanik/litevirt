package corrosion

import (
	"context"
	"testing"
)

// seedLinkedClone inserts a base VM holding a golden disk and one overlay VM
// whose disk records that path in backing_disk — the column a linked clone
// actually uses.
func seedLinkedClone(t *testing.T, c *Client, basePath string) {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: "base", HostName: "h1", State: "stopped"}, nil,
		[]DiskRecord{{VMName: "base", DiskName: "root", HostName: "h1", Path: basePath}}); err != nil {
		t.Fatalf("InsertVM(base): %v", err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "clone1", HostName: "h1", State: "stopped"}, nil,
		[]DiskRecord{{
			VMName: "clone1", DiskName: "root", HostName: "h1",
			Path: "/disks/clone1-root.qcow2", BackingDisk: basePath,
		}}); err != nil {
		t.Fatalf("InsertVM(clone1): %v", err)
	}
}

// TestDisksReferencingPath_FindsLinkedCloneOverlays is part of the #185
// regression.
//
// The query was `path = ? OR backing_image = ?` and never backing_disk — which
// is the column a linked clone writes. DisksReferencingPath is what
// diskPathReferencedByOtherVM asks before deleting a disk file, so a base whose
// only referrers were linked clones read as unreferenced and its file was
// removed. Every overlay's backing chain is destroyed at once, and an overlay
// without its backing file is not recoverable.
//
// LinkedCloneNames already queries backing_disk correctly, which is what the
// refcount guard was supposed to be consulting.
func TestDisksReferencingPath_FindsLinkedCloneOverlays(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	const basePath = "/disks/base-root.qcow2"
	seedLinkedClone(t, c, basePath)

	refs, err := DisksReferencingPath(ctx, c, basePath)
	if err != nil {
		t.Fatalf("DisksReferencingPath: %v", err)
	}
	var foundClone bool
	for _, r := range refs {
		if r.VMName == "clone1" {
			foundClone = true
			if r.BackingDisk != basePath {
				t.Errorf("clone1 backing_disk = %q, want %q — the column must be "+
					"carried back, not just matched", r.BackingDisk, basePath)
			}
		}
	}
	if !foundClone {
		t.Fatalf("clone1 overlays %s via backing_disk and was not reported as a "+
			"referrer; the base's file would be deleted out from under it. got %+v",
			basePath, refs)
	}
}

// The other two reference kinds still work — this must be an addition.
func TestDisksReferencingPath_StillFindsPathAndBackingImage(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	const shared = "/disks/shared.qcow2"

	if err := InsertVM(ctx, c, VMRecord{Name: "a", HostName: "h1", State: "stopped"}, nil,
		[]DiskRecord{{VMName: "a", DiskName: "root", HostName: "h1", Path: shared}}); err != nil {
		t.Fatalf("InsertVM(a): %v", err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "b", HostName: "h1", State: "stopped"}, nil,
		[]DiskRecord{{
			VMName: "b", DiskName: "root", HostName: "h1",
			Path: "/disks/b-root.qcow2", BackingImage: shared,
		}}); err != nil {
		t.Fatalf("InsertVM(b): %v", err)
	}

	refs, err := DisksReferencingPath(ctx, c, shared)
	if err != nil {
		t.Fatalf("DisksReferencingPath: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range refs {
		seen[r.VMName] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("want both a (path) and b (backing_image) as referrers, got %v", seen)
	}
}

// A tombstoned overlay must not pin its base forever.
func TestDisksReferencingPath_IgnoresDeletedOverlays(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	const basePath = "/disks/base-root.qcow2"
	seedLinkedClone(t, c, basePath)

	if err := DeleteVM(ctx, c, "clone1"); err != nil {
		t.Fatalf("DeleteVM(clone1): %v", err)
	}
	refs, err := DisksReferencingPath(ctx, c, basePath)
	if err != nil {
		t.Fatalf("DisksReferencingPath: %v", err)
	}
	for _, r := range refs {
		if r.VMName == "clone1" {
			t.Errorf("a deleted overlay still pins its base: %+v", r)
		}
	}
}
