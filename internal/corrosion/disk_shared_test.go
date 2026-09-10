package corrosion

import (
	"context"
	"testing"
)

func sharedDiskTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func insertDisk(t *testing.T, c *Client, vm, disk, storageType string, deleted bool) {
	t.Helper()
	del := any(nil)
	if deleted {
		del = "2026-09-01T00:00:00Z"
	}
	if err := c.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at, deleted_at)
		 VALUES (?, ?, 'h1', ?, ?, ?, ?)`,
		vm, disk, "/pool/"+disk, storageType, c.NowTS(), del); err != nil {
		t.Fatalf("insert disk: %v", err)
	}
}

// TestVMNamesWithWritableSharedDisk_ClassifiesByStorageType pins which VMs a
// fence-readiness check counts as exposed. A miss in either direction is
// costly: a local-disk VM wrongly counted trains operators to ignore the
// warning, and a shared-disk VM missed is the corruption case the warning
// exists for.
func TestVMNamesWithWritableSharedDisk_ClassifiesByStorageType(t *testing.T) {
	c := sharedDiskTestClient(t)
	ctx := context.Background()

	for _, tc := range []struct{ vm, storage string }{
		{"vm-nfs", "nfs"},
		{"vm-ceph", "ceph"},
		{"vm-rbd", "rbd"},
		{"vm-iscsi", "iscsi"},
		{"vm-dir", "dir"},
		{"vm-lvm", "lvm"},
		{"vm-btrfs", "btrfs"},
	} {
		insertDisk(t, c, tc.vm, tc.vm+"-d0", tc.storage, false)
	}

	got, err := c.namesWithSharedDisk(ctx, t)
	if err != nil {
		t.Fatalf("VMNamesWithWritableSharedDisk: %v", err)
	}
	want := []string{"vm-ceph", "vm-iscsi", "vm-nfs", "vm-rbd"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted)", got, want)
		}
	}
}

// TestVMNamesWithWritableSharedDisk_OneSharedDiskExposesTheVM pins the
// weakest-disk rule: a VM is exposed if ANY disk is shared, because starting it
// elsewhere opens every disk it has.
func TestVMNamesWithWritableSharedDisk_OneSharedDiskExposesTheVM(t *testing.T) {
	c := sharedDiskTestClient(t)
	insertDisk(t, c, "mixed", "root", "dir", false)
	insertDisk(t, c, "mixed", "data", "ceph", false)

	got, err := c.namesWithSharedDisk(context.Background(), t)
	if err != nil {
		t.Fatalf("VMNamesWithWritableSharedDisk: %v", err)
	}
	if len(got) != 1 || got[0] != "mixed" {
		t.Fatalf("got %v, want [mixed] — one shared disk exposes the whole VM", got)
	}
}

// TestVMNamesWithWritableSharedDisk_IgnoresTombstonedDisks pins that a detached
// or deleted disk stops counting. A VM held on the exposed list by a disk it no
// longer has would make the warning permanent and unactionable.
func TestVMNamesWithWritableSharedDisk_IgnoresTombstonedDisks(t *testing.T) {
	c := sharedDiskTestClient(t)
	insertDisk(t, c, "detached", "old", "nfs", true)
	insertDisk(t, c, "live", "d0", "nfs", false)

	got, err := c.namesWithSharedDisk(context.Background(), t)
	if err != nil {
		t.Fatalf("VMNamesWithWritableSharedDisk: %v", err)
	}
	if len(got) != 1 || got[0] != "live" {
		t.Fatalf("got %v, want [live] — a tombstoned disk must not keep a VM exposed", got)
	}
}

// namesWithSharedDisk is a thin call-through so the tests above read as one
// line each.
func (c *Client) namesWithSharedDisk(ctx context.Context, t *testing.T) ([]string, error) {
	t.Helper()
	return VMNamesWithWritableSharedDisk(ctx, c)
}
