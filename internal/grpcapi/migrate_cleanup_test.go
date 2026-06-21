package grpcapi

import "testing"

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
