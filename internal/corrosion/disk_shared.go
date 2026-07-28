package corrosion

import "strings"

// sharedStorageTypes is the set of disk storage drivers that place a disk on
// cluster-shared storage — a second host can open and WRITE the same bytes. A
// shared writable disk is the split-brain hazard a cross-host ownership transfer
// (auto-promote / reschedule) must fence against: unlike a local-disk replica
// (a different image on the target), starting a VM on a shared disk while the
// old owner may still be writing it corrupts the disk.
func sharedStorageType(storageType string) bool {
	switch strings.ToLower(storageType) {
	case "nfs", "ceph", "rbd", "iscsi":
		return true
	default:
		return false
	}
}

// DiskIsShared reports whether a disk lives on cluster-shared storage
// (nfs/ceph/rbd/iscsi). Local/dir/btrfs/lvm are host-local. Exported so the
// failover coordinator, health reconciler, and grpcapi promote path share one
// definition of "shared" rather than each carrying a copy.
func DiskIsShared(d DiskRecord) bool { return sharedStorageType(d.StorageType) }

// VMHasWritableSharedDisk reports whether ANY of the VM's disks is on shared
// storage. There is no read-only bit on DiskRecord, so every disk is treated as
// writable (weakest-writable-disk controls: one shared disk ⇒ the whole VM needs
// the proof-grade fence before a cross-host transfer start).
func VMHasWritableSharedDisk(disks []DiskRecord) bool {
	for _, d := range disks {
		if DiskIsShared(d) {
			return true
		}
	}
	return false
}
