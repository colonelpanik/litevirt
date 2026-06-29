package storage

import "context"

// Teardowner is the OPTIONAL host-side cleanup capability, mirroring the optional
// Replicator pattern. A driver that mounts or logs into something at Prepare time
// (NFS, iSCSI) implements it to undo that on pool delete; most drivers
// (local/dir/ceph/zfs/btrfs/lvm-thin) don't, so AsTeardowner returns nil and the
// caller treats teardown as a no-op.
//
// Teardown must be safe to call WITHOUT a prior Prepare (it derives its own paths)
// and idempotent (a no-op when nothing is mounted / logged in). Whether teardown is
// even attempted — refcounting a shared NFS export / iSCSI target across other pool
// rows — is the caller's job, since that needs the cluster DB.
type Teardowner interface {
	Teardown(ctx context.Context) error
}

// AsTeardowner returns d as a Teardowner if it implements one, else nil.
func AsTeardowner(d Driver) Teardowner {
	if t, ok := d.(Teardowner); ok {
		return t
	}
	return nil
}
