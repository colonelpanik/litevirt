// native send/receive replication.
//
// `lv replicate-volume` historically falls back to qemu-img convert
// for every backend. Native primitives (zfs send | recv, rbd
// export-diff | import-diff, btrfs send | receive) are faster and
// preserve snapshot history — both important for federation +
// off-site DR.
//
// Drivers that can replicate efficiently implement the Replicator
// interface. The grpcapi layer queries it before falling back.

package storage

import (
	"context"
	"errors"
)

// Replicator is an optional capability a Driver may implement when it
// has a backend-native replication primitive. The result of Replicate
// is "destination dataset/image now contains a snapshot equivalent to
// source as of the call". Whether incremental or full is up to the
// implementation; the caller doesn't care.
type Replicator interface {
	// Replicate copies one logical volume to another using the
	// backend's native send/recv. srcRef and dstRef are the
	// driver-specific identifiers (zfs dataset, rbd image, btrfs
	// subvolume path); the implementation parses them.
	Replicate(ctx context.Context, opts ReplicateOptions) error
}

// ReplicateOptions is the input to Replicator.Replicate.
type ReplicateOptions struct {
	SrcRef string
	DstRef string

	// SnapshotName is the name to use for the source snapshot taken
	// for this replication. Empty = synthesise from the timestamp.
	SnapshotName string

	// Incremental, when true and the backend supports it, sends only
	// the diff since the prior replication snapshot (zfs incremental
	// send / rbd export-diff). false forces a full send.
	Incremental bool

	// SSHTarget is "user@host" for cross-host pipes. Empty = local
	// pipe (same host, different dataset/pool).
	SSHTarget string
}

// ErrReplicationNotSupported is returned by drivers that don't have a
// native send/recv primitive. The grpcapi layer treats this as a
// signal to fall back to the qemu-img convert path.
var ErrReplicationNotSupported = errors.New("driver has no native replication; fall back to qemu-img convert")

// AsReplicator returns the Replicator view of d if the driver has
// implemented it, or nil otherwise. Used by callers that want to
// detect support without panicking on type assertions.
func AsReplicator(d Driver) Replicator {
	if r, ok := d.(Replicator); ok {
		return r
	}
	return nil
}
