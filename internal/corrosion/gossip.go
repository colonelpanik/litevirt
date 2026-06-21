package corrosion

import (
	"log/slog"
)

// delegate implements memberlist.Delegate for the Client.
// Memberlist is used for membership detection only — no application data
// is sent through gossip. Replication is handled by the WAL-based replicator.
type delegate struct {
	client *Client
}

func (d *delegate) NodeMeta(limit int) []byte {
	return []byte(d.client.hostName)
}

// NotifyMsg is a no-op — application data is replicated via gRPC, not gossip.
func (d *delegate) NotifyMsg(msg []byte) {
	if len(msg) > 0 {
		slog.Debug("gossip: ignoring data message (replication handled by WAL)")
	}
}

// GetBroadcasts returns nil — we don't broadcast application data via gossip.
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return nil
}

// LocalState returns nil — full state sync is handled by the replicator on join.
func (d *delegate) LocalState(join bool) []byte {
	return nil
}

// MergeRemoteState is a no-op — state merging is handled by the replicator.
func (d *delegate) MergeRemoteState(buf []byte, join bool) {}
