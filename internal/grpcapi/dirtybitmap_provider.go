package grpcapi

import "strings"

// checkpointName derives the deterministic, libvirt-safe checkpoint name a
// backup establishes for a (disk, timestamp) pair. Because it's a pure
// function of the backup's own timestamp, a later incremental re-derives
// its parent's checkpoint from the parent manifest's BitmapName alone.
func checkpointName(diskName, ts string) string {
	return "lv-" + sanitizeName(diskName) + "-" + sanitizeName(ts)
}

// replCheckpointName is the checkpoint name for INCREMENTAL REPLICATION. It uses
// a distinct prefix from backup's checkpointName ("lv-…") so backup's
// GCCheckpoints (which scans the "lv-<disk>-" prefix) can never delete a
// replication checkpoint, and vice versa — the two features chained their dirty
// bitmaps in one namespace and GC'd each other (bug-sweep #4). "lvrepl-<disk>-"
// does not have "lv-<disk>-" as a prefix, so the namespaces are disjoint.
func replCheckpointName(diskName, ts string) string {
	return "lvrepl-" + sanitizeName(diskName) + "-" + sanitizeName(ts)
}

// sanitizeName maps a string to the [A-Za-z0-9_.-] alphabet libvirt accepts
// for checkpoint names (RFC3339 timestamps carry ':' and '+').
func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '-':
			return r
		default:
			return '-'
		}
	}, s)
}
