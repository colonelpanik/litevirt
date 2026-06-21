package grpcapi

import (
	"strings"
	"testing"
)

// TestCheckpointNamespacesDisjoint locks in bug-sweep #4: replication checkpoints
// must not fall under backup's GCCheckpoints prefix (and vice versa), or one
// feature's GC deletes the other's dirty-bitmap chain.
func TestCheckpointNamespacesDisjoint(t *testing.T) {
	disk, ts := "root", "2026-01-01T00:00:00Z"
	backupCP := checkpointName(disk, ts)
	replCP := replCheckpointName(disk, ts)

	// backup_source.GCCheckpoints scans this prefix and deletes anything under
	// it that isn't in the keep-set.
	gcPrefix := "lv-" + sanitizeName(disk) + "-"

	if !strings.HasPrefix(backupCP, gcPrefix) {
		t.Errorf("backup checkpoint %q must match its own GC prefix %q", backupCP, gcPrefix)
	}
	if strings.HasPrefix(replCP, gcPrefix) {
		t.Errorf("replication checkpoint %q must NOT match backup GC prefix %q — backup GC would delete it", replCP, gcPrefix)
	}
	if backupCP == replCP {
		t.Errorf("backup and replication checkpoint names collide: %q", backupCP)
	}
}
