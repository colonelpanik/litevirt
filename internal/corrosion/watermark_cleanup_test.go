package corrosion

import (
	"context"
	"testing"
)

// seedWatermark inserts a replication watermark for a peer.
func seedWatermark(t *testing.T, c *Client, peer string) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at)
		 VALUES (?, 42, datetime('now'))`, peer); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
}

func watermarkExists(t *testing.T, c *Client, peer string) bool {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT peer_name FROM replication_watermarks WHERE peer_name = ?`, peer)
	if err != nil {
		t.Fatalf("query watermark: %v", err)
	}
	return len(rows) > 0
}

// TestCleanupDepartedWatermark_KeepsRejoinedPeer is the A4 regression: if a peer
// rejoins before the cleanup grace period elapses, its watermark must survive
// (deleting it would force a needless full re-sync).
func TestCleanupDepartedWatermark_KeepsRejoinedPeer(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer db.Close()
	if err := InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	r := NewReplicator(db, "", RelayConfig{})

	seedWatermark(t, db, "peer-x")
	// Peer rejoined: it's back in r.peers before the cleanup timer fires.
	// Set it directly (same package) to avoid spawning a real peer goroutine.
	r.mu.Lock()
	r.peers["peer-x"] = func() {}
	r.mu.Unlock()

	r.cleanupDepartedWatermark("peer-x")

	if !watermarkExists(t, db, "peer-x") {
		t.Error("watermark for a rejoined (live) peer was wrongly deleted")
	}
}

// TestCleanupDepartedWatermark_DeletesDepartedPeer confirms the cleanup still
// reclaims the watermark of a peer that is genuinely gone.
func TestCleanupDepartedWatermark_DeletesDepartedPeer(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer db.Close()
	if err := InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	r := NewReplicator(db, "", RelayConfig{})

	seedWatermark(t, db, "peer-y")
	// peer-y never rejoined — not in r.peers.
	r.cleanupDepartedWatermark("peer-y")

	if watermarkExists(t, db, "peer-y") {
		t.Error("watermark for a genuinely-departed peer should be deleted")
	}
}
