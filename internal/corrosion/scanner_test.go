package corrosion

import (
	"context"
	"testing"
)

func TestScanLocalTables_AndDumpRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := InsertHost(ctx, c, HostRecord{Name: "host-a", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "host-a", Name: "web", State: "running"}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	// Local scan: the container row is present, keyed by its composed PK, with a
	// non-empty content hash; and it surfaces as an owned row for the semantic check.
	snaps, owned, err := c.ScanLocalTables(ctx, []string{"hosts", "containers"})
	if err != nil {
		t.Fatalf("ScanLocalTables: %v", err)
	}
	ctLabel := "host-a" + pkSep + "web"
	if m, ok := snaps["containers"].Rows[ctLabel]; !ok || m.RowHash == "" || m.State != "running" {
		t.Fatalf("container row meta missing/empty: %+v", snaps["containers"].Rows)
	}
	var sawOwned bool
	for _, o := range owned {
		if o.Host == "host-a" && o.Name == "web" {
			sawOwned = true
		}
	}
	if !sawOwned {
		t.Fatalf("expected an owned container row, got %+v", owned)
	}

	// Peer-dump round-trip: parsing this node's own operator-safe dump yields the
	// SAME per-row hash (so cross-node comparison is apples-to-apples).
	dumpSnaps, _, err := SnapshotFromDumpBytes(c.DumpStateBytes(), map[string]bool{"containers": true})
	if err != nil {
		t.Fatalf("SnapshotFromDumpBytes: %v", err)
	}
	if dumpSnaps["containers"].Rows[ctLabel].RowHash != snaps["containers"].Rows[ctLabel].RowHash {
		t.Fatalf("dump hash %q != local hash %q",
			dumpSnaps["containers"].Rows[ctLabel].RowHash, snaps["containers"].Rows[ctLabel].RowHash)
	}
}

func TestScanLocalSensitive_HMACOnly(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Seed a sensitive row (recovery_codes: PK includes a bcrypt-style hash).
	now := c.NowTS()
	if err := c.Execute(ctx,
		`INSERT INTO recovery_codes (username, code_hash, set_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"alice", "$2a$10$abcdefghijklmnopqrstuv", "set1", now, now); err != nil {
		t.Fatalf("seed recovery_codes: %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	rows, err := c.ScanLocalSensitive(ctx, key, []string{"recovery_codes"})
	if err != nil {
		t.Fatalf("ScanLocalSensitive: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 sensitive row, got %d", len(rows))
	}
	r := rows[0]
	// Never leak the raw PK (username + code_hash) or content.
	if contains(r.PKLabel, "alice") || contains(r.PKLabel, "$2a$") || contains(r.RowHash, "alice") {
		t.Fatalf("sensitive HMAC leaked plaintext: %+v", r)
	}
	// HMACs are deterministic for the same key (cross-node matching).
	rows2, _ := c.ScanLocalSensitive(ctx, key, []string{"recovery_codes"})
	if rows2[0].PKLabel != r.PKLabel || rows2[0].RowHash != r.RowHash {
		t.Fatal("sensitive HMAC not deterministic for the same key")
	}
	// And fold into a snapshot keyed by the HMAC label.
	snap := SensitiveRowsToSnapshot(rows)
	if _, ok := snap["recovery_codes"].Rows[r.PKLabel]; !ok {
		t.Fatalf("sensitive snapshot missing HMAC-keyed row: %+v", snap)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
