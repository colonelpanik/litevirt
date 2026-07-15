package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestStateDigest_ColumnOrderInvariant is the core motivating case: two nodes hold
// logically identical rows but in a different physical column ORDER (a fresh CREATE vs
// an ALTER-upgraded schema). The positional v1 Hash MUST differ (that's the standing
// false-divergence), while the order-invariant v2 HashV2 MUST match once both nodes
// enable digest_v2. Count is equal in both cases.
func TestStateDigest_ColumnOrderInvariant(t *testing.T) {
	ctx := context.Background()

	// storage_pools has a known PK (host_name, name) but the digest hashes the whole
	// declared column set regardless — we just need the two nodes' scratch tables to
	// carry the same columns in a different order with identical logical rows.
	nodeA := testClient(t)
	nodeB := testClient(t)
	nodeA.SetDigestV2Enabled(func() bool { return true })
	nodeB.SetDigestV2Enabled(func() bool { return true })

	if _, err := nodeA.db.ExecContext(ctx,
		`CREATE TABLE dv2 (id TEXT, name TEXT, updated_at TEXT)`); err != nil {
		t.Fatalf("create A: %v", err)
	}
	// nodeB: same columns, different physical order (as if id was ADDed by ALTER).
	if _, err := nodeB.db.ExecContext(ctx,
		`CREATE TABLE dv2 (name TEXT, updated_at TEXT, id TEXT)`); err != nil {
		t.Fatalf("create B: %v", err)
	}
	insert := func(c *Client, id, name string) {
		t.Helper()
		if _, err := c.db.ExecContext(ctx,
			`INSERT INTO dv2 (id, name, updated_at) VALUES (?, ?, ?)`, id, name, "2024-01-01T00:00:00Z"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert(nodeA, "1", "alpha")
	insert(nodeA, "2", "beta")
	insert(nodeB, "1", "alpha")
	insert(nodeB, "2", "beta")

	da, err := nodeA.stateDigestForTables(ctx, []string{"dv2"})
	if err != nil || len(da) != 1 {
		t.Fatalf("digest A: %v (%d tables)", err, len(da))
	}
	db, err := nodeB.stateDigestForTables(ctx, []string{"dv2"})
	if err != nil || len(db) != 1 {
		t.Fatalf("digest B: %v (%d tables)", err, len(db))
	}

	if da[0].Count != db[0].Count {
		t.Fatalf("count mismatch: A=%d B=%d", da[0].Count, db[0].Count)
	}
	if da[0].Hash == db[0].Hash {
		t.Fatalf("expected v1 (positional) hashes to DIFFER across column orders, both %q", da[0].Hash)
	}
	if da[0].HashV2 == "" || db[0].HashV2 == "" {
		t.Fatalf("expected v2 hashes to be emitted (A=%q B=%q)", da[0].HashV2, db[0].HashV2)
	}
	if da[0].HashV2 != db[0].HashV2 {
		t.Fatalf("expected v2 hashes to MATCH across column orders, A=%q B=%q", da[0].HashV2, db[0].HashV2)
	}
}

// TestDigestTableRows_V1UnaffectedByV2 pins that turning digest_v2 ON does not change the
// v1 (positional) hash of a table — enabling the feature must be behavior-neutral for the
// v1 comparison every mixed-version / flag-off peer still uses.
func TestDigestTableRows_V1UnaffectedByV2(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := UpsertStoragePool(ctx, c, StoragePoolRecord{
		HostName: "host-a", Name: "pool1", Driver: "local", TotalBytes: 5000000000, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}

	c.SetDigestV2Enabled(func() bool { return false })
	off, err := c.stateDigestForTables(ctx, []string{"storage_pools"})
	if err != nil || len(off) != 1 {
		t.Fatalf("digest off: %v", err)
	}
	c.SetDigestV2Enabled(func() bool { return true })
	on, err := c.stateDigestForTables(ctx, []string{"storage_pools"})
	if err != nil || len(on) != 1 {
		t.Fatalf("digest on: %v", err)
	}
	if off[0].Hash != on[0].Hash {
		t.Fatalf("v1 hash changed when digest_v2 enabled: off=%q on=%q", off[0].Hash, on[0].Hash)
	}
	if off[0].HashV2 != "" {
		t.Fatalf("expected NO v2 hash when disabled, got %q", off[0].HashV2)
	}
	if on[0].HashV2 == "" {
		t.Fatalf("expected a v2 hash when enabled")
	}
}

// TestDigestMismatches_PairwiseNegotiation exercises the field-presence negotiation in
// digestMismatches: v2 is compared ONLY when both sides supply hash_v2, otherwise v1 is
// the arbiter — in both directions — and Count is always compared.
func TestDigestMismatches_PairwiseNegotiation(t *testing.T) {
	local := func(hash, hashV2 string, count int) TableDigest {
		return TableDigest{Name: "t", Hash: hash, HashV2: hashV2, Count: count}
	}
	remote := func(hash, hashV2 string, count int) *pb.TableDigest {
		return &pb.TableDigest{Name: "t", Hash: hash, HashV2: hashV2, Count: int32(count)}
	}
	cases := []struct {
		name     string
		local    TableDigest
		remote   *pb.TableDigest
		mismatch bool
	}{
		{"both-v2-equal-v1-differs-converged",
			local("v1a", "v2same", 3), remote("v1b", "v2same", 3), false},
		{"both-v2-differ-mismatch",
			local("v1same", "v2a", 3), remote("v1same", "v2b", 3), true},
		{"local-flag-off-v1-equal-fallback-converged",
			local("v1same", "", 3), remote("v1same", "v2b", 3), false},
		{"local-flag-off-v1-differs-mismatch",
			local("v1a", "", 3), remote("v1b", "v2b", 3), true},
		{"remote-preV2-v1-equal-fallback-converged",
			local("v1same", "v2a", 3), remote("v1same", "", 3), false},
		{"count-differs-always-mismatch",
			local("v1same", "v2same", 3), remote("v1same", "v2same", 4), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := digestMismatches("peer", []*pb.TableDigest{tc.remote},
				map[string]TableDigest{"t": tc.local})
			if (len(got) > 0) != tc.mismatch {
				t.Fatalf("mismatch=%v, want %v (got tables %v)", len(got) > 0, tc.mismatch, got)
			}
		})
	}
}

// TestTableSnapshot_ColumnReorderV2 is the Lane-B (divergence scanner) analogue: the same
// logical row in two different column orders yields DIFFERENT v1 RowHash but the SAME v2
// RowHashV2, so ClassifyTable sees the two nodes as converged under v2.
func TestTableSnapshot_ColumnReorderV2(t *testing.T) {
	colsA := []string{"host_name", "name", "driver", "updated_at"}
	rowsA := [][]interface{}{{"host-a", "pool1", "local", "2024-01-01T00:00:00Z"}}
	// Same PK + same logical values, physical columns reordered.
	colsB := []string{"name", "driver", "host_name", "updated_at"}
	rowsB := [][]interface{}{{"pool1", "local", "host-a", "2024-01-01T00:00:00Z"}}

	snapA, _ := tableSnapshotFromRows("storage_pools", colsA, rowsA, true)
	snapB, _ := tableSnapshotFromRows("storage_pools", colsB, rowsB, true)

	pk := "host-a" + pkSep + "pool1"
	ma, okA := snapA.Rows[pk]
	mb, okB := snapB.Rows[pk]
	if !okA || !okB {
		t.Fatalf("missing row: A=%v B=%v", okA, okB)
	}
	if ma.RowHash == mb.RowHash {
		t.Fatalf("expected v1 RowHash to differ across column order, both %q", ma.RowHash)
	}
	if ma.RowHashV2 == "" || mb.RowHashV2 == "" {
		t.Fatalf("expected v2 RowHash emitted (A=%q B=%q)", ma.RowHashV2, mb.RowHashV2)
	}
	if ma.RowHashV2 != mb.RowHashV2 {
		t.Fatalf("expected v2 RowHash to match across column order, A=%q B=%q", ma.RowHashV2, mb.RowHashV2)
	}
}

// TestSameHash_PairwiseV2 covers the Lane-B row-level negotiation: v2 arbitrates only when
// EVERY node supplies row_hash_v2 (so a column-order artifact — v1 differs, v2 equal — reads
// converged), and a single node missing v2 falls the whole comparison back to v1.
func TestSameHash_PairwiseV2(t *testing.T) {
	cases := []struct {
		name    string
		perNode map[string]RowMeta
		same    bool
	}{
		{"all-v2-equal-v1-differs-converged", map[string]RowMeta{
			"a": {RowHash: "v1a", RowHashV2: "v2same"},
			"b": {RowHash: "v1b", RowHashV2: "v2same"},
		}, true},
		{"all-v2-differ-divergent", map[string]RowMeta{
			"a": {RowHash: "v1same", RowHashV2: "v2a"},
			"b": {RowHash: "v1same", RowHashV2: "v2b"},
		}, false},
		{"one-missing-v2-falls-back-to-v1-equal", map[string]RowMeta{
			"a": {RowHash: "v1same", RowHashV2: "v2a"},
			"b": {RowHash: "v1same", RowHashV2: ""},
		}, true},
		{"one-missing-v2-falls-back-to-v1-differs", map[string]RowMeta{
			"a": {RowHash: "v1a", RowHashV2: "v2same"},
			"b": {RowHash: "v1b", RowHashV2: ""},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameHash(tc.perNode); got != tc.same {
				t.Fatalf("sameHash=%v, want %v", got, tc.same)
			}
		})
	}
}
