package corrosion

import (
	"context"
	"testing"
)

// TestDiscardReplicatedStateForReseed_ClearsSensitiveTables is part of the #199
// regression.
//
// The discard iterated tableNames only. sensitiveTableNames — registry
// credentials, notification targets and routes, 2FA factors and their sets,
// recovery codes and their sets, and the split-brain runtime action proofs —
// were never cleared. A node reseeding out of quarantine therefore kept every
// row it had written while it was incompatible, and once the isolation epoch
// cleared a healthy peer pulled them fleet-wide. That is precisely the state a
// reseed exists to discard.
func TestDiscardReplicatedStateForReseed_ClearsSensitiveTables(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	// One row in every sensitive table, written the way a quarantined node
	// would have: local, unreplicated.
	for _, tbl := range SensitiveTableNames() {
		seedOneRow(t, c, tbl)
	}
	for _, tbl := range SensitiveTableNames() {
		if n := rowCountOf(t, c, tbl); n == 0 {
			t.Fatalf("fixture failed: %s is empty before the discard", tbl)
		}
	}

	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("DiscardReplicatedStateForReseed: %v", err)
	}

	for _, tbl := range SensitiveTableNames() {
		if n := rowCountOf(t, c, tbl); n != 0 {
			t.Errorf("%s still holds %d row(s) after a reseed discard; a quarantined "+
				"secret survives the reseed and replicates fleet-wide once the epoch clears",
				tbl, n)
		}
	}
}

// The operator tables are still cleared, and the keep set is still kept — the
// sensitive addition must not disturb either.
func TestDiscardReplicatedStateForReseed_StillHonoursTheKeepSet(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := InsertHost(ctx, c, HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("DiscardReplicatedStateForReseed: %v", err)
	}

	if n := rowCountOf(t, c, "vms"); n != 0 {
		t.Errorf("vms still holds %d row(s); the operator tables must be replaced", n)
	}
	if n := rowCountOf(t, c, "hosts"); n == 0 {
		t.Error("hosts was cleared; it carries the isolation record and the peer " +
			"addressing this node needs to keep talking to the cluster")
	}
}

// seedOneRow inserts a single row into an arbitrary table, filling every column
// the schema requires. Generic on purpose: the assertion is about EVERY
// sensitive table, and a hand-written insert per table would quietly stop
// covering one the day a table is added to the set.
func seedOneRow(t *testing.T, c *Client, table string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	if len(rows) == 0 {
		t.Fatalf("table %s has no columns (does it exist?)", table)
	}
	var cols []string
	var vals []interface{}
	for _, r := range rows {
		name := r.String("name")
		cols = append(cols, name)
		switch r.String("type") {
		case "INTEGER", "INT":
			vals = append(vals, 1)
		default:
			vals = append(vals, "quarantined-"+table+"-"+name)
		}
	}
	ph := ""
	for i := range cols {
		if i > 0 {
			ph += ", "
		}
		ph += "?"
	}
	colList := ""
	for i, c2 := range cols {
		if i > 0 {
			colList += ", "
		}
		colList += c2
	}
	// full-state-delete-ok: test fixture, not a production writer.
	if err := c.Execute(ctx, `INSERT OR REPLACE INTO `+table+` (`+colList+`) VALUES (`+ph+`)`, vals...); err != nil {
		t.Fatalf("seed %s: %v", table, err)
	}
}

// rowCountOf is a local spelling so this file does not collide with the
// package's other row counters.
func rowCountOf(t *testing.T, c *Client, table string) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM `+table)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Int("n")
}
