package corrosion

import (
	"context"
	"testing"
)

// TestMergeExcludesCoordinationTables proves the LWW full-state merge allowlist
// excludes the coordination tables (vm_locks, leader_election): even a peer dump
// that CONTAINS such rows — with a newer-looking updated_at — cannot create or
// overwrite them locally. These are per-node lease state; full-state-merging them
// across a partition would risk split-brain (two VM owners) and corrupt
// leadership. A real dumpState() never includes them (they're antiEntropyExcluded),
// so this asserts the merge-path guard directly, belt-and-suspenders.
func TestMergeExcludesCoordinationTables(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := c.Execute(ctx, `INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES (?,?,?,?)`,
		"vm1", "me", "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("seed vm_lock: %v", err)
	}
	if err := c.Execute(ctx, `INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES (?,?,?,?)`,
		"failover", "me", "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("seed leader_election: %v", err)
	}

	// A peer dump trying to hand BOTH rows to a different holder with a newer ts.
	payload := &syncPayload{Tables: []syncTable{
		{Name: "vm_locks", Columns: []string{"vm_name", "holder", "expires_at", "updated_at"},
			Rows: [][]interface{}{{"vm1", "attacker", "2999-01-01T00:00:00Z", "3000-01-01T00:00:00Z"}}},
		{Name: "leader_election", Columns: []string{"key", "holder", "expires_at", "updated_at"},
			Rows: [][]interface{}{{"failover", "attacker", "2999-01-01T00:00:00Z", "3000-01-01T00:00:00Z"}}},
	}}
	c.mergeStatePayloadLWW(payload)

	assertHolder := func(table, sql, want string) {
		rows, err := c.Query(ctx, sql)
		if err != nil || len(rows) == 0 {
			t.Fatalf("%s query: err=%v rows=%d", table, err, len(rows))
		}
		if got := rows[0].String("holder"); got != want {
			t.Fatalf("%s holder = %q after merge, want %q (coordination table was wrongly merged)", table, got, want)
		}
	}
	assertHolder("vm_locks", `SELECT holder FROM vm_locks WHERE vm_name='vm1'`, "me")
	assertHolder("leader_election", `SELECT holder FROM leader_election WHERE key='failover'`, "me")

	if replicatedTableSet["vm_locks"] || replicatedTableSet["leader_election"] {
		t.Fatal("vm_locks/leader_election must NOT be in the public full-state merge allowlist")
	}
	if sensitiveTableSet["vm_locks"] || sensitiveTableSet["leader_election"] {
		t.Fatal("vm_locks/leader_election must NOT be in the sensitive merge allowlist")
	}
}
