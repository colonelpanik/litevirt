package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// tracked reports whether an unresolved-tie marker is currently held for (table, pk).
func tracked(c *Client, table string, pkVals ...interface{}) bool {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	_, ok := c.unresolvedTies[unresolvedKey(table, pkKey(pkVals))]
	return ok
}

// TestWAL_LaterStatementRollbackPreservesUnresolvedMarker (review 2): a WAL-side unresolved-tie clear
// must be deferred to commit. If a later statement in the same batch back-pressures, the transaction
// rolls back and the safety-fault marker must SURVIVE — an immediate clear would temporarily hide a
// real divergence.
func TestWAL_LaterStatementRollbackPreservesUnresolvedMarker(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	c.trackUnresolved("images", pkKey([]interface{}{"img1"}), []interface{}{"a"}, []interface{}{"b"}, pathWAL, "test")
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("precondition: one tracked tie, got %d", c.UnresolvedTieCount())
	}

	good := `{"SQL":"INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["img1","f","","",1,"2020-01-01T00:00:00Z","3000000000000-0000-n2"]}`
	// An unregistered shape → back-pressure → the whole batch (including the img1 write and its
	// deferred clear) rolls back.
	bad := `{"SQL":"INSERT INTO images (name, bogus_col) VALUES (?, ?)","Params":["x","y"]}`
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: "3000000000000-0000-n2", Origin: "peer", Stmts: "[" + good + "," + bad + "]"}}); err == nil {
		t.Fatal("the unregistered second statement must back-pressure the batch")
	}
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("a rolled-back batch must NOT clear the safety-fault marker, got %d", c.UnresolvedTieCount())
	}
	if rows, _ := c.Query(ctx, "SELECT name FROM images WHERE name = ?", "img1"); len(rows) != 0 {
		t.Fatal("the first statement's write must also roll back")
	}

	// Control: the SAME good statement alone COMMITS and clears the marker — proving the deferred
	// clear does run on success (so the assertion above isn't passing merely because clearing broke).
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 2, Hlc: "3000000000000-0000-n3", Origin: "peer", Stmts: "[" + good + "]"}}); err != nil {
		t.Fatalf("good-only batch must apply: %v", err)
	}
	if c.UnresolvedTieCount() != 0 {
		t.Fatalf("a committed converging write must clear the marker, got %d", c.UnresolvedTieCount())
	}
}

// TestBulkUpdate_ClearsOnlyChangedRows (review 2): the per-row-LWW bulk apply must clear the marker
// only for the rows it actually changed, keyed by each row's exact PK (the original bulk shape has no
// full-PK identity, so a shape-based clear would be a silent no-op). A row skipped because its local
// copy is newer keeps its marker.
func TestBulkUpdate_ClearsOnlyChangedRows(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	const older, mid, newer = "1000000000000-0000-n1", "2000000000000-0000-n2", "3000000000000-0000-n3"

	// Two ip_sets in one stack: is0 older than the incoming bulk write (will change), is1 newer
	// (skipped).
	if err := c.Execute(ctx, `INSERT INTO ip_sets (id, name, stack_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"is0", "web", "stackA", "2020-01-01T00:00:00Z", older); err != nil {
		t.Fatalf("seed is0: %v", err)
	}
	if err := c.Execute(ctx, `INSERT INTO ip_sets (id, name, stack_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"is1", "db", "stackA", "2020-01-01T00:00:00Z", newer); err != nil {
		t.Fatalf("seed is1: %v", err)
	}
	c.trackUnresolved("ip_sets", pkKey([]interface{}{"is0"}), []interface{}{"a"}, []interface{}{"b"}, pathWAL, "test")
	c.trackUnresolved("ip_sets", pkKey([]interface{}{"is1"}), []interface{}{"a"}, []interface{}{"b"}, pathWAL, "test")
	if c.UnresolvedTieCount() != 2 {
		t.Fatalf("precondition: 2 tracked ties, got %d", c.UnresolvedTieCount())
	}

	// A registered bulk tombstone by stack_name at the MIDDLE timestamp.
	stmts := fmt.Sprintf(`[{"SQL":"UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL","Params":["2026-01-01T00:00:00Z","%s","stackA"]}]`, mid)
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: mid, Origin: "peer", Stmts: stmts}}); err != nil {
		t.Fatalf("apply bulk: %v", err)
	}

	if tracked(c, "ip_sets", "is0") {
		t.Error("the CHANGED row's marker must be cleared")
	}
	if !tracked(c, "ip_sets", "is1") {
		t.Error("the SKIPPED newer row's marker must be RETAINED")
	}
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("exactly one marker (the skipped row) should remain, got %d", c.UnresolvedTieCount())
	}
}
