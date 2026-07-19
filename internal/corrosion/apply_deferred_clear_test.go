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

// TestWAL_UnresolvedCreationRolledBackByLaterFailure (review 2): a tie CREATED during a WAL batch
// tracks its unresolved marker only on commit. If a later statement back-pressures, the batch rolls
// back and NO ghost marker is created.
func TestWAL_UnresolvedCreationRolledBackByLaterFailure(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2026-06-03T18:40:00Z"
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	forceUpdatedAt(t, c, "vms", "name", "vm1", ts)

	// stmt1 is an exact-tie runtime-owned write (would track unresolved, DEFERRED); stmt2 is an
	// unregistered shape → back-pressure → the whole batch rolls back, dropping the deferred track.
	tie := `{"SQL":"INSERT OR REPLACE INTO vms (name, host_name, state, spec, updated_at) VALUES (?, ?, ?, ?, ?)","Params":["vm1","host-b","running","{}","2026-06-03T18:40:00Z"]}`
	bad := `{"SQL":"INSERT INTO vms (name, bogus_col) VALUES (?, ?)","Params":["x","y"]}`
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "peer", Stmts: "[" + tie + "," + bad + "]"}}); err == nil {
		t.Fatal("the unregistered statement must back-pressure the batch")
	}
	if c.UnresolvedTieCount() != 0 {
		t.Fatalf("a rolled-back batch must NOT create a ghost unresolved marker, got %d", c.UnresolvedTieCount())
	}
}

// TestAE_ChunkRollbackRetainsMarker (review 2): an AE merge that applies a strictly-newer row would
// clear that PK's unresolved marker — but only on commit. A chunk that rolls back must RETAIN the
// marker (it must not clear it for a change that never landed). The committed control clears it.
func TestAE_ChunkRollbackRetainsMarker(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	const oldTs, newTs = "1000000000000-0000-n1", "3000000000000-0000-n2"
	if err := c.Execute(ctx,
		`INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"img1", "old", "", "", 1, "2020-01-01T00:00:00Z", oldTs); err != nil {
		t.Fatalf("seed: %v", err)
	}
	c.trackUnresolved("images", pkKey([]interface{}{"img1"}), []interface{}{"a"}, []interface{}{"b"}, pathAE, "test")

	newerImg1 := func() *syncPayload {
		return &syncPayload{Tables: []syncTable{{
			Name:    "images",
			Columns: []string{"name", "format", "source_url", "checksum", "size_bytes", "created_at", "updated_at"},
			Rows:    [][]interface{}{{"img1", "new", "", "", int64(1), "2020-01-01T00:00:00Z", newTs}},
		}}}
	}

	// Forced rollback: the strictly-newer img1 applies + schedules the deferred clear, then the chunk
	// rolls back (the merge returns the forced-rollback error, as expected) → the clear is dropped →
	// marker retained.
	mergeChunkFailHook = func() bool { return true }
	if err := c.mergeStatePayloadLWW(newerImg1()); err == nil {
		t.Fatal("the forced-rollback hook must make the merge return an error")
	}
	mergeChunkFailHook = nil
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("a rolled-back AE chunk must RETAIN the marker, got %d", c.UnresolvedTieCount())
	}

	// Committed control: the same merge now commits and clears the marker (proving the deferred
	// clear runs on success, so the assertion above isn't passing merely because clearing broke).
	if err := c.mergeStatePayloadLWW(newerImg1()); err != nil {
		t.Fatalf("merge (commit): %v", err)
	}
	if c.UnresolvedTieCount() != 0 {
		t.Fatalf("a committed AE merge must clear the marker, got %d", c.UnresolvedTieCount())
	}
}
