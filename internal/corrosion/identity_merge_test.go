package corrosion

import (
	"context"
	"testing"
)

// snapshotDumpCols is the full snapshots column list for an anti-entropy dump.
var snapshotDumpCols = []string{
	"id", "vm_name", "host_name", "name", "state", "size_bytes", "parent_id", "type",
	"vmstate_path", "vmstate_size_bytes", "created_at", "updated_at", "deleted_at",
}

// snapshotDumpRow builds a dump row for the snapshots table.
func snapshotDumpRow(id, vmName, host, name, updatedAt string) []interface{} {
	return []interface{}{id, vmName, host, name, "ready", nil, nil, "disk", nil, 0, "2020-01-01T00:00:00Z", updatedAt, nil}
}

func seedSnapshot(t *testing.T, c *Client, id, vmName, name, updatedAt string) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, vmName, "host-a", name, "ready", "2020-01-01T00:00:00Z", updatedAt); err != nil {
		t.Fatalf("seed snapshot %s: %v", id, err)
	}
}

// TestMergeIdentity_IncomingWinsCollapses: under canonical_identity_v1, a newer incoming
// snapshot with a DIFFERENT id but the same natural key collapses the local one — the group
// converges to the single winning id instead of colliding on the secondary UNIQUE.
func TestMergeIdentity_IncomingWinsCollapses(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "1000000000000-0000-n1")

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name: "snapshots", Columns: snapshotDumpCols,
		Rows: [][]interface{}{snapshotDumpRow("incoming-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2")},
	}}})

	rows, err := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 snapshot for (vm1, snap1), got %d (collapse failed)", len(rows))
	}
	if got := rows[0].String("id"); got != "incoming-id" {
		t.Errorf("surviving id = %q, want incoming-id (winner)", got)
	}
	if gone, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE id = ?", "local-id"); len(gone) != 0 {
		t.Error("local-id must be collapsed away")
	}
}

// TestMergeIdentity_LocalWinsKeepsLocal: an OLDER incoming with a different id keeps local.
func TestMergeIdentity_LocalWinsKeepsLocal(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "2000000000000-0000-n1")

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name: "snapshots", Columns: snapshotDumpCols,
		Rows: [][]interface{}{snapshotDumpRow("incoming-id", "vm1", "host-b", "snap1", "1000000000000-0000-n2")},
	}}})

	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "local-id" {
		t.Fatalf("local (newer) must be kept; got %d rows id=%v", len(rows), rows)
	}
}

// TestMergeIdentity_DisabledBackPressures: with the capability OFF (default), the same
// collision keeps local via the constraint path — no collapse (the legacy behavior).
func TestMergeIdentity_DisabledBackPressures(t *testing.T) {
	c := mustTestClient(t) // canonicalIdentity hook unset ⇒ off
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "1000000000000-0000-n1")

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name: "snapshots", Columns: snapshotDumpCols,
		Rows: [][]interface{}{snapshotDumpRow("incoming-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2")},
	}}})

	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "local-id" {
		t.Fatalf("capability off: local must be kept (no collapse); got %d rows id=%v", len(rows), rows)
	}
}

// TestMergeIdentity_Convergence: the same collision resolved on two nodes from opposite
// starting rows reaches the SAME winning id — the associativity the resolver guarantees.
func TestMergeIdentity_Convergence(t *testing.T) {
	const tsA = "1000000000000-0000-n1"
	const tsB = "2000000000000-0000-n2" // newer ⇒ id-b wins on both nodes
	rowA := snapshotDumpRow("id-a", "vm1", "host-a", "snap1", tsA)
	rowB := snapshotDumpRow("id-b", "vm1", "host-b", "snap1", tsB)

	// Node 1 starts with A, receives B. Node 2 starts with B, receives A.
	n1 := mustTestClient(t)
	n1.SetCanonicalIdentity(func() bool { return true })
	seedSnapshot(t, n1, "id-a", "vm1", "snap1", tsA)
	n1.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{Name: "snapshots", Columns: snapshotDumpCols, Rows: [][]interface{}{rowB}}}})

	n2 := mustTestClient(t)
	n2.SetCanonicalIdentity(func() bool { return true })
	seedSnapshot(t, n2, "id-b", "vm1", "snap1", tsB)
	n2.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{Name: "snapshots", Columns: snapshotDumpCols, Rows: [][]interface{}{rowA}}}})

	ctx := context.Background()
	id1, _ := n1.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	id2, _ := n2.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(id1) != 1 || len(id2) != 1 {
		t.Fatalf("each node must have one row; got n1=%d n2=%d", len(id1), len(id2))
	}
	if id1[0].String("id") != id2[0].String("id") || id1[0].String("id") != "id-b" {
		t.Errorf("nodes diverged: n1=%q n2=%q (want both id-b)", id1[0].String("id"), id2[0].String("id"))
	}
}

// TestMergeIdentity_NonNullReferenceFailsClosed: a non-null parent_id (the provably-unused
// reference class) must fail closed rather than orphan on collapse.
func TestMergeIdentity_NonNullReferenceFailsClosed(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	row := snapshotDumpRow("incoming-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2")
	row[6] = "some-parent" // parent_id column
	err := c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name: "snapshots", Columns: snapshotDumpCols, Rows: [][]interface{}{row},
	}}})
	if err == nil {
		t.Fatal("a non-null parent_id must fail closed under canonical_identity_v1")
	}
}
