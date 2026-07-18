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

// snapshotSyncTable wraps one dump row for a single-table AE merge payload.
func snapshotSyncPayload(cols []string, row []interface{}) *syncPayload {
	return &syncPayload{Tables: []syncTable{{Name: "snapshots", Columns: cols, Rows: [][]interface{}{row}}}}
}

// TestMergeIdentity_CollapsePreservesReceiverOnlyColumn (finding 2): when the incoming winner
// arrives on an OLDER schema whose dump OMITS a column, collapsing must PRESERVE the local value
// of that receiver-only column (the collapse re-keys in place rather than delete-then-insert). A
// delete-then-insert would reset exactly the newer column the mixed-schema work protects.
func TestMergeIdentity_CollapsePreservesReceiverOnlyColumn(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	// Local row (id-local) carries a receiver-only column value.
	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, vmstate_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"id-local", "vm1", "host-a", "snap1", "ready", "/keep/me", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Incoming winner (newer, different id) on an older schema that omits vmstate_path.
	subset := []string{"id", "vm_name", "host_name", "name", "state", "created_at", "updated_at"}
	incoming := []interface{}{"id-remote", "vm1", "host-b", "snap1", "ready", "2020-01-01T00:00:00Z", "2000000000000-0000-n2"}
	if err := c.mergeStatePayloadLWW(snapshotSyncPayload(subset, incoming)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT id, vmstate_path FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "id-remote" {
		t.Fatalf("want single surviving id-remote, got %v", rows)
	}
	if got := rows[0].String("vmstate_path"); got != "/keep/me" {
		t.Errorf("receiver-only column erased on collapse: vmstate_path=%q, want /keep/me", got)
	}
}

// TestMergeIdentity_TieDifferentContentKeepsLocal (finding 3): an EXACT-instant tie with DIFFERENT
// content is a safety fault — keep local, remain divergent — never a silent id-based collapse.
func TestMergeIdentity_TieDifferentContentKeepsLocal(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	const tie = "2000000000000-0000-tie"
	seedSnapshot(t, c, "id-a", "vm1", "snap1", tie) // state defaults to "ready", host-a
	// Same instant, different id, DIFFERENT content (state).
	incoming := []interface{}{"id-b", "vm1", "host-a", "snap1", "error", nil, nil, "disk", nil, 0, "2020-01-01T00:00:00Z", tie, nil}
	if err := c.mergeStatePayloadLWW(snapshotSyncPayload(snapshotDumpCols, incoming)); err != nil {
		t.Fatalf("merge must not error on a content fault: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT id, state FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "id-a" || rows[0].String("state") != "ready" {
		t.Fatalf("different-content tie must keep local (id-a/ready), got %v", rows)
	}
}

// TestMergeIdentity_TieEqualContentCollapses (finding 3, contrast): an exact-instant tie whose
// content is equivalent except the id collapses deterministically to the smaller id.
func TestMergeIdentity_TieEqualContentCollapses(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	const tie = "2000000000000-0000-tie"
	seedSnapshot(t, c, "id-b", "vm1", "snap1", tie) // host-a, ready
	// Same instant, equivalent content, SMALLER id (id-a) ⇒ collapse to id-a.
	incoming := snapshotDumpRow("id-a", "vm1", "host-a", "snap1", tie)
	if err := c.mergeStatePayloadLWW(snapshotSyncPayload(snapshotDumpCols, incoming)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "id-a" {
		t.Fatalf("equal-content tie must collapse to the smaller id (id-a), got %v", rows)
	}
}

// TestMergeIdentity_IncomingIDBoundToOtherNaturalKeyFailsClosed (finding 4): if the incoming id
// already belongs to a DIFFERENT natural key locally, collapsing would destroy that unrelated row
// — fail closed, leaving both local rows intact.
func TestMergeIdentity_IncomingIDBoundToOtherNaturalKeyFailsClosed(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "id-X", "vm1", "snap1", "1000000000000-0000-n1")
	seedSnapshot(t, c, "id-Y", "vm2", "snap2", "1000000000000-0000-n1")
	// Incoming for (vm1,snap1) reuses id-Y (which belongs to vm2/snap2), newer.
	incoming := snapshotDumpRow("id-Y", "vm1", "host-b", "snap1", "2000000000000-0000-n2")
	if err := c.mergeStatePayloadLWW(snapshotSyncPayload(snapshotDumpCols, incoming)); err == nil {
		t.Fatal("an incoming id bound to a different natural key must fail closed")
	}
	x, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	y, _ := c.Query(ctx, "SELECT vm_name FROM snapshots WHERE id = ?", "id-Y")
	if len(x) != 1 || x[0].String("id") != "id-X" || len(y) != 1 || y[0].String("vm_name") != "vm2" {
		t.Fatalf("both rows must be intact after fail-closed: (vm1,snap1)=%v id-Y=%v", x, y)
	}
}

// TestMergeIdentity_CollapseOrphaningChildFailsClosed (finding 5): a collapse that would orphan an
// existing child referencing the losing id must fail closed (references are not rewritten).
func TestMergeIdentity_CollapseOrphaningChildFailsClosed(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "id-parent", "vm1", "snap1", "1000000000000-0000-n1")
	// A child snapshot references the parent's id via parent_id.
	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"id-child", "vm1", "host-a", "snap2", "ready", "id-parent", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed child: %v", err)
	}
	// Incoming winner for (vm1,snap1) with a new id would collapse the parent → orphan the child.
	incoming := snapshotDumpRow("id-newparent", "vm1", "host-b", "snap1", "2000000000000-0000-n2")
	if err := c.mergeStatePayloadLWW(snapshotSyncPayload(snapshotDumpCols, incoming)); err == nil {
		t.Fatal("a collapse orphaning an existing child must fail closed")
	}
	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "id-parent" {
		t.Fatalf("parent must keep its id after fail-closed, got %v", rows)
	}
}
