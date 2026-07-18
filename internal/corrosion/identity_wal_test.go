package corrosion

import (
	"context"
	"testing"
)

// snapshotInsertSQL is the exact statement the CreateSnapshot builder emits (the shape the WAL
// apply path receives for a replicated snapshot creation).
const snapshotInsertSQL = `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// snapshotInsertStmt builds a replicated snapshots INSERT Statement with the given identity.
func snapshotInsertStmt(id, vmName, host, name, updatedAt string) Statement {
	return Statement{
		SQL:    snapshotInsertSQL,
		Params: []interface{}{id, vmName, host, name, "ready", nil, "disk", nil, float64(0), "2020-01-01T00:00:00Z", updatedAt},
	}
}

// applyWALSnapshot drives the WAL apply path (applyStatementLWW) for one snapshots INSERT.
func applyWALSnapshot(t *testing.T, c *Client, s Statement, incomingTS string) error {
	t.Helper()
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if aerr := r.applyStatementLWW(ctx, tx, s, incomingTS); aerr != nil {
		tx.Rollback()
		return aerr
	}
	if cerr := tx.Commit(); cerr != nil {
		t.Fatalf("commit: %v", cerr)
	}
	return nil
}

// TestWALIdentity_IncomingWinsCollapses: on the WAL path under canonical_identity_v1, a newer
// incoming snapshot INSERT with a DIFFERENT id but the same natural key collapses the local row
// (the two independently-minted ids converge to the winning id) instead of colliding on the
// secondary UNIQUE and back-pressuring.
func TestWALIdentity_IncomingWinsCollapses(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "1000000000000-0000-n1")

	if err := applyWALSnapshot(t, c, snapshotInsertStmt("incoming-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2"), "2000000000000-0000-n2"); err != nil {
		t.Fatalf("applyStatementLWW must resolve the collision, not back-pressure: %v", err)
	}

	rows, err := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0].String("id") != "incoming-id" {
		t.Fatalf("want exactly 1 snapshot id=incoming-id; got %d rows %v", len(rows), rows)
	}
	if gone, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE id = ?", "local-id"); len(gone) != 0 {
		t.Error("local-id must be collapsed away")
	}
}

// TestWALIdentity_LocalWinsKeepsLocal: an OLDER incoming WAL INSERT with a different id keeps
// local and does not introduce the incoming id.
func TestWALIdentity_LocalWinsKeepsLocal(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "2000000000000-0000-n1")

	if err := applyWALSnapshot(t, c, snapshotInsertStmt("incoming-id", "vm1", "host-b", "snap1", "1000000000000-0000-n2"), "1000000000000-0000-n2"); err != nil {
		t.Fatalf("applyStatementLWW: %v", err)
	}

	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "local-id" {
		t.Fatalf("local (newer) must be kept; got %d rows %v", len(rows), rows)
	}
}

// TestWALIdentity_DisabledBackPressures: with the capability OFF (default), the same collision
// hits the secondary UNIQUE via the id-keyed upsert and the fail-closed WAL back-pressures
// (returns an error) — the legacy behavior H1 is meant to relieve once latched.
func TestWALIdentity_DisabledBackPressures(t *testing.T) {
	c := mustTestClient(t) // canonicalIdentity hook unset ⇒ off
	ctx := context.Background()
	seedSnapshot(t, c, "local-id", "vm1", "snap1", "1000000000000-0000-n1")

	err := applyWALSnapshot(t, c, snapshotInsertStmt("incoming-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2"), "2000000000000-0000-n2")
	if err == nil {
		t.Fatal("capability off: a natural-key collision on a different id must back-pressure")
	}
	rows, _ := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "local-id" {
		t.Fatalf("capability off: local must be kept (no collapse); got %d rows %v", len(rows), rows)
	}
}

// TestWALIdentity_SameIdIsLWW: an incoming INSERT with the SAME id as local is a normal LWW
// upsert — newer wins, older is skipped — with no natural-key collapse in play.
func TestWALIdentity_SameIdIsLWW(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	ctx := context.Background()
	seedSnapshot(t, c, "same-id", "vm1", "snap1", "1000000000000-0000-n1")

	if err := applyWALSnapshot(t, c, snapshotInsertStmt("same-id", "vm1", "host-b", "snap1", "2000000000000-0000-n2"), "2000000000000-0000-n2"); err != nil {
		t.Fatalf("applyStatementLWW: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT id, host_name FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "same-id" || rows[0].String("host_name") != "host-b" {
		t.Fatalf("same-id newer incoming must update in place; got %v", rows)
	}
}

// TestWALIdentity_NonNullReferenceFailsClosed: a snapshots INSERT carrying a non-null parent_id
// (the provably-unused self-reference) fails closed under canonical_identity_v1 rather than risk
// orphaning on collapse. Exercised by calling the resolver directly with a parent_id-bearing
// shape (the production builder never emits one, so the ledger would also reject it).
func TestWALIdentity_NonNullReferenceFailsClosed(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	s := Statement{
		SQL:    `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		Params: []interface{}{"incoming-id", "vm1", "host-b", "snap1", "ready", "some-parent", "2020-01-01T00:00:00Z", "2000000000000-0000-n2"},
	}
	sh, err := parseStmtShape(s.SQL, tablePrimaryKeys["snapshots"])
	if err != nil {
		t.Fatalf("parse shape: %v", err)
	}
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if err := r.applyIdentityInsert(ctx, tx, s, sh, "snapshots", tablePrimaryKeys["snapshots"]); err == nil {
		t.Fatal("a non-null parent_id must fail closed under canonical_identity_v1")
	}
}

// TestWALIdentity_CollapsePreservesReceiverOnlyColumn (finding 2, WAL): a collapse driven by an
// older-schema statement that OMITS a column must preserve the local value of that receiver-only
// column. Exercised via applyIdentityInsert directly with a subset (schema-skewed) statement
// (a subset shape is not in the ledger, so the ledger would reject it before this point — this
// unit-tests the collapse's column preservation).
func TestWALIdentity_CollapsePreservesReceiverOnlyColumn(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return true })
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, vmstate_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"id-local", "vm1", "host-a", "snap1", "ready", "/keep/me", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Incoming (newer, different id) statement omits vmstate_path.
	s := Statement{
		SQL:    `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		Params: []interface{}{"id-remote", "vm1", "host-b", "snap1", "ready", "2020-01-01T00:00:00Z", "2000000000000-0000-n2"},
	}
	sh, err := parseStmtShape(s.SQL, tablePrimaryKeys["snapshots"])
	if err != nil {
		t.Fatalf("parse shape: %v", err)
	}
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.applyIdentityInsert(ctx, tx, s, sh, "snapshots", tablePrimaryKeys["snapshots"]); err != nil {
		tx.Rollback()
		t.Fatalf("applyIdentityInsert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT id, vmstate_path FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snap1")
	if len(rows) != 1 || rows[0].String("id") != "id-remote" {
		t.Fatalf("want single surviving id-remote, got %v", rows)
	}
	if got := rows[0].String("vmstate_path"); got != "/keep/me" {
		t.Errorf("receiver-only column erased on WAL collapse: vmstate_path=%q, want /keep/me", got)
	}
}
