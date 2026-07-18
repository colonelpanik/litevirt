package corrosion

import (
	"context"
	"database/sql"
	"testing"
)

// mustSkipLWW parses the statement's shape (as the apply path does) and calls shouldSkipLWW,
// failing the test on any parse/LWW error.
func mustSkipLWW(t *testing.T, r *Replicator, ctx context.Context, tx *sql.Tx, table string, pkCols []string, s Statement, ts string) bool {
	t.Helper()
	sh, err := parseStmtShape(s.SQL, pkCols)
	if err != nil {
		t.Fatalf("parse shape: %v", err)
	}
	skip, err := r.shouldSkipLWW(ctx, tx, table, pkCols, s, sh, ts)
	if err != nil {
		t.Fatalf("shouldSkipLWW: %v", err)
	}
	return skip
}

// The WAL (replicator) path resolves a full-image-INSERT tie through the SAME
// engine anti-entropy uses, so the two paths never disagree. Numeric params on
// the real path arrive JSON-decoded (float64), matching the json-normalized
// local fetch — these tests mirror that by passing float64.

func TestWAL_TieResolvesFullImageInsert(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2026-06-03T18:40:00Z"

	if err := InsertImage(ctx, c, ImageRecord{Name: "img", Format: "aaa", SizeBytes: 5000000000}); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}
	forceUpdatedAt(t, c, "images", "name", "img", ts)

	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	// Incoming full-image upsert at the SAME timestamp with a lexically-greater
	// format. size_bytes equal (and large) on both → content-max decides on format.
	s := Statement{
		SQL:    `INSERT OR REPLACE INTO images (name, format, size_bytes, updated_at) VALUES (?, ?, ?, ?)`,
		Params: []interface{}{"img", "zzz", float64(5000000000), ts},
	}
	if mustSkipLWW(t, r, ctx, tx, "images", []string{"name"}, s, ts) {
		t.Fatal("content-max must take the lexically-greater incoming row (zzz), not skip it")
	}
}

func TestWAL_TieRuntimeOwnedKeepsLocal(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2026-06-03T18:40:00Z"

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	forceUpdatedAt(t, c, "vms", "name", "vm1", ts)

	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	s := Statement{
		SQL:    `INSERT OR REPLACE INTO vms (name, host_name, state, spec, updated_at) VALUES (?, ?, ?, ?, ?)`,
		Params: []interface{}{"vm1", "host-b", "running", "{}", ts},
	}
	if !mustSkipLWW(t, r, ctx, tx, "vms", []string{"name"}, s, ts) {
		t.Fatal("a runtime-owned host_name tie must keep local (skip the incoming)")
	}
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("WAL tie must track unresolved, count=%d", c.UnresolvedTieCount())
	}
	if len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "vms/wal/runtime_owned" {
		t.Fatalf("expected vms/wal/runtime_owned, got %v", sm.tieUnresolved)
	}
}

// A tied partial UPDATE keeps local (deferred to AE), never resolving from a
// partial local⊕SET image.
func TestWAL_TiePartialUpdateKeepsLocal(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2026-06-03T18:40:00Z"

	if err := InsertImage(ctx, c, ImageRecord{Name: "img", Format: "aaa", SizeBytes: 1}); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}
	forceUpdatedAt(t, c, "images", "name", "img", ts)

	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	s := Statement{
		SQL:    `UPDATE images SET format = ?, updated_at = ? WHERE name = ?`,
		Params: []interface{}{"zzz", ts, "img"},
	}
	if !mustSkipLWW(t, r, ctx, tx, "images", []string{"name"}, s, ts) {
		t.Fatal("a tied partial UPDATE must keep local (defer convergence to anti-entropy)")
	}
}

// TestWAL_ZeroRowUpdateKeepsUnresolved: a strictly-newer WAL UPDATE that matches
// NO row (guarded) applies cleanly but changes nothing, so it must NOT clear the
// tracked unresolved tie.
func TestWAL_ZeroRowUpdateKeepsUnresolved(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	const oldTs = "2026-06-03T18:40:00Z"
	const newTs = "2026-06-30T00:00:00Z"

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	forceUpdatedAt(t, c, "vms", "name", "vm1", oldTs)
	cols := []string{"name", "host_name", "updated_at"}
	c.resolveTie("vms", cols, []interface{}{"vm1", "host-a", oldTs}, []interface{}{"vm1", "host-b", oldTs}, []int{0}, pathAE)
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("expected one tracked tie, got %d", c.UnresolvedTieCount())
	}

	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	// A registered vms UpdateObservedActuals CAS shape with a newer timestamp (so LWW would
	// apply) but a wrong vm_owner_epoch guard, so it matches 0 rows (CAS miss on a live vm1).
	s := Statement{
		SQL:    `UPDATE vms SET cpu_actual = ?, mem_actual = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = ?`,
		Params: []interface{}{4, 8, newTs, "vm1", 999},
	}
	if err := r.applyStatementLWW(ctx, tx, s, newTs); err != nil {
		t.Fatalf("applyStatementLWW: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("a WAL zero-row update must not clear the unresolved tracking, count=%d", c.UnresolvedTieCount())
	}
}
