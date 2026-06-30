package corrosion

import (
	"context"
	"testing"
)

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
	if r.shouldSkipLWW(ctx, tx, "images", []string{"name"}, s, ts) {
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
	if !r.shouldSkipLWW(ctx, tx, "vms", []string{"name"}, s, ts) {
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
	if !r.shouldSkipLWW(ctx, tx, "images", []string{"name"}, s, ts) {
		t.Fatal("a tied partial UPDATE must keep local (defer convergence to anti-entropy)")
	}
}
