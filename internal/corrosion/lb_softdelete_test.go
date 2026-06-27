package corrosion

import (
	"context"
	"testing"
)

// TestLBBackend_SurvivesStaleMerge: a removed backend must not be resurrected by
// an anti-entropy merge of a stale peer that still has it live. Red while the
// delete is a hard DELETE (no tombstone → the merge re-inserts it).
func TestLBBackend_SurvivesStaleMerge(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if err := TombstoneLBBackend(ctx, c, "lb1", "b1"); err != nil {
		t.Fatalf("TombstoneLBBackend: %v", err)
	}

	// Stale peer dump still has b1 LIVE with an OLDER updated_at.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_backends",
		Columns: []string{"lb_name", "name", "address", "is_vm", "vm_name", "enabled", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"lb1", "b1", "10.0.0.1", 0, "", 1, "2020-01-01T00:00:00Z", nil}},
	}}})

	bs, err := ListLBBackends(ctx, c, "lb1")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(bs) != 0 {
		t.Errorf("deleted backend resurrected by stale peer merge: %+v", bs)
	}
}

// TestLBBackend_OldDumpMissingDeletedAt_KeepsTombstone covers the mixed-rollout
// window: an old peer (pre-v29) dumps lb_backends WITHOUT the deleted_at column.
// Its columns are a subset of the local schema so columnsKnown passes and the merge
// proceeds — protection here comes from LWW, not a table-skip: the newer local
// tombstone must beat the older live row, so the backend stays deleted. (If the old
// live row were NEWER it would legitimately re-add the backend; that's the OR-set
// recreate case, a documented limitation, not tested here.)
func TestLBBackend_OldDumpMissingDeletedAt_KeepsTombstone(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if err := TombstoneLBBackend(ctx, c, "lb1", "b1"); err != nil {
		t.Fatalf("TombstoneLBBackend: %v", err)
	}

	// OLD-shape dump: NO deleted_at column, carrying b1 LIVE with an OLDER updated_at.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_backends",
		Columns: []string{"lb_name", "name", "address", "is_vm", "vm_name", "enabled", "updated_at"},
		Rows:    [][]interface{}{{"lb1", "b1", "10.0.0.1", 0, "", 1, "2020-01-01T00:00:00Z"}},
	}}})

	bs, err := ListLBBackends(ctx, c, "lb1")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(bs) != 0 {
		t.Errorf("old-shape dump (missing deleted_at) resurrected a newer tombstone: %+v", bs)
	}
}

// TestLBConfig_SurvivesStaleMerge: same, for the LB config row. Red while
// production cleanup paths hard-delete lb_configs.
func TestLBConfig_SurvivesStaleMerge(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "roundrobin", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := SoftDeleteLBConfig(ctx, c, "lb1"); err != nil {
		t.Fatalf("SoftDeleteLBConfig: %v", err)
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_configs",
		Columns: []string{"name", "stack_name", "vip", "algorithm", "hosts", "ports", "enabled", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"lb1", "", "10.0.0.9", "roundrobin", "", "[]", 1, "2020-01-01T00:00:00Z", nil}},
	}}})

	cfgs, err := ListLBConfigs(ctx, c)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	for _, cfg := range cfgs {
		if cfg.Name == "lb1" {
			t.Errorf("deleted LB config resurrected by stale peer merge")
		}
	}
}

// TestLBBackend_RecreateHidesOldTombstone: after a backend is deleted then the LB
// is recreated with the same backend, the live row wins (tombstone cleared).
func TestLBBackend_RecreateHidesOldTombstone(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if err := TombstoneLBBackend(ctx, c, "lb1", "b1"); err != nil {
		t.Fatalf("TombstoneLBBackend: %v", err)
	}
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.2", Enabled: true}); err != nil {
		t.Fatalf("re-add UpsertLBBackend: %v", err)
	}
	bs, err := ListLBBackends(ctx, c, "lb1")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(bs) != 1 || bs[0].Address != "10.0.0.2" {
		t.Errorf("re-added backend should be live with new address, got %+v", bs)
	}
}
