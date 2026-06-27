package corrosion

import (
	"context"
	"testing"
)

// lbBackendHas reports whether ListLBBackends renders a backend with the given
// name for the LB.
func lbBackendHas(t *testing.T, c *Client, lbName, backendName string) bool {
	t.Helper()
	bs, err := ListLBBackends(context.Background(), c, lbName)
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	for _, b := range bs {
		if b.Name == backendName {
			return true
		}
	}
	return false
}

// TestLB_StaleGenerationDoesNotRenderAfterRecreate is the LB OR-set regression
// (Fix 1). After the LB is recreated at a fresh generation, a backend a
// partitioned peer still holds from the OLD incarnation — LIVE, with a NEWER
// updated_at so LWW keeps it as a live row — merges into the DB but must NOT
// render, because its generation no longer matches the config's. RED before the
// generation filter (the live newer row would render and re-attach traffic to a
// removed backend).
func TestLB_StaleGenerationDoesNotRenderAfterRecreate(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// The LB's current incarnation is generation g2.
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "rr", Enabled: true, Generation: "g2"}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// A partitioned peer pushes a backend from the OLD incarnation (generation
	// g1), LIVE, with a future updated_at so it wins LWW as a live row.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_backends",
		Columns: []string{"lb_name", "name", "address", "is_vm", "vm_name", "enabled", "updated_at", "deleted_at", "generation"},
		Rows:    [][]interface{}{{"lb1", "ghost", "10.9.9.9", 0, "", 1, "2099-01-01T00:00:00Z", nil, "g1"}},
	}}})

	if lbBackendHas(t, c, "lb1", "ghost") {
		t.Error("stale-generation backend rendered after recreate — traffic could be re-routed to a removed backend")
	}
}

// TestLB_ConcurrentRecreateOnlyWinnerRenders: two partitioned recreates pick
// different generations; LWW arbitrates the config row, and only the winning
// generation's backends render (the loser's merge in but stay hidden).
func TestLB_ConcurrentRecreateOnlyWinnerRenders(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// Local recreate: config gA + backend "a".
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "rr", Enabled: true, Generation: "gA"}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "a", Address: "10.0.0.1", Enabled: true, Generation: "gA"}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	// Peer's concurrent recreate WINS LWW on the config (future updated_at):
	// generation gB, with its own backend "b". Backend "a" also gets a (losing,
	// older) update leaving it on gA.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_configs",
		Columns: []string{"name", "stack_name", "vip", "algorithm", "hosts", "ports", "enabled", "updated_at", "deleted_at", "generation"},
		Rows:    [][]interface{}{{"lb1", "", "10.0.0.9", "rr", "", "[]", 1, "2099-01-01T00:00:00Z", nil, "gB"}},
	}}})
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_backends",
		Columns: []string{"lb_name", "name", "address", "is_vm", "vm_name", "enabled", "updated_at", "deleted_at", "generation"},
		Rows:    [][]interface{}{{"lb1", "b", "10.0.0.2", 0, "", 1, "2099-01-01T00:00:00Z", nil, "gB"}},
	}}})

	if !lbBackendHas(t, c, "lb1", "b") {
		t.Error("winning-generation backend should render")
	}
	if lbBackendHas(t, c, "lb1", "a") {
		t.Error("losing-generation backend should not render after the config converges to gB")
	}
}

// TestLB_UpdatePreservesGeneration: editing the config (VIP/algorithm) must not
// orphan its backends. The update passes generation=” and the COALESCE guard
// preserves the live token, so the existing backend keeps matching and rendering.
func TestLB_UpdatePreservesGeneration(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "rr", Enabled: true, Generation: "g1"}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true, Generation: "g1"}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	// Edit the algorithm; deliberately pass an empty generation (a careless/older
	// call site). The COALESCE(NULLIF(...)) guard must keep g1.
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "leastconn", Enabled: true, Generation: ""}); err != nil {
		t.Fatalf("UpsertLBConfig edit: %v", err)
	}

	cfgs, err := ListLBConfigs(ctx, c)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	var gen, algo string
	for _, cfg := range cfgs {
		if cfg.Name == "lb1" {
			gen, algo = cfg.Generation, cfg.Algorithm
		}
	}
	if gen != "g1" {
		t.Errorf("update blanked the generation: got %q, want g1", gen)
	}
	if algo != "leastconn" {
		t.Errorf("update did not take effect: algorithm=%q", algo)
	}
	if !lbBackendHas(t, c, "lb1", "b1") {
		t.Error("backend orphaned by a config edit — generation was not preserved")
	}
}

// TestLB_LegacyEmptyGenerationRenders: a pre-v31 LB whose config and backends
// both default to generation=” still renders (” = ” matches the join).
func TestLB_LegacyEmptyGenerationRenders(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// No Generation set on either → both '' (the migration default).
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "rr", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if !lbBackendHas(t, c, "lb1", "b1") {
		t.Error("legacy ''-generation backend should still render")
	}
}

// TestLB_NoConfigDoesNotRender: a backend whose config is absent or tombstoned
// does not render (the join gates on a live config).
func TestLB_NoConfigDoesNotRender(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// (a) No config at all.
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true, Generation: "g1"}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if lbBackendHas(t, c, "lb1", "b1") {
		t.Error("backend with no config rendered")
	}

	// (b) Config then tombstoned.
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb2", VIP: "10.0.0.8", Algorithm: "rr", Enabled: true, Generation: "g2"}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb2", Name: "b2", Address: "10.0.0.2", Enabled: true, Generation: "g2"}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	if !lbBackendHas(t, c, "lb2", "b2") {
		t.Fatal("precondition: backend should render before the config is tombstoned")
	}
	if err := SoftDeleteLBConfig(ctx, c, "lb2"); err != nil {
		t.Fatalf("SoftDeleteLBConfig: %v", err)
	}
	if lbBackendHas(t, c, "lb2", "b2") {
		t.Error("backend rendered after its config was tombstoned")
	}
}

// TestLB_OldDumpMissingGenerationColumn covers the mixed-rollout window: an
// old (pre-v31) peer dumps lb_backends WITHOUT the generation column, carrying a
// LIVE backend with a future updated_at. Its columns are a subset of the local
// schema so the merge proceeds; the new row lands with generation=” (the
// default). Against the current non-empty config generation it does NOT render —
// the security property holds regardless of LWW on updated_at.
func TestLB_OldDumpMissingGenerationColumn(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "lb1", VIP: "10.0.0.9", Algorithm: "rr", Enabled: true, Generation: "g2"}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// OLD-shape dump: NO generation column, a LIVE backend with a future updated_at.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "lb_backends",
		Columns: []string{"lb_name", "name", "address", "is_vm", "vm_name", "enabled", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"lb1", "old-ghost", "10.9.9.9", 0, "", 1, "2099-01-01T00:00:00Z", nil}},
	}}})

	if lbBackendHas(t, c, "lb1", "old-ghost") {
		t.Error("old-shape ('' generation) backend rendered under the current non-empty generation")
	}
}
