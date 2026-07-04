package corrosion

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ───────────────────────── coverage / invariants ─────────────────────────

// TestCapabilityMap_Bijection: the capability map covers EXACTLY the AE-repaired
// tables (tableNames ∪ sensitiveTableNames) — no missing entry (which would fail
// closed to "uncategorized" + alert) and no straggler (a table no longer
// repaired). This is invariant 5: every replicated table assigned exactly one
// category, no implicit default bucket.
func TestCapabilityMap_Bijection(t *testing.T) {
	repaired := make(map[string]bool)
	for _, n := range tableNames {
		repaired[n] = true
	}
	for _, n := range sensitiveTableNames {
		repaired[n] = true
	}
	for n := range repaired {
		if customMergeTables[n] {
			continue // bespoke MONOTONE merge (customMergeTables) — bypasses the LWW resolver
		}
		if _, ok := capabilityMap[n]; !ok {
			t.Errorf("repaired table %q has no capabilityMap entry — assign it a resolver category", n)
		}
	}
	for n := range capabilityMap {
		if !repaired[n] {
			t.Errorf("capabilityMap has %q, which is not in tableNames/sensitiveTableNames — remove it or add it to a lane", n)
		}
		if customMergeTables[n] {
			t.Errorf("capabilityMap has %q, which uses the bespoke customMergeTables merge — it must NOT go through the LWW resolver", n)
		}
	}
}

// TestCapabilityMap_PartitionsSchema: every CREATE-TABLE in the schema is in
// EXACTLY ONE of {capabilityMap (LWW resolver), customMergeTables (bespoke
// monotone merge), antiEntropyExcluded}. A new table can neither silently get a
// resolver nor silently be excluded — it must be explicitly placed.
func TestCapabilityMap_PartitionsSchema(t *testing.T) {
	for _, tbl := range schemaDDLTables() {
		_, resolved := capabilityMap[tbl]
		_, excluded := antiEntropyExcluded[tbl]
		custom := customMergeTables[tbl]
		n := 0
		for _, in := range []bool{resolved, custom, excluded} {
			if in {
				n++
			}
		}
		switch {
		case n > 1:
			t.Errorf("table %q is in more than one of {capabilityMap, customMergeTables, antiEntropyExcluded} — pick one", tbl)
		case n == 0:
			t.Errorf("table %q is in none of {capabilityMap, customMergeTables, antiEntropyExcluded} — assign a category or exclude with a reason", tbl)
		}
	}
}

// TestResolver_EveryChainTerminates: a chain must always reach a terminal rule
// (content_max or unresolved). Probe with a row pair that differs only in a
// column none of the semantic rules special-case, so every non-terminal rule
// passes and ONLY a terminal can decide. If neither a tie-break nor an
// unresolved-track is recorded, the chain fell through (a bug).
func TestResolver_EveryChainTerminates(t *testing.T) {
	cols := []string{"____probe", "updated_at"}
	pkIdx := []int{0}
	for table := range capabilityMap {
		c := testClient(t)
		sm := &fakeSyncMetrics{}
		c.SetSyncMetrics(sm)
		local := []interface{}{"A", "T"}
		incoming := []interface{}{"B", "T"}
		c.resolveTie(table, cols, local, incoming, pkIdx, pathAE)
		decided := len(sm.tieBreaks) == 1 || (len(sm.tieUnresolved) == 1 && c.UnresolvedTieCount() == 1)
		if !decided {
			t.Errorf("table %q chain did not terminate (breaks=%v unresolved=%v) — last rule must be content_max or unresolved",
				table, sm.tieBreaks, sm.tieUnresolved)
		}
	}
}

// ───────────────────────── lwwOrder ─────────────────────────

func TestLWWOrder(t *testing.T) {
	older := "2026-06-03T18:40:00Z"
	newer := "2026-06-03T18:40:01Z"
	if lwwOrder(newer, older) != 1 {
		t.Error("local strictly newer should be +1")
	}
	if lwwOrder(older, newer) != -1 {
		t.Error("incoming strictly newer should be -1")
	}
	if lwwOrder(older, older) != 0 {
		t.Error("exact equal should be 0 (the tie that reaches the resolver)")
	}
	// Sub-second fixed-width vs the same instant compares as instants, not lexically.
	if lwwOrder("2026-06-03T18:40:00.000000000Z", "2026-06-03T18:40:00Z") != 0 {
		t.Error("fixed-width fractional and bare-second of the same instant must tie")
	}
}

// ───────────────────────── per-category behavior ─────────────────────────

func resolve(t *testing.T, table string, cols []string, local, incoming []interface{}) (*Client, *fakeSyncMetrics, bool, bool) {
	t.Helper()
	c := testClient(t)
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	keepLocal, unresolved := c.resolveTie(table, cols, local, incoming, []int{0}, pathAE)
	return c, sm, keepLocal, unresolved
}

func TestResolver_RuntimeOwnedHostName(t *testing.T) {
	cols := []string{"name", "host_name", "updated_at"}
	c, sm, keepLocal, unresolved := resolve(t, "vms", cols,
		[]interface{}{"db1", "node-2", "T"},
		[]interface{}{"db1", "node-3", "T"})
	if !keepLocal || !unresolved {
		t.Fatalf("vms host_name split must be unresolved+keep-local, got keepLocal=%v unresolved=%v", keepLocal, unresolved)
	}
	if c.UnresolvedTieCount() != 1 || len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "vms/ae/runtime_owned" {
		t.Fatalf("expected one runtime_owned unresolved track, got %v", sm.tieUnresolved)
	}
}

func TestResolver_TenancyUnresolved(t *testing.T) {
	cols := []string{"name", "project", "vip", "updated_at"}
	_, sm, keepLocal, unresolved := resolve(t, "networks", cols,
		[]interface{}{"n1", "acme", "10.0.0.1", "T"},
		[]interface{}{"n1", "other", "10.0.0.1", "T"})
	if !keepLocal || !unresolved || len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "networks/ae/tenancy" {
		t.Fatalf("differing tenancy must be unresolved, got keepLocal=%v unresolved=%v track=%v", keepLocal, unresolved, sm.tieUnresolved)
	}
	// Same project, differing other column → converges by content-max.
	_, sm2, _, unresolved2 := resolve(t, "networks", cols,
		[]interface{}{"n1", "acme", "10.0.0.9", "T"},
		[]interface{}{"n1", "acme", "10.0.0.1", "T"})
	if unresolved2 || len(sm2.tieBreaks) != 1 {
		t.Fatalf("same-tenancy content tie must converge, got unresolved=%v breaks=%v", unresolved2, sm2.tieBreaks)
	}
}

func TestResolver_TombstoneWins(t *testing.T) {
	cols := []string{"name", "value", "updated_at", "deleted_at"}
	// Incoming deleted, local live → take incoming (the tombstone). A tombstone tie
	// is recorded in its own benign counter, NOT the tie-break series.
	_, sm, keepLocal, unresolved := resolve(t, "dns_records", cols,
		[]interface{}{"a", "1.1.1.1", "T", nil},
		[]interface{}{"a", "1.1.1.1", "T", "2026-06-03T00:00:00Z"})
	if keepLocal || unresolved {
		t.Fatalf("one-sided tombstone must win (take incoming), got keepLocal=%v unresolved=%v", keepLocal, unresolved)
	}
	if len(sm.tieBreaks) != 0 {
		t.Fatalf("a tombstone tie must not hit the tie-break series, got %v", sm.tieBreaks)
	}
	if len(sm.tombstoneTies) != 1 || sm.tombstoneTies[0] != "dns_records" {
		t.Fatalf("a tombstone tie must be counted in the tombstone series, got %v", sm.tombstoneTies)
	}
}

func TestResolver_ContentMaxSymmetric(t *testing.T) {
	cols := []string{"name", "value", "updated_at"}
	// content-max is a total order: both orderings pick the same row ("Z" > "A").
	_, _, keepA, _ := resolve(t, "images", cols,
		[]interface{}{"i", "Z", "T"}, []interface{}{"i", "A", "T"})
	_, _, keepB, _ := resolve(t, "images", cols,
		[]interface{}{"i", "A", "T"}, []interface{}{"i", "Z", "T"})
	if !keepA {
		t.Error("local 'Z' should win over incoming 'A'")
	}
	if keepB {
		t.Error("local 'A' should lose to incoming 'Z' — both nodes must pick 'Z' (convergence)")
	}
}

func TestResolver_PolicyUnresolved(t *testing.T) {
	cols := []string{"id", "verb", "path", "updated_at"}
	_, sm, keepLocal, unresolved := resolve(t, "role_bindings", cols,
		[]interface{}{"b1", "vm.delete", "/projects/a", "T"},
		[]interface{}{"b1", "vm.*", "/", "T"})
	if !keepLocal || !unresolved || len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "role_bindings/ae/policy" {
		t.Fatalf("policy tie must be unresolved (no content-max to the broader grant), got keepLocal=%v track=%v", keepLocal, sm.tieUnresolved)
	}
}

func TestResolver_NumericRatchet(t *testing.T) {
	cols := []string{"username", "method", "last_step", "updated_at"}
	// Higher last_step wins (the TOTP replay ratchet must never decrease).
	_, sm, keepLocal, unresolved := resolve(t, "user_2fa", cols,
		[]interface{}{"u", "totp", "5", "T"},
		[]interface{}{"u", "totp", "9", "T"})
	if keepLocal || unresolved || sm.tieBreaks[0] != "user_2fa/numeric_max/incoming" {
		t.Fatalf("higher last_step must win, got keepLocal=%v breaks=%v", keepLocal, sm.tieBreaks)
	}
	// Equal last_step, differing secret → unresolved (auth_factor).
	cols2 := []string{"username", "method", "secret", "last_step", "updated_at"}
	_, sm2, keep2, unres2 := resolve(t, "user_2fa", cols2,
		[]interface{}{"u", "totp", "AAA", "5", "T"},
		[]interface{}{"u", "totp", "BBB", "5", "T"})
	if !keep2 || !unres2 || sm2.tieUnresolved[0] != "user_2fa/ae/auth_factor" {
		t.Fatalf("differing 2FA secret at a tie must be unresolved, got %v", sm2.tieUnresolved)
	}
}

func TestResolver_RecoveryUsedWins(t *testing.T) {
	cols := []string{"username", "code_hash", "used_at", "updated_at"}
	_, sm, keepLocal, unresolved := resolve(t, "recovery_codes", cols,
		[]interface{}{"u", "h", "2026-06-03T00:00:00Z", "T"},
		[]interface{}{"u", "h", nil, "T"})
	if !keepLocal || unresolved || sm.tieBreaks[0] != "recovery_codes/non_null_wins/local" {
		t.Fatalf("a consumed (used_at set) code must win over unused, got keepLocal=%v breaks=%v", keepLocal, sm.tieBreaks)
	}
}

func TestResolver_LBGeneration(t *testing.T) {
	cols := []string{"name", "vip", "generation", "updated_at"}
	// One empty, one non-empty → non-empty wins.
	_, sm, keepLocal, _ := resolve(t, "lb_configs", cols,
		[]interface{}{"lb", "10.0.0.1", "gen-abc", "T"},
		[]interface{}{"lb", "10.0.0.1", "", "T"})
	if !keepLocal || sm.tieBreaks[0] != "lb_configs/lb_generation/local" {
		t.Fatalf("non-empty generation must beat empty, got keepLocal=%v breaks=%v", keepLocal, sm.tieBreaks)
	}
	// Two different non-empty → unresolved.
	_, sm2, keep2, unres2 := resolve(t, "lb_configs", cols,
		[]interface{}{"lb", "10.0.0.1", "gen-abc", "T"},
		[]interface{}{"lb", "10.0.0.1", "gen-xyz", "T"})
	if !keep2 || !unres2 || sm2.tieUnresolved[0] != "lb_configs/ae/lb_token" {
		t.Fatalf("two different incarnation tokens must be unresolved, got %v", sm2.tieUnresolved)
	}
}

func TestResolver_AuthPointerUnresolved(t *testing.T) {
	cols := []string{"username", "active_epoch", "updated_at"}
	_, sm, keepLocal, unresolved := resolve(t, "user_2fa_sets", cols,
		[]interface{}{"u", "epoch-1", "T"},
		[]interface{}{"u", "epoch-2", "T"})
	if !keepLocal || !unresolved || sm.tieUnresolved[0] != "user_2fa_sets/ae/auth_pointer" {
		t.Fatalf("two different active-set pointers must be unresolved, got %v", sm.tieUnresolved)
	}
}

// ───────────────────────── bounded tracker ─────────────────────────

func TestUnresolvedTracker_DistinctOnce(t *testing.T) {
	c := testClient(t)
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	cols := []string{"name", "host_name", "updated_at"}
	a := []interface{}{"db1", "node-2", "T"}
	b := []interface{}{"db1", "node-3", "T"}

	// Same divergence observed repeatedly → counted once.
	for i := 0; i < 5; i++ {
		c.resolveTie("vms", cols, a, b, []int{0}, pathAE)
	}
	if c.UnresolvedTieCount() != 1 || len(sm.tieUnresolved) != 1 {
		t.Fatalf("re-observing the same divergence must count once, got count=%d metric=%d", c.UnresolvedTieCount(), len(sm.tieUnresolved))
	}
	if sm.unresolvedCurrent != 1 {
		t.Fatalf("current-unresolved gauge = %d, want 1", sm.unresolvedCurrent)
	}

	// The content changes (a real new write) → re-evaluated, counted again (the
	// monotonic counter), but it's the SAME row so the current gauge stays 1.
	b2 := []interface{}{"db1", "node-4", "T"}
	c.resolveTie("vms", cols, a, b2, []int{0}, pathAE)
	if len(sm.tieUnresolved) != 2 {
		t.Fatalf("a changed divergence must re-count, got metric=%d", len(sm.tieUnresolved))
	}
	if sm.unresolvedCurrent != 1 {
		t.Fatalf("a same-row content change must not bump the current gauge, got %d", sm.unresolvedCurrent)
	}

	// Convergence clears the entry → the gauge drops to 0 (the counter stays at 2).
	c.clearUnresolved("vms", pkKeyAt(b2, []int{0}))
	if c.UnresolvedTieCount() != 0 {
		t.Fatalf("clearUnresolved must drop the entry, count=%d", c.UnresolvedTieCount())
	}
	if sm.unresolvedCurrent != 0 {
		t.Fatalf("current-unresolved gauge must drop to 0 after repair, got %d", sm.unresolvedCurrent)
	}
}

// TestUnresolvedGauge_ConcurrentTrackClear: under concurrent track/clear the
// exported current-unresolved gauge must always settle on the true map length —
// never a stale (backwards) value from callback reordering. Run with -race.
func TestUnresolvedGauge_ConcurrentTrackClear(t *testing.T) {
	c := testClient(t)
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	const n = 50

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.trackUnresolved("vms", fmt.Sprintf("vm%d", i),
				[]interface{}{"a"}, []interface{}{"b"}, pathAE, "runtime_owned")
		}(i)
	}
	wg.Wait()
	if c.UnresolvedTieCount() != n || sm.unresolvedCurrent != n {
		t.Fatalf("after %d concurrent tracks: count=%d gauge=%d, want %d", n, c.UnresolvedTieCount(), sm.unresolvedCurrent, n)
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.clearUnresolved("vms", fmt.Sprintf("vm%d", i))
		}(i)
	}
	wg.Wait()
	if c.UnresolvedTieCount() != 0 || sm.unresolvedCurrent != 0 {
		t.Fatalf("after clearing all: count=%d gauge=%d, want 0 (gauge must not be left stale)", c.UnresolvedTieCount(), sm.unresolvedCurrent)
	}
}

// TestLocalWriteClearsUnresolved: a local write to a tracked PK (the on-node
// remediation path, e.g. repair-owner's UpdateVMHost) clears the stale tracking.
func TestLocalWriteClearsUnresolved(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Track an unresolved tie for vm1 via the real resolver path (pkKey-formatted key).
	cols := []string{"name", "host_name", "updated_at"}
	c.resolveTie("vms", cols, []interface{}{"vm1", "host-a", "T"}, []interface{}{"vm1", "host-b", "T"}, []int{0}, pathAE)
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("expected one tracked tie, got %d", c.UnresolvedTieCount())
	}
	// A local write to the same PK clears it.
	if err := UpdateVMHost(ctx, c, "vm1", "host-a", "running"); err != nil {
		t.Fatalf("UpdateVMHost: %v", err)
	}
	if c.UnresolvedTieCount() != 0 {
		t.Fatalf("a local write to the PK must clear the unresolved tracking, count=%d", c.UnresolvedTieCount())
	}
}

// TestLocalZeroRowWriteKeepsUnresolved: a guarded local write that matches NO row
// (e.g. WHERE … deleted_at IS NOT NULL on a live row) changed no content, so it
// must NOT clear the tracked tie.
func TestLocalZeroRowWriteKeepsUnresolved(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	cols := []string{"name", "host_name", "updated_at"}
	c.resolveTie("vms", cols, []interface{}{"vm1", "host-a", "T"}, []interface{}{"vm1", "host-b", "T"}, []int{0}, pathAE)
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("expected one tracked tie, got %d", c.UnresolvedTieCount())
	}
	// vm1 is live (deleted_at NULL), so this matches 0 rows.
	if err := c.ExecuteBatch(ctx, []Statement{{
		SQL: `UPDATE vms SET state = 'x' WHERE name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{"vm1"},
	}}); err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if c.UnresolvedTieCount() != 1 {
		t.Fatalf("a zero-row write must not clear the unresolved tracking, count=%d", c.UnresolvedTieCount())
	}
}

// TestResolver_OpaqueDefinitionUnresolved: a differing opaque definition blob
// (vms.spec, networks.config, …) is NEVER content-max'd — it is unresolved, so an
// arbitrary length-prefix tiebreak can't silently downgrade a live definition to
// a stale serialization (the prod regression that motivated this).
func TestResolver_OpaqueDefinitionUnresolved(t *testing.T) {
	vmCols := []string{"name", "host_name", "project", "spec", "updated_at"}

	// A differing spec at a tie → unresolved, category "opaque".
	_, sm, keepLocal, unresolved := resolve(t, "vms", vmCols,
		[]interface{}{"db1", "node-2", "_default", `{"cpu":4,"x":1}`, "T"},
		[]interface{}{"db1", "node-2", "_default", `{"cpu":4,"x":2}`, "T"})
	if !keepLocal || !unresolved || len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "vms/ae/opaque" {
		t.Fatalf("a differing vms.spec must be unresolved (opaque), got keepLocal=%v unresolved=%v track=%v", keepLocal, unresolved, sm.tieUnresolved)
	}

	// The exact prod shape: a SHORTER stale spec must NOT win over a longer live
	// one (content-max would pick it by length prefix) — it must be unresolved.
	_, _, keep2, unres2 := resolve(t, "vms", vmCols,
		[]interface{}{"db1", "node-2", "_default", strings.Repeat("x", 1149), "T"}, // live, longer
		[]interface{}{"db1", "node-2", "_default", strings.Repeat("y", 963), "T"})  // stale, shorter
	if !keep2 || !unres2 {
		t.Fatalf("live-vs-stale spec tie must be unresolved (no silent downgrade), got keepLocal=%v unresolved=%v", keep2, unres2)
	}

	// networks.config behaves the same.
	nCols := []string{"name", "project", "config", "updated_at"}
	_, sm3, _, unres3 := resolve(t, "networks", nCols,
		[]interface{}{"n1", "_default", `{"bridge":"br0"}`, "T"},
		[]interface{}{"n1", "_default", `{"bridge":"br1"}`, "T"})
	if !unres3 || sm3.tieUnresolved[0] != "networks/ae/opaque" {
		t.Fatalf("a differing networks.config must be unresolved, got %v", sm3.tieUnresolved)
	}

	// A NON-opaque difference (same spec, a benign scalar differs) still converges.
	benignCols := []string{"name", "host_name", "project", "spec", "state", "updated_at"}
	_, sm4, _, unres4 := resolve(t, "vms", benignCols,
		[]interface{}{"db1", "node-2", "_default", `{"cpu":4}`, "running", "T"},
		[]interface{}{"db1", "node-2", "_default", `{"cpu":4}`, "paused", "T"})
	if unres4 || len(sm4.tieBreaks) != 1 || sm4.tieBreaks[0] != "vms/content_max/local" {
		t.Fatalf("an equal-spec tie differing only in a benign column must still converge, got unresolved=%v breaks=%v", unres4, sm4.tieBreaks)
	}
}

func TestResolver_HostsControlPlaneUnresolved(t *testing.T) {
	cols := []string{"name", "state", "fence_strategy", "cpu_total", "updated_at"}
	// A control-plane column (fence_strategy) differs → unresolved (no coin-flip).
	_, sm, keepLocal, unresolved := resolve(t, "hosts", cols,
		[]interface{}{"h1", "active", "reboot", "16", "T"},
		[]interface{}{"h1", "active", "poweroff", "16", "T"})
	if !keepLocal || !unresolved || len(sm.tieUnresolved) != 1 || sm.tieUnresolved[0] != "hosts/ae/control_plane" {
		t.Fatalf("a control-plane host tie must be unresolved, got keepLocal=%v unresolved=%v track=%v", keepLocal, unresolved, sm.tieUnresolved)
	}
	// Only a benign telemetry column (cpu_total) differs → content-max converges.
	_, sm2, _, unres2 := resolve(t, "hosts", cols,
		[]interface{}{"h1", "active", "reboot", "16", "T"},
		[]interface{}{"h1", "active", "reboot", "32", "T"})
	if unres2 || len(sm2.tieBreaks) != 1 {
		t.Fatalf("a benign-only host tie should converge by content-max, got unresolved=%v breaks=%v", unres2, sm2.tieBreaks)
	}
}
