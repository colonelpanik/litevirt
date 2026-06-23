package corrosion

import (
	"context"
	"testing"
)

func newAuditTestClient(t *testing.T) *Client {
	t.Helper()
	ResetChainStateForTests()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close(); ResetChainStateForTests() })
	return c
}

// TestAuditChain_IntactAcrossInserts confirms each new row chains
// off the prior one and VerifyAuditChain runs clean.
func TestAuditChain_IntactAcrossInserts(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	for i, action := range []string{"vm.create", "vm.start", "vm.stop"} {
		if err := InsertAuditLog(ctx, c, AuditRecord{
			ID:       "row-" + string(rune('a'+i)),
			Username: "alice",
			HostName: "node-0",
			Action:   action,
			Target:   "vm-1",
			Detail:   "test",
			Result:   "ok",
		}); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}
	checked, broken, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if broken != "" {
		t.Errorf("chain broken at %q", broken)
	}
	if checked != 3 {
		t.Errorf("checked %d rows, want 3", checked)
	}
}

// TestAuditChain_DetectsRowTampering proves the verifier catches a
// post-insert mutation. We bypass InsertAuditLog to forge the row.
func TestAuditChain_DetectsRowTampering(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	// Insert one legitimate row.
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "row-1", Username: "alice", HostName: "node-0",
		Action: "vm.start", Target: "vm-1", Detail: "", Result: "ok",
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Tamper: bypass the chain code and rewrite the row's detail
	// field directly. The content_hash stays at its now-stale value.
	if err := c.Execute(ctx,
		`UPDATE audit_log SET detail = 'tampered' WHERE id = 'row-1'`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	checked, broken, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if broken != "row-1" {
		t.Errorf("broken_at = %q, want row-1 (checked=%d)", broken, checked)
	}
}

// TestAuditChain_NullHashIsResetPoint lets pre-3.4 rows (NULL hashes)
// coexist with chained rows without failing the verify.
func TestAuditChain_NullHashIsResetPoint(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	// Bypass InsertAuditLog so the row lands with NULL hashes —
	// simulates an audit_log row that pre-dates the
	// migration.
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, action, target, result)
		 VALUES ('legacy', '2025-01-01T00:00:00Z', 'vm.start', 'vm-old', 'ok')`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "modern", Username: "alice", HostName: "node-0",
		Action: "vm.stop", Target: "vm-old", Result: "ok",
	}); err != nil {
		t.Fatalf("Insert modern: %v", err)
	}
	checked, broken, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if broken != "" {
		t.Errorf("legacy + modern coexistence should be clean; broken at %q", broken)
	}
	if checked < 2 {
		t.Errorf("expected at least 2 rows checked, got %d", checked)
	}
}

// ins is a test helper that appends one audit row for the named host,
// at an explicit timestamp, through the real chain code.
func ins(t *testing.T, c *Client, id, host, ts string) {
	t.Helper()
	if err := InsertAuditLog(context.Background(), c, AuditRecord{
		ID: id, Username: "u", HostName: host,
		Action: "vm.start", Target: "x", Result: "ok", Timestamp: ts,
	}); err != nil {
		t.Fatalf("InsertAuditLog %s: %v", id, err)
	}
}

// TestAuditChain_MultiHost_InterleavedTimestamps_Clean is the core
// regression: two daemons (two processes) append concurrently, so their
// rows interleave by global timestamp (a1,b1,a2,b2). A single global
// chain would break at the first cross-host row; per-host sub-chains must
// verify clean. ResetChainStateForTests() between the two stands in for
// the second daemon's separate process.
func TestAuditChain_MultiHost_InterleavedTimestamps_Clean(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Host A's daemon writes a1@:01, a2@:03.
	ResetChainStateForTests()
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:03Z")
	// Host B's daemon (separate process) writes b1@:02, b2@:04 — interleaved.
	ResetChainStateForTests()
	ins(t, c, "b1", "hostB", "2026-06-23T10:00:02Z")
	ins(t, c, "b2", "hostB", "2026-06-23T10:00:04Z")

	checked, broken, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if broken != "" {
		t.Errorf("interleaved multi-host chain should verify per-host; broke at %q", broken)
	}
	if checked != 4 {
		t.Errorf("checked %d rows, want 4", checked)
	}
}

// TestAuditChain_ResealFixesLegacyGlobalChain simulates the old global
// model (one process chains host B's row off host A's tail) and proves
// VerifyAuditChain flags it, then ResealAuditChain re-bases host B's
// sub-chain so the verify passes.
func TestAuditChain_ResealFixesLegacyGlobalChain(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Old bug: NO reset between hosts, so b1 chains off a1's hash.
	ResetChainStateForTests()
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "b1", "hostB", "2026-06-23T10:00:02Z") // global-chained off a1

	if _, broken, _ := VerifyAuditChain(ctx, c); broken != "b1" {
		t.Fatalf("expected per-host verify to break at b1 (legacy global link), got %q", broken)
	}

	n, err := ResealAuditChain(ctx, c, "hostB")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 1 {
		t.Errorf("resealed %d rows, want 1 (b1 re-based to genesis)", n)
	}
	if _, broken, _ := VerifyAuditChain(ctx, c); broken != "" {
		t.Errorf("after reseal the chain should be clean; broke at %q", broken)
	}
}

// TestResealAuditChain_Idempotent: re-sealing an already-consistent
// per-host chain rewrites nothing.
func TestResealAuditChain_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	ResetChainStateForTests()
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:02Z")
	ins(t, c, "a3", "hostA", "2026-06-23T10:00:03Z")

	n, err := ResealAuditChain(ctx, c, "hostA")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 0 {
		t.Errorf("reseal of an already-consistent chain rewrote %d rows, want 0", n)
	}
}
