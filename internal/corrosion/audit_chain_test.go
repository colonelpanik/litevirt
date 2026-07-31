package corrosion

import (
	"context"
	"testing"
)

func newAuditTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
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
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q", res.BrokenAt)
	}
	if res.RowsChecked != 3 {
		t.Errorf("checked %d rows, want 3", res.RowsChecked)
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

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "row-1" {
		t.Errorf("broken_at = %q, want row-1 (checked=%d)", res.BrokenAt, res.RowsChecked)
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
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("legacy + modern coexistence should be clean; broken at %q", res.BrokenAt)
	}
	if res.RowsChecked < 2 {
		t.Errorf("expected at least 2 rows checked, got %d", res.RowsChecked)
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

// globalChainedRow forges a row the way the pre-per-host model wrote them:
// linked to the tail of a DIFFERENT host's row (afterID), which is what made
// those chains unverifiable per-host. InsertAuditLog can no longer produce this
// shape, so a test that needs one has to write it directly.
func globalChainedRow(t *testing.T, c *Client, id, host, ts, afterID string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT content_hash FROM audit_log WHERE id = ?`, afterID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %v (rows=%d)", afterID, err, len(rows))
	}
	rec := AuditRecord{
		ID: id, Timestamp: ts, Username: "u", HostName: host,
		Action: "vm.start", Target: "x", Result: "ok",
		PrevHash: rows[0].String("content_hash"),
	}
	rec.ContentHash = HashAuditRow(rec)
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName,
		rec.Action, rec.Target, rec.Result, rec.PrevHash, rec.ContentHash); err != nil {
		t.Fatalf("seed global-chained row %s: %v", id, err)
	}
}

// TestAuditChain_MultiHost_InterleavedTimestamps_Clean is the core
// regression: two daemons (two processes) append concurrently, so their
// rows interleave by global timestamp (a1,b1,a2,b2). A single global
// chain would break at the first cross-host row; per-host sub-chains must
// verify clean. No reset is needed between the two hosts: the tails are keyed
// by host_name, so writing for hostB never disturbs hostA's position.
func TestAuditChain_MultiHost_InterleavedTimestamps_Clean(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Host A's daemon writes a1@:01, a2@:03.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:03Z")
	// Host B's daemon writes b1@:02, b2@:04 — interleaved.
	ins(t, c, "b1", "hostB", "2026-06-23T10:00:02Z")
	ins(t, c, "b2", "hostB", "2026-06-23T10:00:04Z")

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("interleaved multi-host chain should verify per-host; broke at %q", res.BrokenAt)
	}
	if res.RowsChecked != 4 {
		t.Errorf("checked %d rows, want 4", res.RowsChecked)
	}
}

// TestAuditChain_ResealFixesLegacyGlobalChain simulates the old global
// model (one process chains host B's row off host A's tail) and proves
// VerifyAuditChain flags it, then ResealAuditChain re-bases host B's
// sub-chain so the verify passes.
func TestAuditChain_ResealFixesLegacyGlobalChain(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Old bug: one shared tail across hosts, so b1 chains off a1's hash. That
	// is no longer reachable through InsertAuditLog, so forge it directly —
	// what matters is that such rows exist in the field and must still heal.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	globalChainedRow(t, c, "b1", "hostB", "2026-06-23T10:00:02Z", "a1")

	if res, _ := VerifyAuditChain(ctx, c); res.BrokenAt != "b1" {
		t.Fatalf("expected per-host verify to break at b1 (legacy global link), got %q", res.BrokenAt)
	}

	n, err := ResealAuditChain(ctx, c, "hostB")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 1 {
		t.Errorf("resealed %d rows, want 1 (b1 re-based to genesis)", n)
	}
	if res, _ := VerifyAuditChain(ctx, c); res.BrokenAt != "" {
		t.Errorf("after reseal the chain should be clean; broke at %q", res.BrokenAt)
	}
}

// TestAuditChain_EmptyHostRowIsResetPoint reproduces the live v1.0.15 failure:
// a background-context audit row with no host_name (e.g. failover.promote) sorts
// first under per-host verify and carries a global-model hash, so a naive
// per-host verify breaks at row 0. Such rows belong to no host's sub-chain and
// must be treated as reset points, not chain links.
func TestAuditChain_EmptyHostRowIsResetPoint(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// An orphan row with empty host_name and a non-NULL, arbitrary content_hash
	// (as the old global chain would have produced) — bypass InsertAuditLog.
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, result, prev_hash, content_hash)
		 VALUES ('orphan', '2026-06-08T14:10:41Z', 'failover-coordinator', '', 'failover.promote', 'vm1', 'ok', 'deadbeef', 'cafebabe')`); err != nil {
		t.Fatalf("seed orphan row: %v", err)
	}
	// A normal per-host chain alongside it.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:02Z")

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("empty-host orphan should be a reset point, not a break; broke at %q", res.BrokenAt)
	}
	if res.RowsChecked != 3 {
		t.Errorf("checked %d, want 3 (orphan + a1 + a2)", res.RowsChecked)
	}
}

// TestResealAuditChain_Idempotent: re-sealing an already-consistent
// per-host chain rewrites nothing.
func TestResealAuditChain_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
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
