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
