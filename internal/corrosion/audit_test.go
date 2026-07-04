package corrosion

import (
	"context"
	"testing"
	"time"
)

// HostManualFenceConfirmed trusts ONLY a recent result="manual-confirmed" row (operator
// attestation the host is down) — not an automatic result="fenced" attempt, and not one
// older than the window.
func TestHostManualFenceConfirmed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	const window = 5 * time.Minute

	// No fencing_log row → not confirmed.
	if ok, err := HostManualFenceConfirmed(ctx, c, "h1", time.Now(), window); err != nil || ok {
		t.Fatalf("no row: ok=%v err=%v; want false/nil", ok, err)
	}

	// An automatic 'fenced' attempt (may have partially failed) must NOT count.
	if err := InsertFenceLog(ctx, c, FenceLogRecord{ID: "f1", HostName: "h1", Method: "ipmi", Result: "fenced"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := HostManualFenceConfirmed(ctx, c, "h1", time.Now(), window); err != nil || ok {
		t.Fatalf("automatic 'fenced' must not confirm: ok=%v err=%v", ok, err)
	}

	// A fresh operator manual-confirm → confirmed within the window.
	if err := InsertFenceLog(ctx, c, FenceLogRecord{ID: "m1", HostName: "h2", Method: "manual", Result: "manual-confirmed"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := HostManualFenceConfirmed(ctx, c, "h2", time.Now(), window); err != nil || !ok {
		t.Fatalf("fresh manual-confirm must confirm: ok=%v err=%v", ok, err)
	}

	// Same row, but evaluated an hour later with a 5-min window → expired (fail-closed).
	if ok, err := HostManualFenceConfirmed(ctx, c, "h2", time.Now().Add(time.Hour), window); err != nil || ok {
		t.Fatalf("expired manual-confirm must NOT confirm: ok=%v err=%v", ok, err)
	}
}

func TestInsertAuditLog(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	rec := AuditRecord{
		ID:       "audit-001",
		Username: "admin",
		HostName: "node1",
		Action:   "create_vm",
		Target:   "vm-web",
		Detail:   "created VM with 2 vCPU, 1GB RAM",
		Result:   "success",
	}
	if err := InsertAuditLog(ctx, c, rec); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	// Verify by querying directly
	rows, err := c.Query(ctx, `SELECT id, username, host_name, action, target, detail, result, timestamp FROM audit_log WHERE id = ?`, "audit-001")
	if err != nil {
		t.Fatalf("Query audit_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.String("username") != "admin" {
		t.Errorf("username = %q, want admin", r.String("username"))
	}
	if r.String("host_name") != "node1" {
		t.Errorf("host_name = %q, want node1", r.String("host_name"))
	}
	if r.String("action") != "create_vm" {
		t.Errorf("action = %q, want create_vm", r.String("action"))
	}
	if r.String("target") != "vm-web" {
		t.Errorf("target = %q, want vm-web", r.String("target"))
	}
	if r.String("detail") != "created VM with 2 vCPU, 1GB RAM" {
		t.Errorf("detail = %q", r.String("detail"))
	}
	if r.String("result") != "success" {
		t.Errorf("result = %q, want success", r.String("result"))
	}
	if r.String("timestamp") == "" {
		t.Error("timestamp should be set automatically")
	}
}

func TestInsertAuditLog_Multiple(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, rec := range []AuditRecord{
		{ID: "a1", Username: "admin", Action: "create_vm", Target: "vm1", Result: "success"},
		{ID: "a2", Username: "admin", Action: "delete_vm", Target: "vm2", Result: "success"},
		{ID: "a3", Username: "viewer", Action: "list_vms", Target: "cluster", Result: "success"},
	} {
		if err := InsertAuditLog(ctx, c, rec); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", rec.ID, err)
		}
	}

	rows, err := c.Query(ctx, `SELECT id FROM audit_log`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("expected 3 audit entries, got %d", len(rows))
	}
}

func TestInsertFenceLog(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	rec := FenceLogRecord{
		ID:       "fence-001",
		HostName: "node2",
		Method:   "ipmi",
		Result:   "success",
		Detail:   "IPMI power cycle completed",
	}
	if err := InsertFenceLog(ctx, c, rec); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT id, host_name, method, result, detail, timestamp FROM fencing_log WHERE id = ?`, "fence-001")
	if err != nil {
		t.Fatalf("Query fencing_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 fence row, got %d", len(rows))
	}
	r := rows[0]
	if r.String("host_name") != "node2" {
		t.Errorf("host_name = %q, want node2", r.String("host_name"))
	}
	if r.String("method") != "ipmi" {
		t.Errorf("method = %q, want ipmi", r.String("method"))
	}
	if r.String("result") != "success" {
		t.Errorf("result = %q, want success", r.String("result"))
	}
	if r.String("detail") != "IPMI power cycle completed" {
		t.Errorf("detail = %q", r.String("detail"))
	}
	if r.String("timestamp") == "" {
		t.Error("timestamp should be set automatically")
	}
}

func TestInsertFenceLog_Multiple(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, rec := range []FenceLogRecord{
		{ID: "f1", HostName: "node1", Method: "ipmi", Result: "success", Detail: "power off"},
		{ID: "f2", HostName: "node1", Method: "watchdog", Result: "failed", Detail: "timeout"},
		{ID: "f3", HostName: "node2", Method: "ipmi", Result: "success", Detail: "reset"},
	} {
		if err := InsertFenceLog(ctx, c, rec); err != nil {
			t.Fatalf("InsertFenceLog %s: %v", rec.ID, err)
		}
	}

	rows, err := c.Query(ctx, `SELECT id FROM fencing_log`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("expected 3 fence entries, got %d", len(rows))
	}
}
