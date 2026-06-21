package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestPublish_DoesNotPanic(t *testing.T) {
	s := testServer(t)
	// Verify publish works with no webhook URL.
	s.publish("test.event", "target", "detail")
}

func TestAudit_DoesNotPanic(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	// Verify audit works.
	s.audit(ctx, "test.action", "target", "detail", "ok")
}

func TestSetWebhookURL(t *testing.T) {
	s := testServer(t)
	s.SetWebhookURL("https://example.com/webhook")
	if s.webhookURL != "https://example.com/webhook" {
		t.Errorf("webhookURL = %q", s.webhookURL)
	}
}

func TestAudit_InsertsRecord(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.audit(ctx, "vm.created", "my-vm", "cpu=2 mem=1024", "ok")

	rows, err := s.db.Query(ctx,
		`SELECT username, host_name, action, target, detail, result FROM audit_log WHERE target = ?`, "my-vm")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.String("username") != "admin" {
		t.Errorf("username = %q, want admin", r.String("username"))
	}
	if r.String("host_name") != "test-host" {
		t.Errorf("host_name = %q, want test-host", r.String("host_name"))
	}
	if r.String("action") != "vm.created" {
		t.Errorf("action = %q", r.String("action"))
	}
	if r.String("detail") != "cpu=2 mem=1024" {
		t.Errorf("detail = %q", r.String("detail"))
	}
	if r.String("result") != "ok" {
		t.Errorf("result = %q", r.String("result"))
	}
}

func TestListAuditLog(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert 3 audit records.
	for _, rec := range []corrosion.AuditRecord{
		{ID: "a1", Username: "admin", HostName: "host-a", Action: "vm.created", Target: "vm-1", Detail: "ok", Result: "success"},
		{ID: "a2", Username: "admin", HostName: "host-a", Action: "vm.started", Target: "vm-1", Detail: "ok", Result: "success"},
		{ID: "a3", Username: "bob", HostName: "host-b", Action: "vm.migrated", Target: "vm-2", Detail: "to=host-a", Result: "success"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", rec.ID, err)
		}
	}

	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(resp.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(resp.Entries))
	}
	// Entries should be ordered by timestamp DESC, but since we insert them in quick
	// succession they may have the same timestamp. Just verify all are present.
	actions := map[string]bool{}
	for _, e := range resp.Entries {
		actions[e.Action] = true
	}
	for _, want := range []string{"vm.created", "vm.started", "vm.migrated"} {
		if !actions[want] {
			t.Errorf("missing action %q", want)
		}
	}
}

func TestListAuditLog_Filters(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, rec := range []corrosion.AuditRecord{
		{ID: "f1", Username: "alice", HostName: "h", Action: "sg.create", Target: "/projects/acme", Result: "ok"},
		{ID: "f2", Username: "alice", HostName: "h", Action: "sg.delete", Target: "/projects/acme", Result: "ok"},
		{ID: "f3", Username: "bob", HostName: "h", Action: "vm.start", Target: "/projects/other", Result: "ok"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", rec.ID, err)
		}
	}

	// action prefix glob: sg.* matches sg.create + sg.delete.
	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Action: "sg.*"})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("action=sg.* → %d entries, want 2", len(resp.Entries))
	}

	// exact action (no glob).
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Action: "sg.create"})
	if len(resp.Entries) != 1 {
		t.Fatalf("action=sg.create → %d, want 1", len(resp.Entries))
	}

	// user filter.
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{User: "bob"})
	if len(resp.Entries) != 1 || resp.Entries[0].Action != "vm.start" {
		t.Fatalf("user=bob filter wrong: %+v", resp.Entries)
	}

	// target filter.
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Target: "/projects/other"})
	if len(resp.Entries) != 1 || resp.Entries[0].Username != "bob" {
		t.Fatalf("target filter wrong: %+v", resp.Entries)
	}
}

func TestListAuditLog_DefaultLimit(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Limit 0 should default to 100 (we just verify it doesn't error).
	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 0})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestListAuditLog_RequiresViewer(t *testing.T) {
	s := testServer(t)
	ctx := context.Background() // no role

	_, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 10})
	if err == nil {
		t.Fatal("expected permission denied, got nil")
	}
	if !strings.Contains(err.Error(), "PermissionDenied") && !strings.Contains(err.Error(), "role") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListAuditLog_ClusterWideEntries(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert audit entries from different hosts — simulates Corrosion CRDT replication.
	for _, rec := range []corrosion.AuditRecord{
		{ID: "local-1", Username: "admin", HostName: "test-host", Action: "vm.created", Target: "vm-local", Result: "ok"},
		{ID: "remote-1", Username: "admin", HostName: "remote-host", Action: "vm.migrated", Target: "vm-remote", Result: "ok"},
		{ID: "remote-2", Username: "bot", HostName: "other-host", Action: "vm.deleted", Target: "vm-other", Result: "ok"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}
	}

	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 50})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}

	// All entries from all hosts should be visible (cluster-wide via Corrosion).
	if len(resp.Entries) != 3 {
		t.Fatalf("expected 3 entries from all hosts, got %d", len(resp.Entries))
	}

	hosts := map[string]bool{}
	for _, e := range resp.Entries {
		hosts[e.HostName] = true
	}
	for _, want := range []string{"test-host", "remote-host", "other-host"} {
		if !hosts[want] {
			t.Errorf("missing entries from host %q", want)
		}
	}
}

func TestSetDNSDomain(t *testing.T) {
	s := testServer(t)
	s.SetDNSDomain("litevirt.local")
	if s.dnsDomain != "litevirt.local" {
		t.Errorf("dnsDomain = %q", s.dnsDomain)
	}
}
