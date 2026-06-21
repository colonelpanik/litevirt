package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

func dnsRecordActive(t *testing.T, s *Server, name string) bool {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT name FROM dns_records WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		t.Fatalf("query dns_records: %v", err)
	}
	return len(rows) > 0
}

func TestReapOrphanDNSRecords(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "litevirt.local"
	ctx := context.Background()

	// Active VM with an IP'd interface — its auto record must be KEPT.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "keepvm", StackName: "st", HostName: "test-host", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "keepvm", NetworkName: "n", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.5"}},
		nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := dns.UpsertRecord(ctx, s.db, "keepvm.st.litevirt.local", "10.0.0.5"); err != nil {
		t.Fatalf("UpsertRecord keepvm: %v", err)
	}

	// Old orphan (no matching VM, stale updated_at) — must be REAPED.
	if err := s.db.Execute(ctx,
		`INSERT INTO dns_records (name, type, value, source, updated_at) VALUES (?, 'A', ?, 'auto', ?)`,
		"ghost.st.litevirt.local", "10.0.0.9", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert orphan: %v", err)
	}

	// Fresh orphan (no matching VM, recent updated_at) — must be KEPT (grace
	// window guards against reaping a record whose VM hasn't replicated yet).
	if err := dns.UpsertRecord(ctx, s.db, "freshghost.st.litevirt.local", "10.0.0.8"); err != nil {
		t.Fatalf("UpsertRecord freshghost: %v", err)
	}

	s.ReapOrphanDNSRecords(ctx)

	if !dnsRecordActive(t, s, "keepvm.st.litevirt.local") {
		t.Error("valid VM's record was wrongly reaped")
	}
	if dnsRecordActive(t, s, "ghost.st.litevirt.local") {
		t.Error("stale orphan record was NOT reaped")
	}
	if !dnsRecordActive(t, s, "freshghost.st.litevirt.local") {
		t.Error("fresh record was reaped despite the grace window")
	}
}
