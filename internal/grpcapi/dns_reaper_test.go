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

// TestReapOrphanDNSRecords_Containers: a live container with a known managed-NIC
// IP keeps its auto record; an orphan CT record (no live CT) is reaped. Without
// the CT expected-set extension the reaper would delete live CT records.
func TestReapOrphanDNSRecords_Containers(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "litevirt.local"
	ctx := context.Background()

	// Live CT on a stack, with an IP'd managed NIC — its record must be KEPT.
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "keepct", State: "running", Project: "acme",
		Labels: map[string]string{corrosion.LabelStack: "st"},
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "test-host", CtName: "keepct", NetworkName: "n", Ordinal: 0,
		MAC: "52:00:00:00:00:01", IP: "10.0.0.7", VethDevice: "lvcdef",
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}
	if err := dns.UpsertRecord(ctx, s.db, "keepct.st.litevirt.local", "10.0.0.7"); err != nil {
		t.Fatalf("UpsertRecord keepct: %v", err)
	}

	// Old orphan CT record (no live CT) — must be REAPED.
	if err := s.db.Execute(ctx,
		`INSERT INTO dns_records (name, type, value, source, updated_at) VALUES (?, 'A', ?, 'auto', ?)`,
		"ghostct.st.litevirt.local", "10.0.0.9", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert orphan: %v", err)
	}

	s.ReapOrphanDNSRecords(ctx)

	if !dnsRecordActive(t, s, "keepct.st.litevirt.local") {
		t.Error("live container's DNS record was wrongly reaped")
	}
	if dnsRecordActive(t, s, "ghostct.st.litevirt.local") {
		t.Error("orphan container DNS record was NOT reaped")
	}
}
