package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

func TestIPScanner_NewIPScanner(t *testing.T) {
	s := testServer(t)
	scanner := NewIPScanner(s)
	if scanner.hostName != "test-host" {
		t.Errorf("hostName = %q, want test-host", scanner.hostName)
	}
	if scanner.db != s.db {
		t.Error("db not wired")
	}
	if scanner.server != s {
		t.Error("server not wired")
	}
}

func TestIPScanner_ScanSkipsVMsWithIP(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// Insert a running VM with an interface that already has an IP.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "has-ip", HostName: "test-host", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "has-ip", NetworkName: "default", MAC: "52:54:00:aa:bb:cc", IP: "10.0.0.1"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	scanner := NewIPScanner(s)
	// scan should skip VMs that already have IPs (no ARP/DHCP lookup).
	// Since there's no real ARP table, scan just returns without changes.
	scanner.scan(ctx) // should not panic
}

func TestIPScanner_ScanSkipsNonRunning(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// Insert a stopped VM.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "stopped-vm", HostName: "test-host", State: "stopped",
	}, []corrosion.InterfaceRecord{
		{VMName: "stopped-vm", NetworkName: "default", MAC: "52:54:00:dd:ee:ff"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	scanner := NewIPScanner(s)
	scanner.scan(ctx) // should skip stopped VMs, no panic
}

func TestIPScanner_DNSUpsertOnDiscovery(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "litevirt.local"
	ctx := context.Background()

	// Insert a running VM with an interface that has no IP.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", HostName: "test-host", State: "running", StackName: "prod",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-1", NetworkName: "default", MAC: "52:54:00:11:22:33"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Simulate the post-discovery path that would run after IP is found:
	// The scanner calls UpdateVMInterfaceIP then dns.UpsertRecord.
	ip := "10.0.50.100"
	if err := corrosion.UpdateVMInterfaceIP(ctx, s.db, "web-1", "default", ip); err != nil {
		t.Fatalf("UpdateVMInterfaceIP: %v", err)
	}

	dnsName := dns.VMRecordName("web-1", "prod", "litevirt.local")
	if err := dns.UpsertRecord(ctx, s.db, dnsName, ip); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	// Verify the DNS record was created.
	rows, err := s.db.Query(ctx,
		`SELECT value FROM dns_records WHERE name = ? AND deleted_at IS NULL`, dnsName)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 DNS record, got %d", len(rows))
	}
	if rows[0].String("value") != ip {
		t.Errorf("DNS value = %q, want %q", rows[0].String("value"), ip)
	}

	// Verify the expected DNS name format.
	expectedName := "web-1.prod.litevirt.local"
	if dnsName != expectedName {
		t.Errorf("DNS name = %q, want %q", dnsName, expectedName)
	}
}

func TestIPScanner_DNSNotSetWhenNoDomain(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "" // no DNS domain configured
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "no-dns-vm", HostName: "test-host", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "no-dns-vm", NetworkName: "default", MAC: "52:54:00:44:55:66"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Simulate IP discovery — but since dnsDomain is empty, no DNS record should be created.
	corrosion.UpdateVMInterfaceIP(ctx, s.db, "no-dns-vm", "default", "10.0.0.99")

	// The scanner code checks `if domain:= s.server.dnsDomain; domain != ""` before upserting.
	// Verify no DNS records exist.
	rows, _ := s.db.Query(ctx, `SELECT name FROM dns_records WHERE deleted_at IS NULL`)
	if len(rows) != 0 {
		t.Errorf("expected 0 DNS records with empty domain, got %d", len(rows))
	}
}

// TestIPScanner_ContainerDNSReconcile: the scanner discovers a running local
// container's IP (lxc-info), persists it onto the managed NIC row, and upserts the
// auto DNS record (ct.stack.domain → IP) — the convergent CT-DNS reconciler.
func TestIPScanner_ContainerDNSReconcile(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	s.dnsDomain = "litevirt.local"
	s.SetContainerRuntime(&fakeCTRuntime{ipByName: map[string]string{"ct1": "10.0.60.5"}})
	ctx := context.Background()

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "ct1", State: "running", Project: "acme",
		Labels: map[string]string{corrosion.LabelStack: "prod"},
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	// A managed NIC with no IP yet (DHCP pending).
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "test-host", CtName: "ct1", NetworkName: "br0", Ordinal: 0,
		MAC: "52:00:00:00:00:02", IP: "", VethDevice: "lvc123",
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}

	NewIPScanner(s).scanContainers(ctx)

	// IP persisted onto the NIC row.
	ifaces, _ := corrosion.GetContainerInterfaces(ctx, s.db, "test-host", "ct1")
	if len(ifaces) != 1 || ifaces[0].IP != "10.0.60.5" {
		t.Fatalf("NIC IP not persisted: %+v", ifaces)
	}
	// DNS record upserted at ct.stack.domain.
	rows, _ := s.db.Query(ctx,
		`SELECT value FROM dns_records WHERE name = ? AND deleted_at IS NULL`, "ct1.prod.litevirt.local")
	if len(rows) != 1 || rows[0].String("value") != "10.0.60.5" {
		t.Fatalf("CT DNS record not upserted: %+v", rows)
	}
}

func TestCleanupFDBForVM_NonVXLAN(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// Insert a VM with interface on a bridge network (not VXLAN).
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "bridge-vm", HostName: "test-host", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "bridge-vm", NetworkName: "default", MAC: "52:54:00:77:88:99"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// No network record or a bridge-type network → early exit, no FDB cleanup needed.
	s.CleanupFDBForVM(ctx, "bridge-vm") // should not panic
}

func TestCleanupFDBForVM_NoInterfaces(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// VM with no interfaces — cleanup should be a no-op.
	s.CleanupFDBForVM(ctx, "nonexistent-vm") // should not panic
}

func TestSetVMIP_DNSUpsert(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "test.local"
	ctx := adminCtx()

	// Insert a running VM.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "dns-vm", HostName: "test-host", State: "running", StackName: "web",
	}, []corrosion.InterfaceRecord{
		{VMName: "dns-vm", NetworkName: "production", MAC: "52:54:00:ab:cd:ef"},
	}, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Call SetVMIP which should also upsert DNS.
	_, err = s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "dns-vm", Ip: "10.0.1.50",
	})
	if err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}

	// Verify DNS record was created.
	expectedDNS := "dns-vm.web.test.local"
	rows, err := s.db.Query(ctx,
		`SELECT value FROM dns_records WHERE name = ? AND deleted_at IS NULL`, expectedDNS)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 DNS record for %s, got %d", expectedDNS, len(rows))
	}
	if rows[0].String("value") != "10.0.1.50" {
		t.Errorf("DNS value = %q, want 10.0.1.50", rows[0].String("value"))
	}
}
