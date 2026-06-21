package corrosion

import (
	"context"
	"testing"
)

func TestInsertAndGetHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	err := InsertHost(ctx, c, HostRecord{
		Name:     "node1",
		Address:  "10.0.0.1",
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    "active",
		CPUTotal: 16,
		MemTotal: 32768,
	})
	if err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	h, err := GetHost(ctx, c, "node1")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h == nil {
		t.Fatal("GetHost returned nil")
	}
	if h.Name != "node1" {
		t.Errorf("Name = %q, want node1", h.Name)
	}
	if h.CPUTotal != 16 {
		t.Errorf("CPUTotal = %d, want 16", h.CPUTotal)
	}
}

func TestGetHost_NotFound(t *testing.T) {
	c := testClient(t)
	h, err := GetHost(context.Background(), c, "missing")
	if err != nil {
		t.Fatalf("GetHost error: %v", err)
	}
	if h != nil {
		t.Errorf("expected nil for missing host, got %+v", h)
	}
}

func TestListHosts_WithLabels(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, cpu_total, mem_total, labels, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"node1", "10.0.0.1", "root", 22, 7443, "active", "", 16, 32768,
		`{"zone":"us-east","env":"prod"}`, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")

	hosts, err := ListHosts(ctx, c)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.Labels["zone"] != "us-east" {
		t.Errorf("Labels[zone] = %q, want us-east", h.Labels["zone"])
	}
	if h.Labels["env"] != "prod" {
		t.Errorf("Labels[env] = %q, want prod", h.Labels["env"])
	}
}

func TestGetHost_WithLabels(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, cpu_total, mem_total, labels, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"labeled", "10.0.0.1", "root", 22, 7443, "active", "", 8, 16384,
		`{"dc":"lon1"}`, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")

	h, err := GetHost(ctx, c, "labeled")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Labels["dc"] != "lon1" {
		t.Errorf("Labels[dc] = %q, want lon1", h.Labels["dc"])
	}
}

func TestDecodeLabels(t *testing.T) {
	tests := []struct {
		raw  string
		key  string
		want string
	}{
		{`{"zone":"us-east"}`, "zone", "us-east"},
		{`{}`, "zone", ""},
		{"", "zone", ""},
		{`invalid json`, "zone", ""},
	}
	for _, tt := range tests {
		m := decodeLabels(tt.raw)
		if m[tt.key] != tt.want {
			t.Errorf("decodeLabels(%q)[%q] = %q, want %q", tt.raw, tt.key, m[tt.key], tt.want)
		}
	}
}

func TestUpdateHostState(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "abc",
	})

	if err := UpdateHostState(ctx, c, "node1", "maintenance"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}

	h, _ := GetHost(ctx, c, "node1")
	if h.State != "maintenance" {
		t.Errorf("State = %q, want maintenance", h.State)
	}
}

func TestDeleteHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// host_health table is missing deleted_at column that DeleteHost expects.
	// Add it so the batch doesn't fail.
	_ = c.execLocal(ctx, `ALTER TABLE host_health ADD COLUMN deleted_at TEXT`)

	InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "abc",
	})

	if err := DeleteHost(ctx, c, "node1"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}

	h, _ := GetHost(ctx, c, "node1")
	if h != nil {
		t.Error("expected nil after DeleteHost")
	}

	hosts, _ := ListHosts(ctx, c)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts after delete, got %d", len(hosts))
	}
}

func TestDeleteHost_PreservesOthers(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_ = c.execLocal(ctx, `ALTER TABLE host_health ADD COLUMN deleted_at TEXT`)

	InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a",
	})
	InsertHost(ctx, c, HostRecord{
		Name: "node2", Address: "10.0.0.2", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b",
	})

	DeleteHost(ctx, c, "node1")

	hosts, _ := ListHosts(ctx, c)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Name != "node2" {
		t.Errorf("remaining host = %q, want node2", hosts[0].Name)
	}
}

func TestUpdateHostResources(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "abc",
		CPUTotal: 8, MemTotal: 16384, DiskTotal: 100,
	})

	if err := UpdateHostResources(ctx, c, "node1", 16, 32768, 500); err != nil {
		t.Fatalf("UpdateHostResources: %v", err)
	}

	h, _ := GetHost(ctx, c, "node1")
	if h.CPUTotal != 16 {
		t.Errorf("CPUTotal = %d, want 16", h.CPUTotal)
	}
	if h.MemTotal != 32768 {
		t.Errorf("MemTotal = %d, want 32768", h.MemTotal)
	}
	if h.DiskTotal != 500 {
		t.Errorf("DiskTotal = %d, want 500", h.DiskTotal)
	}
}

func TestListHosts_Empty(t *testing.T) {
	c := testClient(t)

	hosts, err := ListHosts(context.Background(), c)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestListHosts_Multiple(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, h := range []HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a"},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b"},
		{Name: "node3", Address: "10.0.0.3", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "c"},
	} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}

	hosts, err := ListHosts(ctx, c)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(hosts))
	}
}

func TestInsertHost_WithFenceStrategy(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "abc",
		FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	h, _ := GetHost(ctx, c, "node1")
	if h.FenceStrategy != "ipmi" {
		t.Errorf("FenceStrategy = %q, want ipmi", h.FenceStrategy)
	}
}

func TestUpdateVMHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	c.Execute(ctx, `INSERT INTO vms (name, stack_name, host_name, spec, state, cpu_actual, mem_actual, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"vm1", "", "node1", "{}", "running", 2, 1024, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")

	if err := UpdateVMHost(ctx, c, "vm1", "node2", "running"); err != nil {
		t.Fatalf("UpdateVMHost: %v", err)
	}

	vm, err := GetVM(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "node2" {
		t.Errorf("HostName = %q, want node2", vm.HostName)
	}
	if vm.State != "running" {
		t.Errorf("State = %q, want running", vm.State)
	}
}
