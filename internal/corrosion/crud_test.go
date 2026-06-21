package corrosion

import (
	"context"
	"testing"
)

func newTestDB(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

// ── Hosts ───────────────────────────────────────────────────────────────────

func TestUpdateHostVersion(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertHost(ctx, db, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "abc", MemTotal: 4096,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := UpdateHostVersion(ctx, db, "node1", "1.2.3"); err != nil {
		t.Fatalf("UpdateHostVersion: %v", err)
	}

	h, err := GetHost(ctx, db, "node1")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", h.Version)
	}
}

// ── Images ──────────────────────────────────────────────────────────────────

func TestUpdateImageHostProgress(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Insert an image and image_host record first.
	if err := db.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, '2024-01-01', '2024-01-01')`,
		"ubuntu-24.04", "qcow2", "https://cloud.ubuntu.com/img.qcow2", "abc123", 1024*1024*1024,
	); err != nil {
		t.Fatalf("insert image: %v", err)
	}

	if err := InsertImageHost(ctx, db, ImageHostRecord{
		ImageName: "ubuntu-24.04", HostName: "node1", Path: "/img/ubuntu.qcow2",
		Status: "pulling", PulledAt: "2024-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("InsertImageHost: %v", err)
	}

	if err := UpdateImageHostProgress(ctx, db, "ubuntu-24.04", "node1", 75.5); err != nil {
		t.Fatalf("UpdateImageHostProgress: %v", err)
	}

	rows, err := db.Query(ctx,
		`SELECT progress_pct FROM image_hosts WHERE image_name = ? AND host_name = ?`,
		"ubuntu-24.04", "node1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	// progress_pct is read as int in this codebase (truncated).
	pct := rows[0].Int("progress_pct")
	if pct != 75 {
		t.Errorf("progress_pct = %d, want 75", pct)
	}
}

func TestUpdateImageHostStatus(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := db.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, '2024-01-01', '2024-01-01')`,
		"alpine-3.19", "qcow2", "https://dl-cdn.alpinelinux.org/img.qcow2", "def456", 50*1024*1024,
	); err != nil {
		t.Fatalf("insert image: %v", err)
	}

	if err := InsertImageHost(ctx, db, ImageHostRecord{
		ImageName: "alpine-3.19", HostName: "node1", Path: "/img/alpine.qcow2",
		Status: "pulling", PulledAt: "2024-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("InsertImageHost: %v", err)
	}

	if err := UpdateImageHostStatus(ctx, db, "alpine-3.19", "node1", "ready"); err != nil {
		t.Fatalf("UpdateImageHostStatus: %v", err)
	}

	rows, err := db.Query(ctx,
		`SELECT status FROM image_hosts WHERE image_name = ? AND host_name = ?`,
		"alpine-3.19", "node1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows[0].String("status") != "ready" {
		t.Errorf("status = %q, want ready", rows[0].String("status"))
	}
}

// ── LB Configs ──────────────────────────────────────────────────────────────

func TestListLBConfigs_Empty(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	configs, err := ListLBConfigs(ctx, db)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("expected 0 configs, got %d", len(configs))
	}
}

func TestListLBConfigs_WithRecords(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, db, LBConfigRecord{
		Name: "web-lb", StackName: "web", VIP: "10.0.0.100",
		Algorithm: "roundrobin", Hosts: `["node1","node2"]`,
		Ports: `[{"listen":80,"backend":8080}]`, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	configs, err := ListLBConfigs(ctx, db)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs[0].Name != "web-lb" {
		t.Errorf("name = %q, want web-lb", configs[0].Name)
	}
	if configs[0].VIP != "10.0.0.100" {
		t.Errorf("vip = %q, want 10.0.0.100", configs[0].VIP)
	}
	if !configs[0].Enabled {
		t.Error("expected enabled=true")
	}
}

func TestSoftDeleteLBConfig(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, db, LBConfigRecord{
		Name: "web-lb", VIP: "10.0.0.100", Algorithm: "roundrobin",
		Hosts: `["node1"]`, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	if err := SoftDeleteLBConfig(ctx, db, "web-lb"); err != nil {
		t.Fatalf("SoftDeleteLBConfig: %v", err)
	}

	// ListLBConfigs should exclude soft-deleted records.
	configs, err := ListLBConfigs(ctx, db)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("expected 0 configs after soft delete, got %d", len(configs))
	}
}

// ── Stacks ──────────────────────────────────────────────────────────────────

func TestSetStackState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := UpsertStack(ctx, db, StackRecord{
		Name: "web", ComposeHash: "abc", ComposeYAML: "version: '3'", State: "active",
	}); err != nil {
		t.Fatalf("UpsertStack: %v", err)
	}

	if err := SetStackState(ctx, db, "web", "deleting"); err != nil {
		t.Fatalf("SetStackState: %v", err)
	}

	stacks, err := ListStacks(ctx, db)
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}
	found := false
	for _, s := range stacks {
		if s.Name == "web" {
			found = true
			if s.State != "deleting" {
				t.Errorf("state = %q, want deleting", s.State)
			}
		}
	}
	if !found {
		t.Error("stack 'web' not found")
	}
}

func TestListDeletingStacks_Empty(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	stacks, err := ListDeletingStacks(ctx, db)
	if err != nil {
		t.Fatalf("ListDeletingStacks: %v", err)
	}
	if len(stacks) != 0 {
		t.Errorf("expected 0 deleting stacks, got %d", len(stacks))
	}
}

func TestListDeletingStacks_FiltersByState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, s := range []StackRecord{
		{Name: "active-stack", State: "active"},
		{Name: "deleting-stack", State: "deleting"},
		{Name: "another-active", State: "active"},
	} {
		if err := UpsertStack(ctx, db, s); err != nil {
			t.Fatalf("UpsertStack(%s): %v", s.Name, err)
		}
	}

	stacks, err := ListDeletingStacks(ctx, db)
	if err != nil {
		t.Fatalf("ListDeletingStacks: %v", err)
	}
	if len(stacks) != 1 {
		t.Fatalf("expected 1 deleting stack, got %d", len(stacks))
	}
	if stacks[0].Name != "deleting-stack" {
		t.Errorf("name = %q, want deleting-stack", stacks[0].Name)
	}
}

// ── Users ───────────────────────────────────────────────────────────────────

func TestUpdateUserPassword(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertUser(ctx, db, "alice", "admin", "hash-old"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	if err := UpdateUserPassword(ctx, db, "alice", "hash-new"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}

	rows, err := db.Query(ctx,
		`SELECT password_hash FROM users WHERE username = ? AND deleted_at IS NULL`, "alice")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0].String("password_hash") != "hash-new" {
		t.Errorf("password not updated")
	}
}

// ── VMs: aggregate queries ──────────────────────────────────────────────────

func TestCountVMsByHost(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, vm := range []VMRecord{
		{Name: "vm1", HostName: "node1", State: "running", Spec: `{}`},
		{Name: "vm2", HostName: "node1", State: "stopped", Spec: `{}`},
		{Name: "vm3", HostName: "node2", State: "running", Spec: `{}`},
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	counts, err := CountVMsByHost(ctx, db)
	if err != nil {
		t.Fatalf("CountVMsByHost: %v", err)
	}
	if counts["node1"] != 2 {
		t.Errorf("node1 count = %d, want 2", counts["node1"])
	}
	if counts["node2"] != 1 {
		t.Errorf("node2 count = %d, want 1", counts["node2"])
	}
}

func TestSumVMResourcesByHost(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, vm := range []VMRecord{
		{Name: "vm1", HostName: "node1", State: "running", CPUActual: 4, MemActual: 8192, Spec: `{}`},
		{Name: "vm2", HostName: "node1", State: "running", CPUActual: 2, MemActual: 4096, Spec: `{}`},
		{Name: "vm3", HostName: "node1", State: "stopped", CPUActual: 8, MemActual: 16384, Spec: `{}`}, // stopped — excluded
		{Name: "vm4", HostName: "node2", State: "running", CPUActual: 1, MemActual: 2048, Spec: `{}`},
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	usage, err := SumVMResourcesByHost(ctx, db)
	if err != nil {
		t.Fatalf("SumVMResourcesByHost: %v", err)
	}
	if usage["node1"].CpuUsed != 6 {
		t.Errorf("node1 cpu = %d, want 6", usage["node1"].CpuUsed)
	}
	if usage["node1"].MemUsedMiB != 12288 {
		t.Errorf("node1 mem = %d, want 12288", usage["node1"].MemUsedMiB)
	}
	if usage["node2"].CpuUsed != 1 {
		t.Errorf("node2 cpu = %d, want 1", usage["node2"].CpuUsed)
	}
}

func TestCountVMsByStack(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, vm := range []VMRecord{
		{Name: "web-1", HostName: "n1", StackName: "web", State: "running", Spec: `{}`},
		{Name: "web-2", HostName: "n2", StackName: "web", State: "running", Spec: `{}`},
		{Name: "web-3", HostName: "n1", StackName: "web", State: "stopped", Spec: `{}`},
		{Name: "db-1", HostName: "n1", StackName: "db", State: "error", Spec: `{}`},
		{Name: "orphan", HostName: "n1", StackName: "", State: "running", Spec: `{}`}, // no stack
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	counts, err := CountVMsByStack(ctx, db)
	if err != nil {
		t.Fatalf("CountVMsByStack: %v", err)
	}

	web := counts["web"]
	if web.Total != 3 {
		t.Errorf("web total = %d, want 3", web.Total)
	}
	if web.Running != 2 {
		t.Errorf("web running = %d, want 2", web.Running)
	}
	if web.Stopped != 1 {
		t.Errorf("web stopped = %d, want 1", web.Stopped)
	}

	db2 := counts["db"]
	if db2.Error != 1 {
		t.Errorf("db error = %d, want 1", db2.Error)
	}

	// "orphan" has no stack name — should not appear.
	if _, ok := counts[""]; ok {
		t.Error("empty stack name should not appear in counts")
	}
}

func TestBatchGetVMInterfaces(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Insert VMs.
	for _, vm := range []VMRecord{
		{Name: "vm1", HostName: "n1", State: "running", Spec: `{}`},
		{Name: "vm2", HostName: "n1", State: "running", Spec: `{}`},
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	// Insert interfaces.
	for _, iface := range []InterfaceRecord{
		{VMName: "vm1", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:01:01:01"},
		{VMName: "vm1", NetworkName: "br1", Ordinal: 1, MAC: "52:54:00:01:01:02"},
		{VMName: "vm2", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:02:02:01"},
	} {
		if err := InsertInterface(ctx, db, iface); err != nil {
			t.Fatalf("InsertInterface: %v", err)
		}
	}

	result, err := BatchGetVMInterfaces(ctx, db)
	if err != nil {
		t.Fatalf("BatchGetVMInterfaces: %v", err)
	}
	if len(result["vm1"]) != 2 {
		t.Errorf("vm1 interfaces = %d, want 2", len(result["vm1"]))
	}
	if len(result["vm2"]) != 1 {
		t.Errorf("vm2 interfaces = %d, want 1", len(result["vm2"]))
	}
	// Check ordering by ordinal.
	if result["vm1"][0].NetworkName != "br0" || result["vm1"][1].NetworkName != "br1" {
		t.Errorf("vm1 interfaces not ordered by ordinal")
	}
}

func TestCountVMsByNetwork(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, vm := range []VMRecord{
		{Name: "vm1", HostName: "n1", State: "running", Spec: `{}`},
		{Name: "vm2", HostName: "n1", State: "running", Spec: `{}`},
		{Name: "vm3", HostName: "n1", State: "running", Spec: `{}`},
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	for _, iface := range []InterfaceRecord{
		{VMName: "vm1", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:01:01:01"},
		{VMName: "vm2", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:02:02:01"},
		{VMName: "vm3", NetworkName: "br1", Ordinal: 0, MAC: "52:54:00:03:03:01"},
		{VMName: "vm1", NetworkName: "br1", Ordinal: 1, MAC: "52:54:00:01:01:02"}, // vm1 on two networks
	} {
		if err := InsertInterface(ctx, db, iface); err != nil {
			t.Fatalf("InsertInterface: %v", err)
		}
	}

	counts, err := CountVMsByNetwork(ctx, db)
	if err != nil {
		t.Fatalf("CountVMsByNetwork: %v", err)
	}
	if counts["br0"] != 2 {
		t.Errorf("br0 count = %d, want 2", counts["br0"])
	}
	if counts["br1"] != 2 {
		t.Errorf("br1 count = %d, want 2", counts["br1"])
	}
}

// ── VMs: CRUD operations ────────────────────────────────────────────────────

func TestGetDeletedVM(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-del", HostName: "n1", State: "running", Spec: `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Not deleted yet — should return nil.
	got, err := GetDeletedVM(ctx, db, "vm-del")
	if err != nil {
		t.Fatalf("GetDeletedVM: %v", err)
	}
	if got != nil {
		t.Error("expected nil for non-deleted VM")
	}

	// Delete the VM.
	if err := DeleteVM(ctx, db, "vm-del"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	// Now should return the deleted record.
	got, err = GetDeletedVM(ctx, db, "vm-del")
	if err != nil {
		t.Fatalf("GetDeletedVM after delete: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil for deleted VM")
	}
	if got.Name != "vm-del" {
		t.Errorf("name = %q, want vm-del", got.Name)
	}
}

func TestGetDeletedVM_NotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	got, err := GetDeletedVM(ctx, db, "nonexistent")
	if err != nil {
		t.Fatalf("GetDeletedVM: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent VM")
	}
}

func TestUpdateDiskSize(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-disk", HostName: "n1", State: "running", Spec: `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := InsertDisk(ctx, db, DiskRecord{
		VMName: "vm-disk", DiskName: "root", HostName: "n1",
		Path: "/data/root.qcow2", SizeBytes: 10 * 1024 * 1024 * 1024,
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	newSize := int64(50 * 1024 * 1024 * 1024)
	if err := UpdateDiskSize(ctx, db, "vm-disk", "root", newSize); err != nil {
		t.Fatalf("UpdateDiskSize: %v", err)
	}

	disks, err := GetVMDisks(ctx, db, "vm-disk")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].SizeBytes != newSize {
		t.Errorf("size = %d, want %d", disks[0].SizeBytes, newSize)
	}
}

func TestUpdateVMSpec(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-spec", HostName: "n1", State: "stopped",
		Spec: `{"cpu":2,"memory":4096}`, CPUActual: 2, MemActual: 4096,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	newSpec := `{"cpu":4,"memory":8192}`
	if err := UpdateVMSpec(ctx, db, "vm-spec", newSpec, 4, 8192); err != nil {
		t.Fatalf("UpdateVMSpec: %v", err)
	}

	vm, err := GetVM(ctx, db, "vm-spec")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.Spec != newSpec {
		t.Errorf("spec = %q, want %q", vm.Spec, newSpec)
	}
	if vm.CPUActual != 4 {
		t.Errorf("cpu = %d, want 4", vm.CPUActual)
	}
	if vm.MemActual != 8192 {
		t.Errorf("mem = %d, want 8192", vm.MemActual)
	}
}
