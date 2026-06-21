package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testSweepDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestVMChecker_SweepEmpty(t *testing.T) {
	db := testSweepDB(t)
	v := NewVMChecker("node1", db, nil)

	// No VMs in DB — sweep should complete without error or panic.
	v.sweep(context.Background())
}

func TestVMChecker_SweepSkipsNonRunning(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert VMs in non-running states on our host.
	for _, vm := range []corrosion.VMRecord{
		{Name: "vm-stopped", HostName: "node1", Spec: `{"healthcheck":{"type":"tcp","target":"10.0.0.1:80"}}`, State: "stopped"},
		{Name: "vm-pending", HostName: "node1", Spec: `{"healthcheck":{"type":"tcp","target":"10.0.0.2:80"}}`, State: "pending"},
		{Name: "vm-error", HostName: "node1", Spec: `{"healthcheck":{"type":"tcp","target":"10.0.0.3:80"}}`, State: "error"},
		{Name: "vm-creating", HostName: "node1", Spec: `{"healthcheck":{"type":"tcp","target":"10.0.0.4:80"}}`, State: "creating"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)
	// sweep skips non-running VMs, so no goroutines should be launched
	// and no failure counters should be set.
	v.sweep(ctx)

	v.mu.Lock()
	failureCount := len(v.failures)
	v.mu.Unlock()

	// No failures should be recorded since no VMs were checked.
	if failureCount != 0 {
		t.Errorf("expected 0 failure entries, got %d", failureCount)
	}
}

func TestVMChecker_SweepSkipsNoHealthcheck(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert running VMs without healthcheck specs.
	for _, vm := range []corrosion.VMRecord{
		{Name: "vm-no-hc-1", HostName: "node1", Spec: `{"cpu":1}`, State: "running"},
		{Name: "vm-no-hc-2", HostName: "node1", Spec: `{}`, State: "running"},
		{Name: "vm-no-hc-3", HostName: "node1", Spec: ``, State: "running"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// No VMs should have had checkVM called since none have healthcheck specs.
	v.mu.Lock()
	failureCount := len(v.failures)
	v.mu.Unlock()

	if failureCount != 0 {
		t.Errorf("expected 0 failure entries for VMs without healthcheck, got %d", failureCount)
	}
}

func TestVMChecker_SweepSkipsOtherHost(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert a running VM with healthcheck on a different host.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-other-host",
		HostName: "node2",
		Spec:     `{"healthcheck":{"type":"tcp","target":"10.0.0.5:80"}}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// ListVMs filters by hostName, so VMs on other hosts are not included.
	v.mu.Lock()
	failureCount := len(v.failures)
	v.mu.Unlock()

	if failureCount != 0 {
		t.Errorf("expected 0 failure entries for VMs on other host, got %d", failureCount)
	}
}

func TestPickMigrationTarget_NoHosts(t *testing.T) {
	db := testSweepDB(t)
	v := NewVMChecker("node1", db, nil)

	_, err := v.pickMigrationTarget(context.Background(), "node1", 512)
	if err == nil {
		t.Fatal("expected error when no hosts exist")
	}
}

func TestPickMigrationTarget_ExcludesSelf(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert only one host — our own.
	err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:       "node1",
		Address:    "10.0.0.1",
		SSHUser:    "root",
		SSHPort:    22,
		GRPCPort:   7443,
		State:      "active",
		CertSerial: "abc",
		MemTotal:   8192,
	})
	if err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	_, err = v.pickMigrationTarget(ctx, "node1", 512)
	if err == nil {
		t.Fatal("expected error when only host is self")
	}
}

func TestPickMigrationTarget_InsufficientMemory(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert two hosts. node2 has 1024 MiB total.
	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 8192},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 1024},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost(%s): %v", h.Name, err)
		}
	}

	// Insert a running VM on node2 using 800 MiB.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "existing-vm",
		HostName:  "node2",
		Spec:      `{}`,
		State:     "running",
		MemActual: 800,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	// node2 has 1024 total, 800 used = 224 free. Request 512 MiB — should fail.
	_, err = v.pickMigrationTarget(ctx, "node1", 512)
	if err == nil {
		t.Fatal("expected error when target has insufficient memory")
	}
}

func TestPickMigrationTarget_SelectsBestHost(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	// Insert three hosts. We're node1, node2 has 4096 free, node3 has 8192 free.
	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 16384},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 4096},
		{Name: "node3", Address: "10.0.0.3", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "c", MemTotal: 8192},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost(%s): %v", h.Name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)
	target, err := v.pickMigrationTarget(ctx, "node1", 512)
	if err != nil {
		t.Fatalf("pickMigrationTarget: %v", err)
	}
	// node3 has most free memory (8192 vs 4096).
	if target.Name != "node3" {
		t.Errorf("expected target node3, got %s", target.Name)
	}
}

func TestPickMigrationTarget_ExcludesInactiveHosts(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 8192},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "maintenance", CertSerial: "b", MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost(%s): %v", h.Name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)
	// node2 is in maintenance — should not be picked even though it has more memory.
	_, err := v.pickMigrationTarget(ctx, "node1", 512)
	if err == nil {
		t.Fatal("expected error when only other host is in maintenance")
	}
}

func TestPickMigrationTarget_ZeroMemVM(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()

	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 4096},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 1024},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost(%s): %v", h.Name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)
	// vmMemMiB=0 skips the free memory check.
	target, err := v.pickMigrationTarget(ctx, "node1", 0)
	if err != nil {
		t.Fatalf("pickMigrationTarget: %v", err)
	}
	if target.Name != "node2" {
		t.Errorf("expected node2, got %s", target.Name)
	}
}
