package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func testCheckVMDB(t *testing.T) *corrosion.Client {
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

func TestCheckVM_HealthyProbe_ResetsFailures(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Start a healthy HTTP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL + "/health",
		Retries: 3,
		Action:  "restart",
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-healthy",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	// Pre-seed some failures.
	v.mu.Lock()
	v.failures["vm-healthy"] = 2
	v.actionCount["vm-healthy"] = 1
	v.mu.Unlock()

	vm := corrosion.VMRecord{Name: "vm-healthy", HostName: "node1", Spec: string(specJSON), State: "running"}
	v.checkVM(ctx, vm, hspec)

	// After a healthy probe, failures and actionCount should be reset.
	v.mu.Lock()
	f := v.failures["vm-healthy"]
	ac := v.actionCount["vm-healthy"]
	v.mu.Unlock()

	if f != 0 {
		t.Errorf("failures = %d after healthy probe, want 0", f)
	}
	if ac != 0 {
		t.Errorf("actionCount = %d after healthy probe, want 0", ac)
	}
}

func TestCheckVM_FailedProbe_IncrementsFailures(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// HTTP server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 5, // high so we don't trigger action
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-failing",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-failing", HostName: "node1", Spec: string(specJSON), State: "running"}

	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	f := v.failures["vm-failing"]
	v.mu.Unlock()

	if f != 1 {
		t.Errorf("failures = %d after 1 failed probe, want 1", f)
	}

	// Second failure.
	v.checkVM(ctx, vm, hspec)
	v.mu.Lock()
	f = v.failures["vm-failing"]
	v.mu.Unlock()

	if f != 2 {
		t.Errorf("failures = %d after 2 failed probes, want 2", f)
	}
}

func TestCheckVM_ThresholdCrossed_TriggersAction(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// HTTP server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 2,        // low threshold
		Action:  "restart", // needs virt — will short-circuit since virt is nil
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-action",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-action", HostName: "node1", Spec: string(specJSON), State: "running"}

	// Fail twice (retries=2).
	v.checkVM(ctx, vm, hspec)
	v.checkVM(ctx, vm, hspec)

	// After threshold, failures should be reset to 0 and actionCount incremented.
	v.mu.Lock()
	f := v.failures["vm-action"]
	ac := v.actionCount["vm-action"]
	v.mu.Unlock()

	if f != 0 {
		t.Errorf("failures = %d after threshold crossed, want 0 (reset after action)", f)
	}
	if ac != 1 {
		t.Errorf("actionCount = %d after action, want 1", ac)
	}
}

func TestCheckVM_AlertAction(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 1, // immediate trigger
		Action:  "alert",
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-alert",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-alert", HostName: "node1", Spec: string(specJSON), State: "running"}

	// Should not panic — alert action just logs.
	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	ac := v.actionCount["vm-alert"]
	v.mu.Unlock()

	if ac != 1 {
		t.Errorf("actionCount = %d, want 1", ac)
	}
}

func TestTakeAction_OperatorStop_Skipped(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Insert a VM that was stopped by operator between probe and action.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-opstop",
		HostName: "node1",
		Spec:     `{}`,
		State:    "stopped",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Set operator-stop detail.
	corrosion.UpdateVMState(ctx, db, "vm-opstop", "stopped", "operator-stop")

	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Action: "restart"}
	vm := corrosion.VMRecord{Name: "vm-opstop", HostName: "node1"}

	// takeAction should re-read state from DB and skip because of operator-stop.
	v.takeAction(ctx, vm, hspec)

	// VM should still be in stopped state.
	fresh, _ := corrosion.GetVM(ctx, db, "vm-opstop")
	if fresh.State != "stopped" {
		t.Errorf("expected stopped, got %q", fresh.State)
	}
}

func TestTakeAction_StateChanged_Skipped(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Insert a VM that changed to "migrating" between probe and action.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-migrating",
		HostName: "node1",
		Spec:     `{}`,
		State:    "migrating",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Action: "restart"}
	vm := corrosion.VMRecord{Name: "vm-migrating", HostName: "node1"}

	// takeAction should re-read and skip since state is not "running".
	v.takeAction(ctx, vm, hspec)
}

func TestTakeAction_DefaultAction_IsRestart(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-default-action",
		HostName: "node1",
		Spec:     `{}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	// Empty action should default to "restart".
	hspec := &pb.HealthCheckSpec{Action: ""}
	vm := corrosion.VMRecord{Name: "vm-default-action", HostName: "node1"}

	// With nil virt, restart short-circuits.
	v.takeAction(ctx, vm, hspec)
}

func TestTakeAction_UnknownAction(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-unknown-action",
		HostName: "node1",
		Spec:     `{}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Action: "explode"}
	vm := corrosion.VMRecord{Name: "vm-unknown-action", HostName: "node1"}

	// Should not panic — just logs a warning.
	v.takeAction(ctx, vm, hspec)
}

func TestTakeAction_MigrateAction_NilVirt(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-migrate-nil",
		HostName: "node1",
		Spec:     `{}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Action: "migrate"}
	vm := corrosion.VMRecord{Name: "vm-migrate-nil", HostName: "node1"}

	// migrateVM checks virt == nil and returns early.
	v.takeAction(ctx, vm, hspec)
}

func TestTakeAction_CorrelatedFailure_Suppressed(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-correlated",
		HostName: "node1",
		Spec:     `{}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)

	// Seed correlated failures (3 VMs with >= 2 failures each).
	v.mu.Lock()
	v.failures["vm-a"] = 3
	v.failures["vm-b"] = 2
	v.failures["vm-c"] = 5
	v.mu.Unlock()

	hspec := &pb.HealthCheckSpec{Action: "restart"}
	vm := corrosion.VMRecord{Name: "vm-correlated", HostName: "node1"}

	// takeAction should detect correlated failures and suppress action.
	v.takeAction(ctx, vm, hspec)

	// VM should remain running (action suppressed).
	fresh, _ := corrosion.GetVM(ctx, db, "vm-correlated")
	if fresh.State != "running" {
		t.Errorf("expected running (action suppressed), got %q", fresh.State)
	}
}

func TestTakeAction_VMNotFound_Skipped(t *testing.T) {
	db := testCheckVMDB(t)

	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Action: "restart"}
	vm := corrosion.VMRecord{Name: "nonexistent-vm", HostName: "node1"}

	// Should not panic when VM is not in DB (re-read returns nil).
	v.takeAction(context.Background(), vm, hspec)
}

func TestSweep_WithRunningVMAndHealthcheck(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Start a healthy HTTP server so the probe succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:   "http",
		Target: srv.URL,
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-sweep-running",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// Give the goroutine a moment to run.
	time.Sleep(100 * time.Millisecond)

	// Healthy probe should have cleared failures.
	v.mu.Lock()
	f := v.failures["vm-sweep-running"]
	v.mu.Unlock()

	if f != 0 {
		t.Errorf("expected 0 failures for healthy VM, got %d", f)
	}
}

func TestMigrateVM_NilVirt(t *testing.T) {
	db := testCheckVMDB(t)
	v := NewVMChecker("node1", db, nil)

	vm := corrosion.VMRecord{Name: "vm-mig", HostName: "node1"}
	// Should not panic.
	v.migrateVM(context.Background(), vm)
}

// refreshLBForVM was removed — LB refresh is now handled by the full
// MigrateVM RPC path (via migrateVMFunc callback).

func TestVMSpecFromDB_NotFound(t *testing.T) {
	db := testCheckVMDB(t)
	spec := vmSpecFromDB(context.Background(), db, "nonexistent")
	if spec != nil {
		t.Error("expected nil spec for nonexistent VM")
	}
}

func TestVMSpecFromDB_EmptySpec(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-empty-spec",
		HostName: "node1",
		Spec:     "",
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	spec := vmSpecFromDB(ctx, db, "vm-empty-spec")
	if spec != nil {
		t.Error("expected nil spec for empty spec string")
	}
}

func TestVMSpecFromDB_ValidSpec(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-valid-spec",
		HostName: "node1",
		Spec:     `{"cpu":2,"memory":1024,"guest_agent":true}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	spec := vmSpecFromDB(ctx, db, "vm-valid-spec")
	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
	if !spec.GuestAgent {
		t.Error("expected GuestAgent=true")
	}
}

func TestPickMigrationTarget_PrefersMoreMemory(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Insert 3 hosts.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "failing-host", State: "active", CPUTotal: 16, MemTotal: 32768}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "small-host", State: "active", CPUTotal: 4, MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "big-host", State: "active", CPUTotal: 16, MemTotal: 65536}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// Insert running VMs consuming memory on candidate hosts.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-a", HostName: "small-host", State: "running", MemActual: 4096}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-b", HostName: "big-host", State: "running", MemActual: 4096}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("failing-host", db, nil)
	target, err := v.pickMigrationTarget(ctx, "failing-host", 2048)
	if err != nil {
		t.Fatalf("pickMigrationTarget: %v", err)
	}
	// big-host has 65536-4096=61440 free vs small-host's 8192-4096=4096 free.
	if target.Name != "big-host" {
		t.Errorf("expected big-host, got %q", target.Name)
	}
}

func TestPickMigrationTarget_ExcludesCurrentHost(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-b", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	v := NewVMChecker("host-a", db, nil)
	target, err := v.pickMigrationTarget(ctx, "host-a", 0)
	if err != nil {
		t.Fatalf("pickMigrationTarget: %v", err)
	}
	if target.Name != "host-b" {
		t.Errorf("expected host-b, got %q", target.Name)
	}
}

func TestPickMigrationTarget_InsufficientMemory_AllConsumed(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-b", State: "active", MemTotal: 4096}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// Consume all memory on host-b.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-hog", HostName: "host-b", State: "running", MemActual: 4096}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("host-a", db, nil)
	_, err := v.pickMigrationTarget(ctx, "host-a", 8192)
	if err == nil {
		t.Fatal("expected error for insufficient memory, got nil")
	}
}

func TestPickMigrationTarget_SkipsInactiveHosts(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-b", State: "offline", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-c", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	v := NewVMChecker("host-a", db, nil)
	target, err := v.pickMigrationTarget(ctx, "host-a", 0)
	if err != nil {
		t.Fatalf("pickMigrationTarget: %v", err)
	}
	if target.Name != "host-c" {
		t.Errorf("expected host-c (skipping offline host-b), got %q", target.Name)
	}
}

func TestMigrateVM_UsesCallback(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Insert hosts.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 32768}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-b", State: "active", MemTotal: 32768}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: &pb.HealthCheckSpec{
		Type:    "tcp",
		Target:  "10.0.0.1:80",
		Action:  "migrate",
		Retries: 1,
	}})

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "migrate-test",
		HostName: "host-a",
		State:    "running",
		Spec:     string(specJSON),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("host-a", db, nil)

	var calledVM, calledTarget string
	v.SetMigrateFunc(func(ctx context.Context, vmName, targetHost string) error {
		calledVM = vmName
		calledTarget = targetHost
		return nil
	})

	vm := corrosion.VMRecord{Name: "migrate-test", HostName: "host-a", State: "running", Spec: string(specJSON)}
	v.migrateVM(ctx, vm)

	if calledVM != "migrate-test" {
		t.Errorf("expected callback vmName=migrate-test, got %q", calledVM)
	}
	if calledTarget != "host-b" {
		t.Errorf("expected callback targetHost=host-b, got %q", calledTarget)
	}
}

func TestMigrateVM_NoCallback_NilVirt(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Insert hosts so pickMigrationTarget succeeds.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 32768}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-b", State: "active", MemTotal: 32768}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "migrate-novirt",
		HostName: "host-a",
		State:    "running",
		Spec:     `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// No migrateVMFunc registered and virt=nil.
	v := NewVMChecker("host-a", db, nil)
	vm := corrosion.VMRecord{Name: "migrate-novirt", HostName: "host-a", State: "running"}

	// Should not crash — logs error and returns early.
	v.migrateVM(ctx, vm)

	// VM should stay in its current state (not changed to "migrating").
	fresh, err := corrosion.GetVM(ctx, db, "migrate-novirt")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if fresh.State != "running" {
		t.Errorf("expected VM state running (unchanged), got %q", fresh.State)
	}
}

func TestMigrateVM_NoTarget(t *testing.T) {
	db := testCheckVMDB(t)
	ctx := context.Background()

	// Only 1 host — no migration target available.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "host-a", State: "active", MemTotal: 8192}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "migrate-notarget",
		HostName: "host-a",
		State:    "running",
		Spec:     `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("host-a", db, nil)
	vm := corrosion.VMRecord{Name: "migrate-notarget", HostName: "host-a", State: "running"}

	v.migrateVM(ctx, vm)

	// VM state should be "error" with detail about no migration target.
	fresh, err := corrosion.GetVM(ctx, db, "migrate-notarget")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if fresh.State != "error" {
		t.Errorf("expected VM state error, got %q", fresh.State)
	}
	if fresh.StateDetail == "" {
		t.Error("expected non-empty state detail")
	}
}
