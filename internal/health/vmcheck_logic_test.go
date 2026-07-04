package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

func testLogicDB(t *testing.T) *corrosion.Client {
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

// ── safeAttemptCount ────────────────────────────────────────────────────────

func TestSafeAttemptCount_Nil(t *testing.T) {
	if safeAttemptCount(nil) != 0 {
		t.Error("expected 0 for nil RestartState")
	}
}

func TestSafeAttemptCount_NonNil(t *testing.T) {
	rs := &corrosion.RestartState{AttemptCount: 5}
	if safeAttemptCount(rs) != 5 {
		t.Errorf("expected 5, got %d", safeAttemptCount(rs))
	}
}

// ── publish ─────────────────────────────────────────────────────────────────

func TestPublish_NilBus(t *testing.T) {
	v := &VMChecker{}
	// Should not panic with nil bus.
	v.publish("vm.health.failed", "vm1", "test")
}

func TestPublish_WithBus(t *testing.T) {
	bus := events.NewBus()
	v := &VMChecker{bus: bus}

	ch, unsub := bus.Subscribe()
	defer unsub()
	v.publish("vm.health.failed", "vm1", "probe failed")

	select {
	case evt := <-ch:
		if evt.Action != "vm.health.failed" {
			t.Errorf("action = %q, want vm.health.failed", evt.Action)
		}
		if evt.Target != "vm1" {
			t.Errorf("target = %q, want vm1", evt.Target)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestSetEventBus(t *testing.T) {
	v := &VMChecker{}
	bus := events.NewBus()
	v.SetEventBus(bus)
	if v.bus != bus {
		t.Error("bus not set")
	}
}

func TestSetMigrateFunc(t *testing.T) {
	v := &VMChecker{}
	called := false
	v.SetMigrateFunc(func(ctx context.Context, vmName, targetHost string) error {
		called = true
		return nil
	})
	if v.migrateVMFunc == nil {
		t.Fatal("migrateVMFunc not set")
	}
	_ = v.migrateVMFunc(context.Background(), "vm1", "node2")
	if !called {
		t.Error("callback not invoked")
	}
}

// ── takeAction: split-brain gate ────────────────────────────────────────────

// A health-check "restart"/"migrate" is an automated runtime action: once enforced
// it requires local quorum (ExecutionGate). An isolated host (no quorum) must not
// restart-in-place or migrate a failing VM.
func TestTakeAction_GatedWithoutQuorum(t *testing.T) {
	for _, action := range []string{"restart", "migrate"} {
		t.Run(action, func(t *testing.T) {
			db := testLogicDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node1", Spec: `{}`, State: "running",
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}

			var refused []string
			v := NewVMChecker("node1", db, nil)
			// Enforced (latched) but ExecutionGate refuses (no quorum).
			v.SetGate(fakeGate{exec: GateResult{OK: false, Reason: ReasonNoQuorum}, active: true})
			v.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

			vm := corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "running"}
			v.takeAction(ctx, vm, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: action})

			if len(refused) != 1 || refused[0] != ReasonNoQuorum {
				t.Fatalf("refusal=%v; want [no_quorum]", refused)
			}
			fresh, _ := corrosion.GetVM(ctx, db, "vm1")
			if fresh.State != "running" {
				t.Fatalf("vm state=%q; want running (action refused, no runtime change)", fresh.State)
			}
		})
	}
}

// "alert" is a notification, not a runtime action — it is NOT gated and still fires
// even without quorum.
func TestTakeAction_AlertNotGated(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: `{}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	var refused []string
	v := NewVMChecker("node1", db, nil)
	v.SetGate(fakeGate{exec: GateResult{OK: false, Reason: ReasonNoQuorum}, active: true})
	v.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	vm := corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "running"}
	v.takeAction(ctx, vm, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "alert"})

	if len(refused) != 0 {
		t.Fatalf("alert must not be gated; refusals=%v", refused)
	}
}

// A health action is DROPPED if ownership moved off this host between the queued
// async probe and now — no destroy/start of a stale local domain, no migrate with a
// stale source (the check precedes the gate and acts on the fresh owner).
func TestTakeAction_DroppedWhenOwnershipMoved(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	// The current row shows the VM owned by node2 (moved since the probe was queued).
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node2", Spec: `{}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	v := NewVMChecker("node1", db, nil) // this host is node1
	v.SetEventBus(bus)

	// The queued snapshot still claims node1 (stale).
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "running"}
	v.takeAction(ctx, vm, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "restart"})

	// The ownership check returns BEFORE the "vm.health.failed" publish — so no action
	// event is emitted, and the row is untouched.
	select {
	case evt := <-ch:
		t.Fatalf("expected no action event (VM moved off host); got %q", evt.Action)
	case <-time.After(100 * time.Millisecond):
	}
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	if fresh.HostName != "node2" || fresh.State != "running" {
		t.Fatalf("row mutated: host=%q state=%q; want node2/running (action dropped)", fresh.HostName, fresh.State)
	}
}

// ── takeAction: suppressed by correlated failures ───────────────────────────

func TestTakeAction_SuppressedByCorrelatedFailures(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-supp", HostName: "node1", Spec: `{}`, State: "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	v := NewVMChecker("node1", db, nil)
	v.SetEventBus(bus)

	// Seed correlated failures (3 VMs with >=2 failures).
	v.mu.Lock()
	v.failures["a"] = 5
	v.failures["b"] = 3
	v.failures["c"] = 2
	v.mu.Unlock()

	vm := corrosion.VMRecord{Name: "vm-supp", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "restart"}

	v.takeAction(ctx, vm, hspec)

	// Should emit suppressed event, not restarted.
	select {
	case evt := <-ch:
		if evt.Action != "vm.health.suppressed" {
			t.Errorf("action = %q, want vm.health.suppressed", evt.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for suppressed event")
	}
}

// ── takeAction: operator-stopped VM skipped ─────────────────────────────────

func TestTakeAction_OperatorStoppedSkipped(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	// Insert a VM that was operator-stopped between probe and action.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-op-stop", HostName: "node1", Spec: `{}`,
		State: "stopped", StateDetail: "operator-stop",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-op-stop", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "restart"}

	// Should not panic or attempt restart (virt is nil).
	v.takeAction(ctx, vm, hspec)

	// VM should remain stopped (not changed to running or error).
	fresh, _ := corrosion.GetVM(ctx, db, "vm-op-stop")
	if fresh.State != "stopped" {
		t.Errorf("state = %q, want stopped", fresh.State)
	}
}

// ── takeAction: VM state changed since probe ────────────────────────────────

func TestTakeAction_VMStateChanged(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	// VM is now "migrating" (state changed between probe and action).
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-migrated", HostName: "node1", Spec: `{}`, State: "migrating",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-migrated", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "restart"}

	// Should skip action because fresh state != "running".
	v.takeAction(ctx, vm, hspec)

	fresh, _ := corrosion.GetVM(ctx, db, "vm-migrated")
	if fresh.State != "migrating" {
		t.Errorf("state = %q, want migrating (unchanged)", fresh.State)
	}
}

// ── takeAction: VM deleted between probe and action ─────────────────────────

func TestTakeAction_VMDeleted(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	v := NewVMChecker("node1", db, nil)
	// VM doesn't exist in DB — GetVM returns nil.
	vm := corrosion.VMRecord{Name: "ghost-vm", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Action: "restart"}

	// Should not panic.
	v.takeAction(ctx, vm, hspec)
}

// ── takeAction: alert action ────────────────────────────────────────────────

func TestTakeAction_Alert(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-alert", HostName: "node1", Spec: `{}`, State: "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	v := NewVMChecker("node1", db, nil)
	v.SetEventBus(bus)

	vm := corrosion.VMRecord{Name: "vm-alert", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "http", Target: "http://10.0.0.1/health", Action: "alert"}

	v.takeAction(ctx, vm, hspec)

	// takeAction publishes "vm.health.failed" first, then "vm.health.alert".
	foundAlert := false
	for i := 0; i < 3; i++ {
		select {
		case evt := <-ch:
			if evt.Action == "vm.health.alert" {
				foundAlert = true
			}
		case <-time.After(time.Second):
		}
		if foundAlert {
			break
		}
	}
	if !foundAlert {
		t.Error("expected vm.health.alert event")
	}
}

// ── takeAction: unknown action ──────────────────────────────────────────────

func TestTakeAction_UnknownAction_NoOp(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-unknown-act", HostName: "node1", Spec: `{}`, State: "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-unknown-act", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "reboot-host"}

	// Should not panic on unknown action.
	v.takeAction(ctx, vm, hspec)
}

// ── takeAction: default action is restart ───────────────────────────────────

func TestTakeAction_DefaultActionIsRestart(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-default-act", HostName: "node1", Spec: `{}`, State: "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	v := NewVMChecker("node1", db, nil)
	v.SetEventBus(bus)

	vm := corrosion.VMRecord{Name: "vm-default-act", HostName: "node1", State: "running"}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: ""} // empty = restart

	v.takeAction(ctx, vm, hspec)

	// With nil virt, restart returns early after publishing the event.
	select {
	case evt := <-ch:
		if evt.Action != "vm.health.failed" {
			t.Errorf("action = %q, want vm.health.failed", evt.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// ── takeAction: migrate action with nil virt and nil callback ───────────────

func TestTakeAction_Migrate_NilVirtAndCallback(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	// Insert VM and a target host.
	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 8192},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-migrate", HostName: "node1", Spec: `{}`, State: "running", MemActual: 1024,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil) // nil virt, nil migrateVMFunc
	vm := corrosion.VMRecord{Name: "vm-migrate", HostName: "node1", State: "running", MemActual: 1024}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "migrate"}

	// Should not panic — migrateVM logs error when both virt and callback are nil.
	v.takeAction(ctx, vm, hspec)
}

// ── takeAction: migrate with callback ───────────────────────────────────────

func TestTakeAction_Migrate_WithCallback(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 8192},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-migrate-cb", HostName: "node1", Spec: `{}`, State: "running", MemActual: 1024,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	var migratedTo string
	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	v := NewVMChecker("node1", db, nil)
	v.SetEventBus(bus)
	v.SetMigrateFunc(func(ctx context.Context, vmName, targetHost string) error {
		migratedTo = targetHost
		return nil
	})

	vm := corrosion.VMRecord{Name: "vm-migrate-cb", HostName: "node1", State: "running", MemActual: 1024}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.1:80", Action: "migrate"}

	v.takeAction(ctx, vm, hspec)

	if migratedTo != "node2" {
		t.Errorf("migrated to %q, want node2", migratedTo)
	}

	select {
	case evt := <-ch:
		if evt.Action != "vm.health.failed" {
			// First event is "vm.health.failed", then "vm.health.migrated".
			// Drain to find the migrated event.
			select {
			case evt = <-ch:
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for migrated event")
			}
		}
		// Accept either event as proof the action ran.
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// ── maybeRestartVM: restart policies ────────────────────────────────────────

func TestMaybeRestartVM_NoSpec(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-norestart", HostName: "node1", Spec: `{}`, State: "stopped",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-norestart", HostName: "node1", State: "stopped"}
	// Should not restart — no restart policy.
	v.maybeRestartVM(ctx, vm, time.Now())

	fresh, _ := corrosion.GetVM(ctx, db, "vm-norestart")
	if fresh.State != "stopped" {
		t.Errorf("state = %q, want stopped", fresh.State)
	}
}

func TestMaybeRestartVM_ConditionNone(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "none"}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-cond-none", HostName: "node1", Spec: string(specJSON), State: "stopped",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-cond-none", HostName: "node1", State: "stopped"}
	v.maybeRestartVM(ctx, vm, time.Now())

	fresh, _ := corrosion.GetVM(ctx, db, "vm-cond-none")
	if fresh.State != "stopped" {
		t.Errorf("state = %q, want stopped (condition=none)", fresh.State)
	}
}

func TestMaybeRestartVM_ConditionEmpty(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: ""}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-cond-empty", HostName: "node1", Spec: string(specJSON), State: "error",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-cond-empty", HostName: "node1", State: "error"}
	v.maybeRestartVM(ctx, vm, time.Now())

	fresh, _ := corrosion.GetVM(ctx, db, "vm-cond-empty")
	if fresh.State != "error" {
		t.Errorf("state = %q, want error (condition=empty treated as none)", fresh.State)
	}
}

func TestMaybeRestartVM_OnFailure_StoppedVM(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "on-failure"}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-onfail-stop", HostName: "node1", Spec: string(specJSON), State: "stopped",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-onfail-stop", HostName: "node1", State: "stopped"}
	v.maybeRestartVM(ctx, vm, time.Now())

	fresh, _ := corrosion.GetVM(ctx, db, "vm-onfail-stop")
	if fresh.State != "stopped" {
		t.Errorf("state = %q, want stopped (on-failure doesn't restart clean stop)", fresh.State)
	}
}

func TestMaybeRestartVM_OnFailure_ErrorVM(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "on-failure", Delay: "0s"}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-onfail-err", HostName: "node1", Spec: string(specJSON), State: "error",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	// state_detail=crashed is the failure evidence the reconciler persists; with
	// libvirt unreachable (nil virt) the decision falls back to it.
	vm := corrosion.VMRecord{Name: "vm-onfail-err", HostName: "node1", State: "error", StateDetail: crashedDetail}
	v.maybeRestartVM(ctx, vm, time.Now())

	// With nil virt, the restart path calls IncrementRestart then returns early.
	// Verify the restart counter was incremented.
	rs, err := corrosion.GetRestartState(ctx, db, "vm-onfail-err")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if rs == nil || rs.AttemptCount != 1 {
		t.Errorf("expected 1 restart attempt, got %v", rs)
	}
}

func TestMaybeRestartVM_MaxAttempts(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{
		Condition:   "always",
		MaxAttempts: 2,
		Window:      "1h",
		Delay:       "0s",
	}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-maxatt", HostName: "node1", Spec: string(specJSON), State: "error",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-maxatt", HostName: "node1", State: "error", StateDetail: crashedDetail}

	// Restart twice (hitting max_attempts=2).
	v.maybeRestartVM(ctx, vm, time.Now())
	v.maybeRestartVM(ctx, vm, time.Now())

	// Third attempt should be blocked.
	v.maybeRestartVM(ctx, vm, time.Now())

	rs, _ := corrosion.GetRestartState(ctx, db, "vm-maxatt")
	if rs.AttemptCount != 2 {
		t.Errorf("attempts = %d, want 2 (max_attempts should block third)", rs.AttemptCount)
	}
}

func TestMaybeRestartVM_WindowReset(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{
		Condition:   "always",
		MaxAttempts: 1,
		Window:      "1ms", // Very short window.
		Delay:       "0s",
	}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-winreset", HostName: "node1", Spec: string(specJSON), State: "error",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-winreset", HostName: "node1", State: "error", StateDetail: crashedDetail}

	// First restart.
	v.maybeRestartVM(ctx, vm, time.Now())

	// Wait for window to expire.
	time.Sleep(5 * time.Millisecond)

	// Second restart should succeed because window expired and counter reset.
	v.maybeRestartVM(ctx, vm, time.Now())

	rs, _ := corrosion.GetRestartState(ctx, db, "vm-winreset")
	// After reset + one new restart, count should be 1.
	if rs.AttemptCount != 1 {
		t.Errorf("attempts = %d after window reset, want 1", rs.AttemptCount)
	}
}

func TestMaybeRestartVM_DelayEnforced(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{
		Condition: "always",
		Delay:     "1h", // Very long delay.
	}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-delay", HostName: "node1", Spec: string(specJSON), State: "error",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-delay", HostName: "node1", State: "error", StateDetail: crashedDetail}

	// First restart happens.
	v.maybeRestartVM(ctx, vm, time.Now())

	rs1, _ := corrosion.GetRestartState(ctx, db, "vm-delay")
	if rs1 == nil || rs1.AttemptCount != 1 {
		t.Fatalf("first restart didn't happen: %v", rs1)
	}

	// Second restart should be blocked by 1h delay.
	v.maybeRestartVM(ctx, vm, time.Now())

	rs2, _ := corrosion.GetRestartState(ctx, db, "vm-delay")
	if rs2.AttemptCount != 1 {
		t.Errorf("attempts = %d, want 1 (delay should block second restart)", rs2.AttemptCount)
	}
}

func TestMaybeRestartVM_OperatorStop(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "always", Delay: "0s"}}
	specJSON, _ := json.Marshal(spec)

	// VM was operator-stopped — this is checked in sweep(), not maybeRestartVM.
	// The sweep filters out operator-stop before calling maybeRestartVM.
	// But we test that maybeRestartVM itself doesn't crash on operator-stopped VMs.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-op-stopped", HostName: "node1", Spec: string(specJSON),
		State: "stopped", StateDetail: "operator-stop",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-op-stopped", HostName: "node1",
		State: "stopped", StateDetail: "operator-stop"}

	// Sweep would skip this, but let's verify maybeRestartVM doesn't crash.
	// It will try to restart since it doesn't check StateDetail itself.
	v.maybeRestartVM(ctx, vm, time.Now())
}

// ── sweep: grace period ─────────────────────────────────────────────────────

func TestSweep_GracePeriod(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	// Insert a running VM created just now with a healthcheck.
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "127.0.0.1:1", Retries: 1}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "vm-fresh",
		HostName:  "node1",
		Spec:      string(specJSON),
		State:     "running",
		CreatedAt: time.Now().Format(time.RFC3339),
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// VM was created < 5 minutes ago — should be skipped entirely.
	v.mu.Lock()
	f := v.failures["vm-fresh"]
	v.mu.Unlock()

	if f != 0 {
		t.Errorf("failures = %d, want 0 (grace period should skip check)", f)
	}
}

// ── sweep: second pass restart policy ───────────────────────────────────────

func TestSweep_SecondPass_SkipsOperatorStop(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "always", Delay: "0s"}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-sweep-opstop", HostName: "node1", Spec: string(specJSON),
		State: "stopped", StateDetail: "operator-stop",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// Should not have restarted — operator-stop is filtered in sweep's second pass.
	rs, _ := corrosion.GetRestartState(ctx, db, "vm-sweep-opstop")
	if rs != nil && rs.AttemptCount > 0 {
		t.Errorf("operator-stopped VM was restarted: attempts=%d", rs.AttemptCount)
	}
}

func TestSweep_SecondPass_RestartsErrorVM(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()

	spec := &pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "on-failure", Delay: "0s"}}
	specJSON, _ := json.Marshal(spec)

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-sweep-err", HostName: "node1", Spec: string(specJSON),
		State: "error", StateDetail: crashedDetail,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	v.sweep(ctx)

	// With nil virt, restart increments counter but can't actually start domain.
	rs, _ := corrosion.GetRestartState(ctx, db, "vm-sweep-err")
	if rs == nil || rs.AttemptCount < 1 {
		t.Errorf("error VM should have been restarted by sweep's second pass")
	}
}
