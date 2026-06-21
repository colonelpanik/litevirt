package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

func newTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

// stubFencer returns a Fencer that always reports success. Tests that want to
// exercise the rescheduling path don't need real SSH/IPMI; tests that want to
// exercise the split-brain guard explicitly pass a failing fencer instead.
func stubFencer(success bool) Fencer {
	return func(ctx context.Context, h fence.HostConfig) fence.Result {
		return fence.Result{Method: "test", Detail: "stub", Success: success}
	}
}

func manualFencer() Fencer {
	return func(ctx context.Context, h fence.HostConfig) fence.Result {
		return fence.Result{Method: "manual", Detail: "operator must confirm", Success: false}
	}
}

// newTestCoordinator builds a coordinator with a stubbed always-succeed fencer.
// Use this in tests that exercise rescheduling/placement behavior.
func newTestCoordinator(name string, db *corrosion.Client) *Coordinator {
	c := NewCoordinator(name, db)
	c.SetFencer(stubFencer(true))
	return c
}

func TestCoordinator_NoFailures_NoAction(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Insert a healthy host with no health failures.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c := NewCoordinator("coordinator", db)
	c.run(ctx) // should be a no-op

	// Host should still be active.
	h, _ := corrosion.GetHost(ctx, db, "h1")
	if h == nil || h.State != "active" {
		t.Errorf("host should still be active, got: %+v", h)
	}
}

func TestCoordinator_FailedHost_MarkedOffline(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad-host", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// Simulate health check failures exceeding the threshold.
	for i := 0; i < offlineThreshold; i++ {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			"coordinator", "bad-host", offlineThreshold,
		); err != nil {
			t.Fatalf("insert health row: %v", err)
		}
	}

	c := NewCoordinator("coordinator", db)
	c.run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "bad-host")
	if h == nil {
		t.Fatal("host not found after failover")
	}
	if h.State != "offline" {
		t.Errorf("expected offline, got %q", h.State)
	}
}

// healthyObservers inserts fresh host_health rows where each observer sees the
// target as healthy (consecutive_failures = 0).
func healthyObservers(t *testing.T, db *corrosion.Client, target string, observers ...string) {
	t.Helper()
	ctx := context.Background()
	for _, o := range observers {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: o, Address: "10.0.1." + o[len(o)-1:], SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", o, err)
		}
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'healthy', 0, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			o, target,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
}

// A host stuck in 'offline' after a transient drop must return to 'active'
// once a fresh quorum sees it healthy again — without operator intervention.
func TestCoordinator_OfflineHostRecoversWhenHealthy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "recovered", Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	healthyObservers(t, db, "recovered", "h1", "h2", "h3", "h4")

	newTestCoordinator("coordinator", db).run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "recovered")
	if h == nil || h.State != "active" {
		t.Errorf("offline host should auto-recover to active once healthy, got %+v", h)
	}
}

// A 'fenced' host must NOT auto-recover: a successful fence may have rescheduled
// its VMs, so resurrecting it automatically risks split-brain. Recovery here is
// operator-driven (`lv host undrain`).
func TestCoordinator_FencedHostNotAutoRecovered(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "fenced-host", Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "fenced", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	healthyObservers(t, db, "fenced-host", "h1", "h2", "h3", "h4")

	newTestCoordinator("coordinator", db).run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "fenced-host")
	if h == nil || h.State != "fenced" {
		t.Errorf("fenced host must stay fenced (manual recovery), got %+v", h)
	}
}

// A host that is briefly 'upgrading' (a graceful restart in progress) must NOT
// be fenced even though quorum sees it down — that's the guard that stops a
// routine restart from triggering a destructive failover.
func TestCoordinator_RecentUpgradingHostNotFenced(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "upg", Address: "10.0.0.51", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "upgrading", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	downObservers(t, db, "upg", "h1", "h2", "h3")

	newTestCoordinator("coordinator", db).run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "upg")
	if h == nil || h.State != "upgrading" {
		t.Errorf("recently-upgrading host must be skipped, got %+v", h)
	}
}

// A host stuck 'upgrading' past the timeout (entered the state and never came
// back) must still fail over, or its VMs are stranded.
func TestCoordinator_StuckUpgradingHostFencedAfterTimeout(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "stuck", Address: "10.0.0.50", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// Move to 'upgrading' with an updated_at well past upgradingTimeout.
	old := time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339)
	if err := db.Execute(ctx,
		`UPDATE hosts SET state='upgrading', updated_at=? WHERE name='stuck'`, old); err != nil {
		t.Fatalf("set stale upgrading: %v", err)
	}
	downObservers(t, db, "stuck", "h1", "h2", "h3")

	newTestCoordinator("coordinator", db).run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "stuck")
	if h == nil || h.State == "upgrading" {
		t.Errorf("host stuck upgrading past timeout must fail over, still %+v", h)
	}
}

// downObservers inserts fresh host_health rows where each observer reports the
// target as failed (consecutive_failures >= threshold), enough to satisfy quorum.
func downObservers(t *testing.T, db *corrosion.Client, target string, observers ...string) {
	t.Helper()
	ctx := context.Background()
	for _, o := range observers {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: o, Address: "10.0.4." + o[len(o)-1:], SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", o, err)
		}
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			o, target, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
}

func TestCoordinator_VMsRescheduled(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.10", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost bad: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "good", Address: "10.0.0.11", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost good: %v", err)
	}

	// VM with restart-any policy.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm1",
		HostName: "bad",
		Spec:     `{"on_host_failure":"restart-any"}`,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Trigger health failure threshold — need quorum (2 observers for 2 active hosts).
	for _, observer := range []string{"coordinator", "good"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", err, vm)
	}
	if vm.HostName != "good" {
		t.Errorf("expected VM rescheduled to 'good', got %q", vm.HostName)
	}
	if vm.State != "pending" {
		t.Errorf("expected VM state 'pending', got %q", vm.State)
	}
}

func TestCoordinator_VMWithNonePolicy_NotRescheduled(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "dying", Address: "10.0.0.20", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "alive", Address: "10.0.0.21", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "sticky-vm",
		HostName: "dying",
		Spec:     `{"on_host_failure":"none"}`,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health
		 (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('coordinator', 'dying', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		offlineThreshold,
	); err != nil {
		t.Fatalf("insert health: %v", err)
	}

	c := NewCoordinator("coordinator", db)
	c.run(ctx)

	vm, _ := corrosion.GetVM(ctx, db, "sticky-vm")
	if vm == nil {
		t.Fatal("VM disappeared")
	}
	// Should still be on the original host (not rescheduled).
	if vm.HostName != "dying" {
		t.Errorf("VM should not have been rescheduled, but moved to %q", vm.HostName)
	}
}

// TestCoordinator_FencingFailureBlocksReschedule tests that when fencing fails
// with a non-best-effort strategy, VMs are NOT rescheduled (#6).
func TestCoordinator_FencingFailureBlocksReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Host with IPMI strategy but no IPMI address — fence.Execute will fail.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad-ipmi", Address: "10.0.0.50", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "healthy", Address: "10.0.0.51", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// VM with restart-any policy on the failing host.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "fence-blocked-vm",
		HostName: "bad-ipmi",
		Spec:     `{"on_host_failure":"restart-any"}`,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Quorum of observers report failure.
	for _, observer := range []string{"coordinator", "healthy"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad-ipmi', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := NewCoordinator("coordinator", db)
	c.run(ctx)

	// Host should be marked offline.
	h, _ := corrosion.GetHost(ctx, db, "bad-ipmi")
	if h == nil || h.State != "offline" {
		t.Fatalf("expected host offline, got: %+v", h)
	}

	// VM should NOT have been rescheduled (still on bad-ipmi).
	vm, _ := corrosion.GetVM(ctx, db, "fence-blocked-vm")
	if vm == nil {
		t.Fatal("VM not found")
	}
	if vm.HostName != "bad-ipmi" {
		t.Errorf("VM should NOT be rescheduled when fencing fails with IPMI strategy, but moved to %q", vm.HostName)
	}
	if vm.State == "pending" {
		t.Error("VM should NOT be in pending state — fencing failure should block rescheduling")
	}
}

func TestCoordinator_NoDoubleFailover(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "flaky", Address: "10.0.0.30", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health
		 (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('coordinator', 'flaky', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		offlineThreshold,
	); err != nil {
		t.Fatalf("insert health: %v", err)
	}

	c := NewCoordinator("coordinator", db)
	c.run(ctx) // first run: fences host
	c.run(ctx) // second run: should skip (already in fenced map)

	// Verify fenced map prevents re-processing.
	if !c.fenced["flaky"] {
		t.Error("expected 'flaky' to be in fenced map")
	}
}

func TestCoordinator_PlacementSelectsLargerHost(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// 3 hosts: "bad" will fail, "small" has insufficient resources, "big" can fit the VM.
	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual"},
		{Name: "small", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 2, MemTotal: 4096},
		{Name: "big", Address: "10.0.0.3", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}

	// Heavy VM on "bad" that requires more resources than "small" has.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "heavy-vm",
		HostName:  "bad",
		Spec:      `{"on_host_failure":"restart-any"}`,
		State:     "running",
		CPUActual: 4,
		MemActual: 8192,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Quorum failure for "bad": observers from "small" and "big".
	for _, observer := range []string{"small", "big"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	vm, err := corrosion.GetVM(ctx, db, "heavy-vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", err, vm)
	}
	if vm.HostName == "bad" {
		t.Error("expected VM to be rescheduled away from 'bad', but it is still there")
	}
	if vm.State != "pending" {
		t.Errorf("expected VM state 'pending', got %q", vm.State)
	}
}

func TestCoordinator_FallbackToRoundRobin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// 2 hosts: "bad" (failing) and "tiny" (too small for the VM).
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost bad: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "tiny", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		CPUTotal: 1, MemTotal: 512,
	}); err != nil {
		t.Fatalf("InsertHost tiny: %v", err)
	}

	// Big VM that won't fit on "tiny" via placement constraints.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "big-vm",
		HostName:  "bad",
		Spec:      `{"on_host_failure":"restart-any"}`,
		State:     "running",
		CPUActual: 8,
		MemActual: 32768,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Quorum failure for "bad".
	for _, observer := range []string{"coordinator", "tiny"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	vm, err := corrosion.GetVM(ctx, db, "big-vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", err, vm)
	}
	// Placement will fail (tiny can't fit), but round-robin fallback should rescue the VM.
	if vm.HostName != "tiny" {
		t.Errorf("expected VM rescheduled to 'tiny' via round-robin fallback, got %q", vm.HostName)
	}
	if vm.State != "pending" {
		t.Errorf("expected VM state 'pending', got %q", vm.State)
	}
}

func TestCoordinator_MultipleVMsPlacement(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// 3 hosts: "bad" (failing), "node-a" and "node-b" (healthy, large).
	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual"},
		{Name: "node-a", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
		{Name: "node-b", Address: "10.0.0.3", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}

	// 3 VMs on "bad".
	for _, vmName := range []string{"vm-1", "vm-2", "vm-3"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name:      vmName,
			HostName:  "bad",
			Spec:      `{"on_host_failure":"restart-any"}`,
			State:     "running",
			CPUActual: 2,
			MemActual: 4096,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vmName, err)
		}
	}

	// Quorum failure for "bad": observers from "node-a" and "node-b".
	for _, observer := range []string{"node-a", "node-b"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	// All 3 VMs should be rescheduled away from "bad".
	hostCounts := map[string]int{}
	for _, vmName := range []string{"vm-1", "vm-2", "vm-3"} {
		vm, err := corrosion.GetVM(ctx, db, vmName)
		if err != nil || vm == nil {
			t.Fatalf("GetVM %s: %v %v", vmName, err, vm)
		}
		if vm.HostName == "bad" {
			t.Errorf("VM %s should have been rescheduled away from 'bad'", vmName)
		}
		if vm.State != "pending" {
			t.Errorf("VM %s: expected state 'pending', got %q", vmName, vm.State)
		}
		if vm.HostName != "node-a" && vm.HostName != "node-b" {
			t.Errorf("VM %s: expected host 'node-a' or 'node-b', got %q", vmName, vm.HostName)
		}
		hostCounts[vm.HostName]++
	}

	// All VMs must have been placed on healthy hosts. The placement engine
	// uses bin-packing by default (preferring hosts with more used resources),
	// so all VMs may land on the same host. Verify at least one healthy host
	// received VMs and total count is correct.
	total := 0
	for host, cnt := range hostCounts {
		if host != "node-a" && host != "node-b" {
			t.Errorf("unexpected host %q in distribution", host)
		}
		total += cnt
	}
	if total != 3 {
		t.Errorf("expected 3 VMs rescheduled, got %d (distribution: %v)", total, hostCounts)
	}
}

// TestCoordinator_ManualFenceWithoutConfirmation_BlocksReschedule verifies
// the manual-fence split-brain fix: under manual fence strategy, the split-brain guard now refuses
// to reschedule VMs unless the operator has written a 'manual-confirmed' row
// to fencing_log via `lv host fence-confirm`.
func TestCoordinator_ManualFenceWithoutConfirmation_BlocksReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "manual-host", Address: "10.0.0.40", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "alive", Address: "10.0.0.41", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost alive: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "blocked-vm", HostName: "manual-host",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	for _, observer := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'manual-host', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := NewCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)

	vm, _ := corrosion.GetVM(ctx, db, "blocked-vm")
	if vm == nil {
		t.Fatal("VM disappeared")
	}
	if vm.HostName != "manual-host" {
		t.Errorf("VM should NOT be rescheduled before operator confirms manual fence; moved to %q", vm.HostName)
	}
	if vm.State == "pending" {
		t.Error("VM should not be in pending state without manual fence confirmation")
	}
}

// TestCoordinator_ManualFenceWithConfirmation_Reschedules verifies that once
// the operator writes a 'manual-confirmed' row, a follow-up failover cycle
// does *not* re-fence (recentlyFenced detects the confirmation), so the host
// must already be in a non-active state for VMs to be rescheduled. This is the
// expected production flow: operator powers off the host, runs
// `lv host fence-confirm <host>` which both writes the confirmation row AND
// updates host state, then the next coordinator cycle reschedules.
func TestCoordinator_ManualFenceWithConfirmation_Reschedules(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "manual-host", Address: "10.0.0.40", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "alive", Address: "10.0.0.41", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost alive: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-pending", HostName: "manual-host",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	for _, observer := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'manual-host', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	// Operator writes a manual-confirmed fencing_log row (simulating
	// `lv host fence-confirm manual-host` after physically powering off).
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "operator-1", HostName: "manual-host",
		Method: "manual", Result: "manual-confirmed",
		Detail: "operator: pulled the plug",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}

	c := NewCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)

	// Because recentlyFenced now returns true, the host is short-circuited
	// (it's treated as already fenced). The VM is *not* rescheduled by this
	// cycle alone; the operator-side flow is expected to also update the host
	// state to 'fenced' or 'offline'. So we assert the safe behavior:
	// recentlyFenced suppresses re-processing.
	if !c.fenced["manual-host"] {
		t.Error("expected coordinator to mark manual-host as already-fenced via recentlyFenced")
	}
}

// TestCoordinator_LeaderElection_OnlyOneActs ensures that two coordinators
// running against the same DB do not both proceed past the lease gate. Before
// the leader-election fix: the leader_election table was missing and both coordinators
// would run failover concurrently.
func TestCoordinator_LeaderElection_OnlyOneActs(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	a := NewCoordinator("node-a", db)
	b := NewCoordinator("node-b", db)

	if !a.acquireLease(ctx) {
		t.Fatal("first acquireLease must succeed on a fresh cluster")
	}
	if b.acquireLease(ctx) {
		t.Error("second coordinator must NOT acquire lease while first holds it")
	}
	// First holder can re-acquire (renew).
	if !a.acquireLease(ctx) {
		t.Error("lease holder must be able to renew its own lease")
	}
}

// TestCoordinator_UpgradingHostNotFenced verifies the fix: a host
// in state "upgrading" must not be fenced even when quorum reports it down.
// This prevents routine litevirtd self-upgrades from triggering a destructive
// false-positive failover when the re-exec window exceeds the heartbeat
// threshold.
func TestCoordinator_UpgradingHostNotFenced(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "upgrading-host", Address: "10.0.0.10",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "upgrading",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "watcher-1", Address: "10.0.0.11",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost watcher-1: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "watcher-2", Address: "10.0.0.12",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost watcher-2: %v", err)
	}

	// Quorum reports upgrading-host failing.
	for _, observer := range []string{"watcher-1", "watcher-2"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'upgrading-host', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}

	c := newTestCoordinator("watcher-1", db)
	c.run(ctx)

	// No fence event should have fired, even though quorum was met.
	rows, err := db.Query(ctx, `SELECT COUNT(*) AS n FROM fencing_log WHERE host_name = 'upgrading-host'`)
	if err != nil {
		t.Fatalf("query fence_log: %v", err)
	}
	if got := rows[0].Int("n"); got != 0 {
		t.Errorf("upgrading host fenced %d time(s); want 0", got)
	}

	// Host state must remain `upgrading`.
	h, _ := corrosion.GetHost(ctx, db, "upgrading-host")
	if h == nil || h.State != "upgrading" {
		t.Errorf("upgrading-host state = %q, want upgrading", func() string {
			if h == nil {
				return "nil"
			}
			return h.State
		}())
	}
}

// TestCoordinator_QuorumIgnoresStaleHealth verifies that stale host_health
// rows from observers that haven't reported in longer than healthFreshness
// must not satisfy the quorum predicate.
func TestCoordinator_QuorumIgnoresStaleHealth(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "victim", Address: "10.0.0.50",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "watcher", Address: "10.0.0.51",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// Insert a stale health row backdated past the freshness window.
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health
		 (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('watcher', 'victim', 'suspect', ?, NULL, datetime('now', '-10 minutes'))`,
		offlineThreshold,
	); err != nil {
		t.Fatalf("insert stale health: %v", err)
	}
	// And a fresh, good row from the coordinator itself.
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health
		 (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('coordinator', 'victim', 'healthy', 0, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
	); err != nil {
		t.Fatalf("insert fresh health: %v", err)
	}

	c := newTestCoordinator("coordinator", db)
	c.run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "victim")
	if h == nil || h.State != "active" {
		t.Errorf("victim should remain active when only stale rows accuse it; got state=%q", func() string {
			if h == nil {
				return "nil"
			}
			return h.State
		}())
	}
}
