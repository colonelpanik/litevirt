package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ownerAssertFixture: self=node-a runs vm1 locally, but the DB row says node-b.
// Active hosts: node-a (self), node-b, node-c. The clock is controllable for the
// debounce.
func ownerAssertFixture(t *testing.T) (*Reconciler, *corrosion.Client, *libvirtfake.Fake, *time.Time, map[string]string) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	for i, h := range []string{"node-a", "node-b", "node-c"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + string(rune('1'+i)), State: "active",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return clock }
	results := map[string]string{}
	r.SetOwnerAssertObserver(func(vm, res string) { results[vm] = res })
	return r, db, fake, &clock, results
}

func ownerOf(t *testing.T, db *corrosion.Client, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): %v", name, err)
	}
	return vm.HostName
}

// All other active hosts report ABSENT → after the debounce, reclaim ownership.
func TestOwnerAssert_AllAbsentReclaims(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	r.SetPeerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })

	// First pass: debounce not yet elapsed → no action.
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("must not reclaim before the debounce elapses")
	}
	if results["vm1"] != "" {
		t.Fatalf("no decision expected on the first pass, got %q", results["vm1"])
	}

	// Advance past the debounce → reclaim.
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-a" {
		t.Fatalf("must reclaim ownership to node-a, got %s", ownerOf(t, db, "vm1"))
	}
	if results["vm1"] != "asserted" {
		t.Fatalf("result = %q, want asserted", results["vm1"])
	}
	if n := auditCount(t, db, "vm.runtime-owner-assert"); n != 1 {
		t.Fatalf("want 1 owner-assert audit row, got %d", n)
	}
}

// Another host reports RUNNING → true split-brain → never reclaim; alert only.
func TestOwnerAssert_SplitBrainRefuses(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeRunning, nil
		}
		return RuntimeAbsent, nil
	})
	r.assertRuntimeOwnership(ctx) // seed the debounce
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("split-brain must NOT change ownership")
	}
	if results["vm1"] != "split_brain" {
		t.Fatalf("result = %q, want split_brain", results["vm1"])
	}
}

// A peer is unreachable → inconclusive → no action (retry later).
func TestOwnerAssert_UnreachableInconclusive(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-c" {
			return "", context.DeadlineExceeded
		}
		return RuntimeAbsent, nil
	})
	r.assertRuntimeOwnership(ctx) // seed the debounce
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("an unreachable peer must block the reclaim")
	}
	if results["vm1"] != "inconclusive" {
		t.Fatalf("result = %q, want inconclusive", results["vm1"])
	}
}

// A peer with a stale defined-stopped leftover also blocks the reclaim.
func TestOwnerAssert_DefinedStoppedBlocks(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeDefinedStopped, nil
		}
		return RuntimeAbsent, nil
	})
	r.assertRuntimeOwnership(ctx) // seed the debounce
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("a peer's defined-stopped leftover must block the reclaim")
	}
	if results["vm1"] != "inconclusive" {
		t.Fatalf("result = %q, want inconclusive", results["vm1"])
	}
}

// A VM mid-migration (or under an active lock) is never touched.
func TestOwnerAssert_SkipsInFlightOps(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, _ := ownerAssertFixture(t)
	queried := false
	r.SetPeerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { queried = true; return RuntimeAbsent, nil })
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)

	// (a) migrating state → skip.
	if err := corrosion.UpdateVMState(ctx, db, "vm1", "migrating", "→ node-a"); err != nil {
		t.Fatalf("UpdateVMState: %v", err)
	}
	r.assertRuntimeOwnership(ctx)
	if queried || ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("a migrating VM must not be queried or reclaimed")
	}

	// (b) back to running but an active lock is held → skip.
	if err := corrosion.UpdateVMState(ctx, db, "vm1", "running", ""); err != nil {
		t.Fatalf("UpdateVMState: %v", err)
	}
	if err := db.Execute(ctx, `INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES (?,?,?,?)`,
		"vm1", "node-b", "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	r.assertRuntimeOwnership(ctx)
	if queried || ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("a locked VM must not be queried or reclaimed")
	}
}

// An ACTIVE WITNESS is excluded from corroboration — it never hosts VMs and may
// have no libvirt (its CheckVMRuntime answers "unknown"), so it must not block a
// reclaim when all worker peers are absent.
func TestOwnerAssert_WitnessExcluded(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	if err := corrosion.UpdateHostRole(ctx, db, "node-c", "witness"); err != nil {
		t.Fatalf("UpdateHostRole: %v", err)
	}
	queriedC := false
	r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-c" {
			queriedC = true
			return RuntimeUnknown, nil // witness has no libvirt — would block if queried
		}
		return RuntimeAbsent, nil
	})
	r.assertRuntimeOwnership(ctx) // seed the debounce
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)

	if queriedC {
		t.Fatal("the witness node-c must NOT be probed")
	}
	if ownerOf(t, db, "vm1") != "node-a" {
		t.Fatalf("must reclaim with only the worker peer absent, got %s", ownerOf(t, db, "vm1"))
	}
	if results["vm1"] != "asserted" {
		t.Fatalf("result = %q, want asserted", results["vm1"])
	}
}

// A peer probe that hangs must be bounded — the reconciler returns promptly with
// "inconclusive" rather than wedging on the long-lived daemon context.
func TestOwnerAssert_ProbeTimeoutBounded(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)

	saved := peerRuntimeProbeTimeout
	peerRuntimeProbeTimeout = 50 * time.Millisecond
	defer func() { peerRuntimeProbeTimeout = saved }()

	// A checker that hangs until ITS context is cancelled (the per-probe timeout).
	r.SetPeerRuntimeChecker(func(c context.Context, _, _ string) (string, error) {
		<-c.Done()
		return "", c.Err()
	})
	r.assertRuntimeOwnership(ctx) // seed the debounce
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)

	start := time.Now()
	r.assertRuntimeOwnership(ctx)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("owner-assert did not bound the hung probes (took %s)", elapsed)
	}
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("must not reclaim when probes time out")
	}
	if results["vm1"] != "inconclusive" {
		t.Fatalf("result = %q, want inconclusive", results["vm1"])
	}
}

// A WITNESS local host must NEVER claim a workload to itself, even if it somehow
// runs a domain and all workers are absent (the witness invariant).
func TestOwnerAssert_LocalWitnessStandsDown(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	if err := corrosion.UpdateHostRole(ctx, db, "node-a", "witness"); err != nil {
		t.Fatalf("UpdateHostRole: %v", err)
	}
	r.SetPeerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	r.assertRuntimeOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("a witness local host must not claim ownership")
	}
	if results["vm1"] != "" {
		t.Fatalf("a witness must not even reach a decision, got %q", results["vm1"])
	}
}

// A peer that is UPGRADING (or draining) can still be running the VM — it must be
// probed, and if it reports running the result is split-brain, not a wrongful
// reclaim. Regression for "only active peers were probed".
func TestOwnerAssert_UpgradingPeerRunningIsSplitBrain(t *testing.T) {
	ctx := context.Background()
	r, db, _, clock, results := ownerAssertFixture(t)
	if err := corrosion.UpdateHostState(ctx, db, "node-b", "upgrading"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeRunning, nil // still running the VM mid-upgrade
		}
		return RuntimeAbsent, nil
	})
	r.assertRuntimeOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	r.assertRuntimeOwnership(ctx)
	if ownerOf(t, db, "vm1") != "node-b" {
		t.Fatal("an upgrading peer still running the VM must NOT be skipped → no reclaim")
	}
	if results["vm1"] != "split_brain" {
		t.Fatalf("result = %q, want split_brain (upgrading peer reported running)", results["vm1"])
	}
}

func auditCount(t *testing.T, db *corrosion.Client, action string) int {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM audit_log WHERE action = ?`, action)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Int("n")
}
