package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// seedLease writes the failover lease with an explicit holder and expiry.
func seedLease(t *testing.T, db *corrosion.Client, holder string, expiresAt time.Time) {
	t.Helper()
	exp := expiresAt.UTC().Format(time.RFC3339)
	if err := db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		holder, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
	seedHandoffTerm(t, db, holder)
}

// seedHandoffTerm records the new holder's fencing term, which a real handoff
// writes in the SAME transaction as the election row above.
//
// A lease never changes hands by moving leader_election alone:
// AcquireLeaseWithTerm takes the row and mints the new holder's term
// atomically. Seeding only the election row builds a state a cluster cannot
// reach — the successor holds the lease while the newest recorded term still
// names its PREDECESSOR — and that is exactly the shape AcquireLeaseWithTerm
// refuses, classifying the successor as a superseded holder and returning
// held=false. The coordinator's run() then bails before it reaches the resume
// path, and the workloads this file asserts get recovered stay on the fenced
// host instead.
//
// The term ledger arrives with the lease-term branch. On a build without it
// there is no term to mint and no such state to model, so this is a no-op
// rather than a failure — the fixture has to be honest on both sides of that
// merge, because the tests it feeds live here and the table lives there.
func seedHandoffTerm(t *testing.T, db *corrosion.Client, holder string) {
	t.Helper()
	ctx := context.Background()
	present, err := db.Query(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'leader_lease_terms'`)
	if err != nil {
		t.Fatalf("look up the lease-term ledger: %v", err)
	}
	if len(present) == 0 {
		return
	}
	rows, err := db.Query(ctx,
		`SELECT MAX(term) AS term FROM leader_lease_terms WHERE key = 'failover'`)
	if err != nil {
		t.Fatalf("read the newest lease term: %v", err)
	}
	// One above the highest term on record, which is what a real mint allocates.
	var next int64 = 1
	if len(rows) > 0 {
		next = rows[0].Int64("term") + 1
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT OR IGNORE INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES ('failover', ?, ?, ?, ?, ?)`,
		next, holder, ts, ts, db.NowTS()); err != nil {
		t.Fatalf("mint the handoff term: %v", err)
	}
}

func leaseHolder(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT holder FROM leader_election WHERE key = 'failover'`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	return rows[0].String("holder")
}

func fenceLogCount(t *testing.T, db *corrosion.Client, host string) int {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT id FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		t.Fatalf("read fencing_log: %v", err)
	}
	return len(rows)
}

// TestHoldLeaseAtLeast_RenewsWhenShortOfNeed pins why holdLeaseAtLeast exists.
//
// holdLease returns true whenever more than leaseRenewBefore remains, WITHOUT
// renewing — so its floor is leaseRenewBefore (10s), which is less than an IPMI
// power-off verification takes. A caller that treats that true as "I have the
// lease for a while" can run past expiry. holdLeaseAtLeast must renew to reach
// the head-room the caller actually asked for.
func TestHoldLeaseAtLeast_RenewsWhenShortOfNeed(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }

	// Ours, but only 12s left: more than leaseRenewBefore (so plain holdLease
	// would say yes and not renew) yet short of minFenceLease.
	seedLease(t, db, "me", now.Add(12*time.Second))
	if 12*time.Second <= leaseRenewBefore || 12*time.Second >= minFenceLease {
		t.Fatalf("test fixture no longer sits between leaseRenewBefore (%s) and minFenceLease (%s)",
			leaseRenewBefore, minFenceLease)
	}

	remaining, ok := c.holdLeaseAtLeast(context.Background(), minFenceLease)
	if !ok {
		t.Fatal("holdLeaseAtLeast refused a lease it could have renewed")
	}
	if remaining < minFenceLease {
		t.Errorf("remaining = %s, want at least minFenceLease %s — it reported head-room it does not have",
			remaining, minFenceLease)
	}
}

// TestHoldLeaseAtLeast_RefusesForeignLease pins that head-room never overrides
// ownership: refusing to start is the safe direction.
func TestHoldLeaseAtLeast_RefusesForeignLease(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "other", now.Add(time.Hour))

	if _, ok := c.holdLeaseAtLeast(context.Background(), minFenceLease); ok {
		t.Error("holdLeaseAtLeast approved a lease held by another coordinator")
	}
}

// TestFailover_FenceIsBoundedByTheLease pins that the fence's deadline comes
// from the lease actually held, not from a constant. Nothing renews the lease
// while the fencer blocks (run() is synchronous inside the ticker), so a fence
// permitted to outlive it lets a second coordinator fence the same host.
func TestFailover_FenceIsBoundedByTheLease(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "me", now.Add(leaseDuration))

	var gotDeadline time.Time
	var hadDeadline bool
	c.SetFencer(func(fctx context.Context, h fence.HostConfig) fence.Result {
		gotDeadline, hadDeadline = fctx.Deadline()
		return fence.Result{Method: "test", Detail: "stub", Success: true}
	})

	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if !hadDeadline {
		t.Fatal("the fencer ran on a context with NO deadline — an unbounded fence can outlive the lease")
	}
	// The deadline is derived from real wall-clock remaining lease, so compare
	// against a budget rather than the injected clock: it must be at most
	// (lease head-room - margin) and clearly bounded.
	budget := time.Until(gotDeadline)
	if budget > leaseDuration-leaseFenceMargin {
		t.Errorf("fence budget %s exceeds the lease minus its margin (%s)",
			budget, leaseDuration-leaseFenceMargin)
	}
	if budget <= 0 {
		t.Errorf("fence budget %s leaves no time to fence", budget)
	}
}

// TestFailover_LeaseLostDuringFence_DoesNotReschedule is the load-bearing guard.
//
// The fence is bounded by the lease, but it can still end with the lease gone (a
// slow fence, a clock jump, a peer taking over). Everything after it — placement,
// reschedule proofs, container relocation — is the half that must not run twice,
// and gate.go states the property as "holdLease() && DecisionGate.OK". Without a
// post-fence re-check, two coordinators can each recover the same host.
//
// What must SURVIVE is the record of what physically happened: the fencing_log
// row and, for a verified power-off, hosts.state. Those are facts, not claims of
// authority, and they are how the next leader resumes the recovery instead of
// re-fencing a host that is already off.
func TestFailover_LeaseLostDuringFence_DoesNotReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// A VM with somewhere to go, so "did not reschedule" is a real observation
	// rather than a vacuous one about an empty host.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "h1", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "me", now.Add(leaseDuration))

	// The fence succeeds, but by the time it returns another coordinator holds
	// the lease — exactly the race a fence longer than its lease opens.
	c.SetFencer(func(fctx context.Context, h fence.HostConfig) fence.Result {
		seedLease(t, db, "other", now.Add(leaseDuration))
		return fence.Result{Method: "ipmi", Detail: "powered off", Success: true}
	})

	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if got := leaseHolder(t, db); got != "other" {
		t.Fatalf("fixture failed: lease holder = %q, want other", got)
	}

	// The audit fact is kept.
	if n := fenceLogCount(t, db, "h1"); n != 1 {
		t.Errorf("fencing_log rows for h1 = %d, want 1 — the power-off happened and must be recorded", n)
	}

	// The recovery half must NOT have run: the VM is what a second coordinator
	// would move concurrently, so it is the thing that must stay put.
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "h1" {
		t.Errorf("vm1 moved to %q after the lease was lost — a second coordinator can reschedule it too", vm.HostName)
	}

	// The fact of the verified power-off IS kept, so the next leader has
	// something to resume from.
	after, _ := corrosion.GetHost(ctx, db, "h1")
	if after == nil {
		t.Fatal("host disappeared")
	}
	if after.State != "fenced" {
		t.Errorf("host state = %q, want \"fenced\": a verified power-off is a fact about the host, "+
			"and losing it strands the workloads until the fence record ages out", after.State)
	}
}

// TestRun_ResumesRecoveryFromARecordedFence is the other half of the guard
// above: refusing to reschedule after a handoff is only safe if somebody else
// picks the work up.
//
// A fence that ends with the lease gone leaves a host powered off, recorded as
// "fenced", with its VMs still assigned to it. The next leader used to skip that
// host entirely — recentlyFenced suppressed the fence, and nothing else looked
// at it — so the workloads sat on a dead host until the fence aged out of
// recentFenceWindow and the host was pointlessly powered off a second time.
func TestRun_ResumesRecoveryFromARecordedFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, name := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")

	// Leader one fences "bad" and loses the lease to "good" while the fence runs.
	first := NewCoordinator("first", db)
	first.Now = func() time.Time { return now }
	first.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		seedLease(t, db, "good", now.Add(leaseDuration))
		return fence.Result{Method: "ipmi", Detail: "powered off", Success: true}
	})
	first.RunOnce(ctx)

	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Fatalf("fixture failed: vm1 should still be on bad after the handoff (err=%v)", err)
	}

	// Leader two sees a host it did not fence, in "fenced" state, still holding a
	// VM. It must finish the job from the record, not re-fence and not ignore it.
	second := NewCoordinator("good", db)
	second.Now = func() time.Time { return now }
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Error("the new leader powered off a host that was already provably off")
		return fence.Result{Method: "ipmi", Success: true}
	})
	second.RunOnce(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "good" {
		t.Fatalf("vm1 is still on %q — a successful fence followed by a lease handoff strands the "+
			"workload on a powered-off host", vm.HostName)
	}
	if n := fenceLogCount(t, db, "bad"); n != 1 {
		t.Errorf("fencing_log rows for bad = %d, want 1 — the resumed recovery must not re-fence", n)
	}
}

// TestRun_DoesNotResumeRecoveryForAStaleFence pins the boundary of the resume
// path: it acts on a fence recent enough to still be authority, and only while
// the host state still says the cluster believes that fence. A host an operator
// has undrained is back in service — its VMs must not be moved off it on the
// strength of an old fencing_log row instead of a fresh one.
func TestRun_DoesNotResumeRecoveryForAStaleFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, name := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")
	// A recorded, still-recent proof-grade fence...
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "f1", HostName: "bad", Method: "ipmi", Result: "fenced", Detail: "powered off",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
	// ...that an operator has since consumed by putting the host back in service.
	if err := corrosion.UpdateHostState(ctx, db, "bad", "active"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}

	c := NewCoordinator("good", db)
	c.Now = func() time.Time { return now }
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Fatal("unreachable: recentlyFenced still suppresses the fence itself")
		return fence.Result{}
	})
	c.RunOnce(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "bad" {
		t.Errorf("vm1 moved to %q on the strength of a fence the operator had already undrained past — "+
			"a reschedule with no fresh fence behind it is the split-brain the fence exists to prevent", vm.HostName)
	}
}

// handoffFixture drives one fence to the exact point the lease is lost: "bad" is
// powered off and recorded, its VM is still assigned to it, and the lease now
// belongs to "good". It returns both coordinators plus the injected clock, so a
// test can decide which of them takes the lease next.
func handoffFixture(t *testing.T) (*corrosion.Client, *Coordinator, *Coordinator, *time.Time) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, name := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")

	first := NewCoordinator("first", db)
	second := NewCoordinator("good", db)
	first.Now = func() time.Time { return now }
	second.Now = first.Now
	first.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		seedLease(t, db, "good", now.Add(leaseDuration))
		return fence.Result{Method: "ipmi", Detail: "powered off", Success: true}
	})
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Error("a host that is already provably off was powered off a second time")
		return fence.Result{Method: "ipmi", Success: true}
	})

	first.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Fatalf("fixture failed: vm1 should still be on bad after the handoff (err=%v)", err)
	}
	return db, first, second, &now
}

// TestRun_OriginalLeaderResumesItsOwnUnfinishedRecovery pins that the resume
// path is reachable by the coordinator that performed the fence, not only by a
// different one.
//
// Abandoning the recovery used to leave c.fenced[host] set, which run()'s cached
// "already handled this down-episode" check reads BEFORE it can ever reach
// resumableFence. With the host now sitting in 'fenced' state,
// clearRecoveredFromFenced (which clears only hosts back to 'active') could not
// clear it either — so the coordinator that knew most about the fence was the
// one permanently unable to finish it, for the life of the process.
func TestRun_OriginalLeaderResumesItsOwnUnfinishedRecovery(t *testing.T) {
	db, first, _, now := handoffFixture(t)
	ctx := context.Background()

	// The successor never runs; the lease simply expires back to whoever asks.
	*now = now.Add(leaseDuration + time.Second)
	if err := db.Execute(ctx, `UPDATE host_health SET updated_at = ?`, now.Format(time.RFC3339)); err != nil {
		t.Fatalf("refresh health: %v", err)
	}
	first.RunOnce(ctx)

	if got := leaseHolder(t, db); got != "first" {
		t.Fatalf("fixture failed: lease holder = %q, want first", got)
	}
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "good" {
		t.Errorf("vm1 is still on %q — the coordinator that fenced the host cached itself out of "+
			"finishing the recovery, and nothing else clears that cache while the host stays fenced", vm.HostName)
	}
}

// TestRecoverHosts_OriginalLeaderDoesNotAutoUndrainASuccessorsRelocation pins
// the other stale claim. c.fenceRelocated[host]=false means "I fenced this host
// and no VM moved off it", which recoverHosts treats as safe to bring back to
// 'active' on its own. Seeded before the fence and left behind on abdication, it
// outlived the knowledge it encoded: the successor relocated the VMs, and the
// original leader would later auto-undrain the host on that obsolete basis —
// skipping the manual undrain a relocating fence is supposed to require.
func TestRecoverHosts_OriginalLeaderDoesNotAutoUndrainASuccessorsRelocation(t *testing.T) {
	db, first, second, now := handoffFixture(t)
	ctx := context.Background()

	second.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "good" {
		t.Fatalf("fixture failed: the successor did not relocate vm1 (err=%v)", err)
	}

	// "bad" is reachable again and the lease is up for grabs.
	*now = now.Add(leaseDuration + time.Second)
	if err := db.Execute(ctx,
		`UPDATE host_health SET status = 'healthy', consecutive_failures = 0, updated_at = ?`,
		now.Format(time.RFC3339)); err != nil {
		t.Fatalf("refresh health: %v", err)
	}
	first.RunOnce(ctx)

	if got := leaseHolder(t, db); got != "first" {
		t.Fatalf("fixture failed: lease holder = %q, want first", got)
	}
	h, err := corrosion.GetHost(ctx, db, "bad")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "fenced" {
		t.Errorf("host state = %q, want \"fenced\": a fence whose VMs were relocated must wait for "+
			"`lv host undrain`, and the original leader's cached \"nothing moved\" is not evidence "+
			"about what the successor did", h.State)
	}
}

// TestRun_ResumesOnceAFenceLogRowArrivesLate pins that "no proof yet" is a wait,
// not a verdict.
//
// hosts.state and fencing_log are separate replicated tables, so a successor can
// see the host recorded 'fenced' a cycle or more before the row that authorises
// the resume reaches it. The terminal-state fallback used to cache the skip on
// that first look, and the cache is cleared only for hosts back to 'active' — so
// the proof arriving a moment later was never read, and the workloads stayed on
// the dead host for the life of the process.
func TestRun_ResumesOnceAFenceLogRowArrivesLate(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "ipmi"},
		{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ipmi"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"good"}, "bad")

	c := NewCoordinator("good", db)
	c.Now = func() time.Time { return now }
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Error("a host recorded 'fenced' was powered off again instead of waiting for its proof")
		return fence.Result{Method: "ipmi", Success: true}
	})

	// Cycle one: the state has replicated, the proof has not. Waiting is correct.
	c.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Fatalf("vm1 moved with no fence on record — an unproven 'fenced' state is not authority (err=%v)", err)
	}

	// The fencing_log row lands.
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "f1", HostName: "bad", Method: "ipmi", Result: "fenced", Detail: "verified off",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
	c.RunOnce(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "good" {
		t.Errorf("vm1 is still on %q — the first look decided the host was settled and nothing "+
			"re-read the proof that arrived after it", vm.HostName)
	}
}

// TestFailover_FenceDeadlineCoversTheIPMIWorstCase is the #202 regression.
//
// The deadline handed to the fencer is leaseLeft - leaseFenceMargin, and
// holdLeaseAtLeast returns as soon as leaseLeft is strictly more than
// minFenceLease. At that floor the fencer gets minFenceLease - leaseFenceMargin
// = 15s, against an IPMI fence whose own budget is up to 8s for the power-off
// call plus a further 15s of verification: 23s.
//
// This is not a corner: the lease is renewed at leaseRenewBefore, so in steady
// state leaseLeft sits anywhere in (minFenceLease, leaseDuration] and most
// fences start with less than the worst case available.
//
// The failure mode is the one fencing exists to prevent. The BMC accepts the
// power-off and the chassis goes down; the context expires part-way through
// verifyIPMIPowerOff; fenceIPMI reports Success=false because an unconfirmed
// power-off must never be treated as confirmed; the coordinator logs "partial"
// and does NOT reschedule. A host that is genuinely, verifiably off keeps its
// VMs stopped, which is exactly the outage failover was supposed to end.
//
// The fix belongs on the requirement, not the deadline: a fence must not START
// without enough lease left to finish it.
func TestFailover_FenceDeadlineCoversTheIPMIWorstCase(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	// The LEAST head-room a fence is allowed to begin with: just over
	// minFenceLease, which holdLeaseAtLeast accepts without renewing. This is
	// the budget the coordinator's own floor promises is enough.
	seedLease(t, db, "me", now.Add(minFenceLease+time.Second))

	var budget time.Duration
	var hadDeadline bool
	c.SetFencer(func(fctx context.Context, h fence.HostConfig) fence.Result {
		var dl time.Time
		dl, hadDeadline = fctx.Deadline()
		budget = time.Until(dl)
		return fence.Result{Method: "ipmi", Detail: "stub", Success: true}
	})

	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if !hadDeadline {
		t.Fatal("the fencer ran with no deadline at all")
	}
	if worst := fence.WorstCasePowerOff(); budget < worst {
		t.Errorf("fence budget %s is shorter than an IPMI fence's own worst case %s "+
			"(power-off %s + verify %s): a slow power-off is cut off mid-verification "+
			"and reported as unconfirmed, so the host's VMs are never rescheduled",
			budget.Round(time.Second), worst, 8*time.Second, fence.PowerOffVerifyTimeout)
	}
}

// The floor must be reachable: a freshly renewed lease has to satisfy it, or no
// fence can ever start. This is the other half of raising minFenceLease.
func TestFailover_AFreshLeaseSatisfiesTheFenceFloor(t *testing.T) {
	if leaseDuration <= minFenceLease {
		t.Fatalf("leaseDuration (%s) <= minFenceLease (%s): holdLeaseAtLeast requires "+
			"strictly more than the floor, so even a just-renewed lease would be "+
			"refused and fencing would be impossible", leaseDuration, minFenceLease)
	}
	if got := minFenceLease - leaseFenceMargin; got < fence.WorstCasePowerOff() {
		t.Errorf("minFenceLease - leaseFenceMargin = %s, which is less than "+
			"fence.WorstCasePowerOff() (%s); the floor does not cover the call it gates",
			got, fence.WorstCasePowerOff())
	}
	if leaseRenewBefore >= minFenceLease {
		t.Errorf("leaseRenewBefore (%s) >= minFenceLease (%s): the renewal margin must "+
			"stay below the fence floor or holdLease and holdLeaseAtLeast disagree "+
			"about when a lease is healthy", leaseRenewBefore, minFenceLease)
	}
}
