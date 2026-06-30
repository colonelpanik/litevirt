package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestReconciler_VMLockArbitration proves the per-VM lease prevents a
// double-start under a CONSISTENT lock view: two reconcilers (different hosts,
// same DB) racing to acquire the same VM's lock — exactly one wins. This is the
// local-race guarantee; it makes NO claim about a real network partition (where
// vm_locks is explicitly non-linearizable — see the failover/quorum path).
func TestReconciler_VMLockArbitration(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	rA := NewReconciler("node-a", t.TempDir(), db, nil)
	rB := NewReconciler("node-b", t.TempDir(), db, nil)

	var gotA, gotB bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); gotA = rA.acquireVMLock(ctx, "vm1") }()
	go func() { defer wg.Done(); gotB = rB.acquireVMLock(ctx, "vm1") }()
	wg.Wait()

	if gotA == gotB {
		t.Fatalf("exactly one reconciler must hold the vm1 lock; gotA=%v gotB=%v", gotA, gotB)
	}
}

// TestReconciler_VMLockExpiryWithClock exercises the Now seam: a peer can take
// over a VM lock only AFTER its TTL elapses, advanced deterministically without
// sleeping (the seam the fleet harness relies on for partition+heal scenarios).
func TestReconciler_VMLockExpiryWithClock(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	rA := NewReconciler("node-a", t.TempDir(), db, nil)
	rA.Now = func() time.Time { return base }
	if !rA.acquireVMLock(ctx, "vm1") {
		t.Fatal("A should acquire a fresh lock")
	}

	rB := NewReconciler("node-b", t.TempDir(), db, nil)
	rB.Now = func() time.Time { return base } // same instant → A's lock not expired
	if rB.acquireVMLock(ctx, "vm1") {
		t.Fatal("B must not take A's unexpired lock")
	}
	rB.Now = func() time.Time { return base.Add(vmLockTTL + time.Minute) } // past TTL
	if !rB.acquireVMLock(ctx, "vm1") {
		t.Fatal("B should take over after the lock TTL elapses")
	}
}

// TestReconciler_StartPendingVM_RefusesWhenLockHeld proves the reconciler does
// NOT start a VM whose lock is held by another host — no DefineDomain/StartDomain
// reaches libvirt. The lock acquire is the first thing startPendingVM does.
func TestReconciler_StartPendingVM_RefusesWhenLockHeld(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	const future = "2999-01-01T00:00:00Z"

	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A peer already holds the lock.
	if err := db.Execute(ctx, `INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES (?,?,?,?)`,
		"vm1", "node-b", future, future); err != nil {
		t.Fatalf("seed vm_lock: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.startPendingVM(ctx, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"})

	for _, e := range fake.EventLog() {
		if e.Domain == "vm1" && (e.Op == "start" || e.Op == "define") {
			t.Fatalf("reconciler started/defined vm1 despite peer holding the lock: %+v", e)
		}
	}
	if fake.DomainExists("vm1") {
		t.Fatal("vm1 must not exist locally — start was refused by the lock")
	}
}

// Phase-1 selfFence guard tests. selfFence cleans up a moved-away local domain
// ONLY when it's a clearly-dead leftover (DomainStateReason in the cleanable
// allowlist); it NEVER destroys a domain that is running or holds resumable state
// (paused/pmsuspended/saved), nor on an unreadable state — that defers to the
// Phase-3 runtime/fencing ownership reconciliation.
func wasDestroyed(fake *libvirtfake.Fake, name string) bool {
	for _, e := range fake.EventLog() {
		if e.Domain == name && e.Op == "destroy" {
			return true
		}
	}
	return false
}

// Phase 1 guard: a domain RUNNING locally whose DB row points to another host is
// NOT destroyed — a converged-wrong host_name (the equal-timestamp LWW tie) must
// not drive selfFence into killing a live VM. Ownership is reconciled later
// against runtime/fencing (Phase 3), not by trusting the DB field.
func TestReconciler_SelfFence_RunningLocalNotDestroyed(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning) // still running locally on node-a

	NewReconciler("node-a", t.TempDir(), db, fake).selfFence(ctx)

	if !fake.DomainExists("vm1") || wasDestroyed(fake, "vm1") {
		t.Fatal("selfFence must NOT destroy a locally-running domain whose DB row moved away")
	}
}

// Resumable / live state (paused, pm-suspended, saved-memory) whose DB row moved
// away must NOT be destroyed — coarse DomainState collapses these to "stopped", so
// the guard keys on DomainStateReason. These hold recoverable workload state.
func TestReconciler_SelfFence_ResumableStateNotDestroyed(t *testing.T) {
	for _, reason := range []string{"paused", "pmsuspended", "saved", "from-snapshot", "shutting-down", "crashed", "migrated", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db,
				corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			fake := libvirtfake.New()
			fake.SetState("vm1", libvirtfake.StateDefined) // coarse "stopped"
			fake.SetStateReason("vm1", reason)

			NewReconciler("node-a", t.TempDir(), db, fake).selfFence(ctx)

			if wasDestroyed(fake, "vm1") {
				t.Fatalf("selfFence must NOT destroy a domain with reason %q whose DB row moved away", reason)
			}
		})
	}
}

// Defensive: a cleanable REASON under a non-"stopped" coarse state is still NOT
// cleaned (both conditions must hold). Can't happen under the current real mapping
// — guards a future reason/state decoupling.
func TestReconciler_SelfFence_CleanableReasonButNotStopped(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning) // coarse state "running"
	fake.SetStateReason("vm1", "destroyed")        // a cleanable reason, but state isn't "stopped"

	NewReconciler("node-a", t.TempDir(), db, fake).selfFence(ctx)

	if wasDestroyed(fake, "vm1") {
		t.Fatal("selfFence must require BOTH a stopped state AND a clearly-dead reason")
	}
}

// An unreadable state fails closed — it could be a running domain mid-query.
func TestReconciler_SelfFence_UnreadableNotDestroyed(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateDefined)
	fake.FailDomainStateReason = func(string) error { return context.DeadlineExceeded }

	NewReconciler("node-a", t.TempDir(), db, fake).selfFence(ctx)

	if wasDestroyed(fake, "vm1") {
		t.Fatal("selfFence must fail closed (not destroy) when the local state is unreadable")
	}
}

// A clearly-dead leftover (guest-shutdown / destroyed / daemon / failed) whose DB
// row moved to another host is still cleaned up (destroy + undefine).
func TestReconciler_SelfFence_DeadLeftoverDestroyed(t *testing.T) {
	for _, reason := range []string{"guest-shutdown", "destroyed", "daemon", "failed"} {
		t.Run(reason, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db,
				corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			fake := libvirtfake.New()
			fake.SetState("vm1", libvirtfake.StateDefined)
			fake.SetStateReason("vm1", reason)

			NewReconciler("node-a", t.TempDir(), db, fake).selfFence(ctx)

			if fake.DomainExists("vm1") || !wasDestroyed(fake, "vm1") {
				t.Fatalf("selfFence must clean up a clearly-dead leftover (reason %q) whose VM moved away", reason)
			}
		})
	}
}
