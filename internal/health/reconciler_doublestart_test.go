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

// TestReconciler_SelfFenceDestroysMovedDomain proves the split-brain GC: a domain
// running locally that corrosion says now belongs to ANOTHER host is destroyed +
// undefined locally (the loser of a partition+heal reassignment), leaving exactly
// one owner cluster-wide.
func TestReconciler_SelfFenceDestroysMovedDomain(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Corrosion: vm1 now owned by node-b, running there.
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// But it's still running locally on node-a (a stale copy from before the move).
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.selfFence(ctx)

	if fake.DomainExists("vm1") {
		t.Fatal("selfFence must destroy+undefine the local domain that moved to another host")
	}
	var destroyed bool
	for _, e := range fake.EventLog() {
		if e.Domain == "vm1" && e.Op == "destroy" {
			destroyed = true
		}
	}
	if !destroyed {
		t.Fatal("expected a destroy event for the moved-away vm1")
	}
}
