package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// reconcilePass bounds the pending-VM walk with reconcileWalkBudget, and
// startPendingVM runs inside that walk. StartDomain is not context-bound, so
// once it returns the guest IS RUNNING — but everything after it (completing
// the proof, publishing "running", releasing the per-VM lease) was still
// riding the budgeted context.
//
// On exactly the case the budget was written for — a large failover, peers
// timing out — the budget expires between the start and the commit. The guest
// runs, the publish fails on a cancelled context, and the lease DELETE fails
// too (logged at Debug), stranding the VM's lease for the full vmLockTTL of
// ten minutes so no other host can reconcile it.
//
// Work that has already happened has to be recorded whatever the clock says.
func TestStartPendingVM_ExpiredWalkBudgetStillReleasesTheLease(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")

	// A budget that is already spent by the time the commit tail runs — the
	// shape reconcilePass produces under load, without depending on timing.
	wctx, cancel := context.WithCancel(ctx)
	r.startDomainHook = func(context.Context) { cancel() }
	defer cancel()

	r.startPendingVM(wctx, *fresh)

	if !startedOrDefined(fake, "vm1") {
		t.Fatal("fixture inert: the domain was never started, so the commit tail was never reached")
	}

	rows, err := db.Query(ctx, `SELECT holder FROM vm_locks WHERE vm_name = ?`, "vm1")
	if err != nil {
		t.Fatalf("read vm_locks: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("vm_lock still held by %q after the walk budget expired; the lease is stranded "+
			"for vmLockTTL and no other host can reconcile this VM",
			rows[0].String("holder"))
	}
}

// And the state write itself must land: a running guest whose row still says
// "starting" is a VM the cluster cannot account for.
func TestStartPendingVM_ExpiredWalkBudgetStillPublishesRunning(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	wctx, cancel := context.WithCancel(ctx)
	r.startDomainHook = func(context.Context) { cancel() }
	defer cancel()

	r.startPendingVM(wctx, *fresh)

	after, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || after == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if after.State != "running" {
		t.Fatalf("VM state = %q after a start whose budget expired, want running; the guest is "+
			"up and the cluster does not know", after.State)
	}
}

// The budget must still CUT a walk that has not started anything — bounding
// the walk is the whole point, and this fix must not turn it into an
// unbounded loop.
func TestReconcileWalkBudget_StillBoundsTheWalk(t *testing.T) {
	if reconcileWalkBudget <= 0 {
		t.Fatalf("reconcileWalkBudget = %s, want a positive bound", reconcileWalkBudget)
	}
	if reconcileWalkBudget > 30*time.Second {
		t.Errorf("reconcileWalkBudget = %s, which is no longer a bound worth having", reconcileWalkBudget)
	}
}

// The constant existing is not the same as the walk using it. reconcilePass
// must hand the walk a context that actually carries the deadline — otherwise
// the bound is a comment, and the pass it was added to protect runs unbounded
// under exactly the load it was written for.
//
// Checked at the deepest point of the walk, which is where it matters: the
// per-VM start.
func TestReconcileWalkBudget_IsAppliedToTheWalk(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	var sawDeadline, sawAny bool
	r.startDomainHook = func(walkCtx context.Context) {
		sawAny = true
		_, sawDeadline = walkCtx.Deadline()
	}

	r.reconcilePass(ctx)

	if !sawAny {
		t.Fatal("fixture inert: the walk never reached a VM start, so nothing was observed")
	}
	if !sawDeadline {
		t.Fatal("the walk ran without a deadline; reconcileWalkBudget is not applied and the " +
			"pass is unbounded under the load it exists to bound")
	}
}
