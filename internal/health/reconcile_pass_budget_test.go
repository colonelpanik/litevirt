package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// One reconcile pass walks pending VMs SERIALLY on the same goroutine that then
// runs selfFence and assertRuntimeOwnership. Every per-VM cost in that walk is
// bounded on its own — the lease-term barrier has a budget per call — but the
// PASS had no bound at all, and the two sweeps that follow it are the ones that
// must not be delayed.
//
// selfFence is the sharp one: it is how a doomed node stops driving decisions
// while it waits for the watchdog. Each pending VM contributing its own barrier
// budget means a large failover, or a partition where peers time out, spends
// the whole tick in fan-outs and pushes selfFence arbitrarily far past the 15s
// interval it is supposed to run on.
//
// The walk is retried on the next tick and is idempotent, so cutting it short
// costs a delayed VM start. Not cutting it short costs a delayed self-fence.
func TestReconcilePass_DoesNotLetTheWalkStarveTheSafetySweeps(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", State: "pending",
		Spec: `{"name":"vm1","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Shrink the walk budget so the test does not have to wait out the real one.
	origBudget := reconcileWalkBudget
	reconcileWalkBudget = 300 * time.Millisecond
	t.Cleanup(func() { reconcileWalkBudget = origBudget })

	r := NewReconciler("node-a", t.TempDir(), db, libvirtfake.New())

	// A per-VM step that takes far longer than a whole pass should. It honours
	// ctx, so a bounded pass ends promptly and an unbounded one waits it out.
	const perVM = 4 * time.Second
	r.SetHardwareStartPreparer(func(c context.Context, _ *corrosion.VMRecord) (func(), error) {
		select {
		case <-time.After(perVM):
		case <-c.Done():
		}
		return func() {}, nil
	})

	start := time.Now()
	r.ReconcileOnce(ctx)
	elapsed := time.Since(start)

	if elapsed >= perVM {
		t.Errorf("one reconcile pass took %v; a single slow VM consumed the whole pass\n"+
			"selfFence and assertRuntimeOwnership run after the walk on this same "+
			"goroutine, so an unbounded walk delays the self-fence a doomed node "+
			"depends on. The walk is idempotent and retried next tick; the sweeps "+
			"are not.", elapsed)
	}
}

// NOTE: the other half of this contract — that selfFence and
// assertRuntimeOwnership receive the CALLER's context and not the walk's
// expired one — is correct by construction in reconcilePass (the budget is
// applied to wctx, the sweeps take ctx) but is NOT independently pinned by a
// test. Reaching assertRuntimeOwnership needs an active-worker host row, a
// running local domain, a wired peer-runtime checker and an execution gate;
// that setup was not worth a test that would mostly assert its own scaffolding.
// If reconcilePass is ever refactored, check that line by eye.
