package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/lxc"
)

// TestContainerCheck_ReconcileWriteFailure_NoFalseReconciledEvent reproduces the
// fail-open "reconciled lie": when the reconcile state write to Corrosion fails,
// the pre-fix reconciler still publishes ct.state.reconciled, telling subscribers
// the cluster/runtime divergence is healed when the DB row is unchanged. A
// BEFORE UPDATE trigger on the containers table forces the write to fail.
//
// Correct behavior: no ct.state.reconciled event is published when the write did
// not land. This fails against the pre-fix code and passes once the event is gated
// on the write succeeding.
func TestContainerCheck_ReconcileWriteFailure_NoFalseReconciledEvent(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateRunning // reality: running

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "stopped", // stale cluster drift
		RestartPolicy: ctPolicyJSON(t, "always", 0, "0s", ""),
	})
	ct := mustGetCt(t, db, "ct1")

	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()

	c := NewContainerChecker("node1", db, rt)
	c.SetEventBus(bus)
	var failOp, failClass string
	c.SetStateWriteFailObserver(func(op, class string) { failOp, failClass = op, class })

	// Force the reconcile state write to fail (simulates a Corrosion write error).
	if err := db.Execute(ctx,
		`CREATE TRIGGER inject_fail BEFORE UPDATE ON containers BEGIN SELECT RAISE(ABORT, 'inject'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	c.checkContainer(ctx, ct, time.Now())

	for {
		select {
		case e := <-ch:
			if e.Action == "ct.state.reconciled" {
				t.Errorf("published %q after the reconcile write failed — false-healed event", e.Action)
			}
		default:
			if failOp != corrosion.OpContainerState || failClass != corrosion.WriteClassDBError {
				t.Errorf("state-write-fail observer got op=%q class=%q, want %q/%q",
					failOp, failClass, corrosion.OpContainerState, corrosion.WriteClassDBError)
			}
			return
		}
	}
}
