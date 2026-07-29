// Fleet scenario: the startup operation-recovery barrier decides from REPLICATED
// state.
//
// A host that crashes mid-operation leaves host-local journal entries holding
// rollback artifacts. On restart it must decide, per entry, whether it is still
// the authorized owner — resume/roll back if so, and critically do NO external
// rollback once ownership has moved or the operation is gone. Rolling back a
// device attach the new owner has already taken over would corrupt live state.
//
// DecideRecovery (internal/opjournal/recovery.go) is pure and exhaustively
// unit-tested. What those tests cannot reach is where its INPUTS come from: the
// crashed host learns about the takeover only through CRDT replication from the
// peer that adopted the work. These scenarios cover that half — the recovery
// verdict must flip while the crashed host sits still, purely because state
// arrived over the real anti-entropy path.
//
// The lookup below mirrors Daemon.runOperationRecovery (internal/daemon/daemon.go
// :1604) so the scenarios feed PlanRecovery the same shape the daemon does.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// ── harness helpers ─────────────────────────────────────────────────────────

// opStateLookup builds the OpStateLookup the daemon wires at startup, reading
// node n's OWN DB — so every verdict reflects exactly what has replicated to n
// and nothing more.
func opStateLookup(ctx context.Context, n *Node) opjournal.OpStateLookup {
	return func(opID string) (bool, int64, bool, error) {
		op, err := corrosion.GetOperation(ctx, n.DB, opID)
		if err != nil {
			return false, 0, false, err
		}
		if op == nil {
			return false, 0, false, nil // GC'd → supersede
		}
		epoch, ok, err := corrosion.GetVMOwnerEpoch(ctx, n.DB, op.ResourceID)
		if err != nil {
			return false, 0, false, err
		}
		if !ok {
			return false, 0, false, nil // VM gone → not owned → supersede
		}
		state, _, err := corrosion.OperationCurrentState(ctx, n.DB, opID, op.VMOwnerEpoch,
			corrosion.OperationKind(op.OperationKind))
		if err != nil {
			return false, 0, false, err
		}
		return true, epoch, corrosion.IsOperationTerminal(state), nil
	}
}

// converge pulls pullee's full-state dump into puller over the REAL anti-entropy
// path (StreamStateDump → MergeStateBytesLWW), the same route partition_test.go
// uses to reconverge a lagging node.
func converge(t *testing.T, c *Cluster, puller, pullee *Node) {
	t.Helper()
	blob, err := peerPull(c, puller, pullee)
	if err != nil {
		t.Fatalf("state pull %s←%s: %v", puller.Name, pullee.Name, err)
	}
	puller.DB.MergeStateBytesLWW(blob)
}

// wedgedOp is the fixture identity shared by the scenarios below.
const (
	wedgedVM    = "vm1"
	wedgedOpID  = "op-wedged-1"
	wedgedEpoch = int64(0)
)

// seedWedgedOperation puts `origin` in the state a host has after crashing
// mid-operation: it owns the VM at the entry's epoch, an operation header is
// live with non-terminal progress recorded, and a host-local journal entry holds
// the rollback artifacts. Returns the journal the restarted daemon would reopen.
func seedWedgedOperation(t *testing.T, origin *Node) *opjournal.Journal {
	t.Helper()
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, origin.DB, corrosion.VMRecord{
		Name: wedgedVM, HostName: origin.Name, Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertOperation(ctx, origin.DB, corrosion.OperationRecord{
		ID:            wedgedOpID,
		Method:        "AttachDevice",
		Principal:     "admin",
		ResourceKind:  "vm",
		ResourceID:    wedgedVM,
		OperationKind: string(corrosion.OpDeviceAttach),
		RequestHash:   "hash-1",
		VMOwnerEpoch:  wedgedEpoch,
	}); err != nil {
		t.Fatalf("InsertOperation: %v", err)
	}
	// Partial progress: reserved+claimed, no terminal — the operation is live.
	for _, step := range []string{corrosion.OpStepReserved, corrosion.OpStepClaimed} {
		if err := corrosion.AppendOperationStep(ctx, origin.DB, corrosion.OperationStepRecord{
			OperationID: wedgedOpID, OwnerEpoch: wedgedEpoch, StepName: step,
		}); err != nil {
			t.Fatalf("AppendOperationStep %s: %v", step, err)
		}
	}

	j, err := opjournal.Open(t.TempDir())
	if err != nil {
		t.Fatalf("opjournal.Open: %v", err)
	}
	if err := j.Write(opjournal.Entry{
		OperationID: wedgedOpID,
		OwnerEpoch:  wedgedEpoch,
		ResourceID:  wedgedVM,
		Kind:        string(corrosion.OpDeviceAttach),
		Stage:       corrosion.OpStepClaimed,
		Artifacts:   map[string]string{"prior_driver:0000:00:1f.0": "vfio-pci"},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("journal Write: %v", err)
	}
	return j
}

// singleAction runs recovery planning for n and returns the sole entry's action.
func singleAction(t *testing.T, j *opjournal.Journal, n *Node) opjournal.RecoveryAction {
	t.Helper()
	plan, corrupt, err := j.PlanRecovery(opStateLookup(context.Background(), n))
	if err != nil {
		t.Fatalf("PlanRecovery on %s: %v", n.Name, err)
	}
	if len(corrupt) != 0 {
		t.Fatalf("PlanRecovery on %s reported corrupt entries: %v", n.Name, corrupt)
	}
	if len(plan) != 1 {
		t.Fatalf("PlanRecovery on %s: got %d planned entries, want 1", n.Name, len(plan))
	}
	return plan[0].Action
}

// assertResumesBeforeReplication pins the pre-condition every scenario depends
// on: while the crashed host is still the authorized owner of a live operation,
// recovery authorizes it to resume — so a later flip can only be attributed to
// the state that replicated in.
func assertResumesBeforeReplication(t *testing.T, j *opjournal.Journal, origin *Node) {
	t.Helper()
	if got := singleAction(t, j, origin); got != opjournal.RecoveryResume {
		t.Fatalf("baseline: got %s, want resume (still the authorized owner of a live operation)", got)
	}
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestFleet_OpJournalRecovery_ReplicatedTakeoverSupersedes is the headline
// contract: once ownership has moved to another host, the crashed host must NOT
// perform an external rollback — it supersedes and archives its entry. The
// crashed host takes no local action here; the verdict flips solely because the
// takeover replicated in.
func TestFleet_OpJournalRecovery_ReplicatedTakeoverSupersedes(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	origin, taker := c.Nodes[0], c.Nodes[1]

	j := seedWedgedOperation(t, origin)
	assertResumesBeforeReplication(t, j, origin)

	// The taker learns about the VM/operation, then adopts the VM while origin is
	// down: ownership moves and the authorized owner epoch advances past the
	// journal entry's. (v41 is foundation-only — no production writer advances
	// vm_owner_epoch yet — so the adoption is written directly here.)
	converge(t, c, taker, origin)
	if err := taker.DB.Execute(ctx,
		`UPDATE vms SET host_name = ?, vm_owner_epoch = vm_owner_epoch + 1, updated_at = ? WHERE name = ?`,
		taker.Name, taker.DB.NowTS(), wedgedVM); err != nil {
		t.Fatalf("adopt %s on %s: %v", wedgedVM, taker.Name, err)
	}

	// The takeover replicates back to the crashed host.
	converge(t, c, origin, taker)
	epoch, ok, err := corrosion.GetVMOwnerEpoch(ctx, origin.DB, wedgedVM)
	if err != nil || !ok {
		t.Fatalf("read replicated owner epoch on %s: ok=%v err=%v", origin.Name, ok, err)
	}
	if epoch == wedgedEpoch {
		t.Fatalf("takeover did not replicate to %s: owner epoch still %d", origin.Name, epoch)
	}

	if got := singleAction(t, j, origin); got != opjournal.RecoverySupersede {
		t.Fatalf("after takeover: got %s, want supersede — the crashed host must not roll back externally", got)
	}
}

// TestFleet_OpJournalRecovery_ReplicatedTerminalCleansUp: the operation finished
// under the SAME owner epoch while this host was down. It is still the
// authorized owner, so there is no takeover to defer to — but the artifacts are
// no longer needed, so the entry is cleaned up rather than resumed.
func TestFleet_OpJournalRecovery_ReplicatedTerminalCleansUp(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	origin, peer := c.Nodes[0], c.Nodes[1]

	j := seedWedgedOperation(t, origin)
	assertResumesBeforeReplication(t, j, origin)

	// The peer records the terminal step for the same epoch and it replicates in.
	converge(t, c, peer, origin)
	if err := corrosion.AppendOperationStep(ctx, peer.DB, corrosion.OperationStepRecord{
		OperationID: wedgedOpID, OwnerEpoch: wedgedEpoch, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		t.Fatalf("AppendOperationStep completed: %v", err)
	}
	converge(t, c, origin, peer)

	if got := singleAction(t, j, origin); got != opjournal.RecoveryCleanup {
		t.Fatalf("after a replicated terminal step: got %s, want cleanup", got)
	}
}

// TestFleet_OpJournalRecovery_ReapedOperationSupersedes: the operation header was
// GC'd cluster-wide while this host was down. With nothing left to resume, the
// entry must supersede — never roll back against an operation that no longer
// exists. Exercises the opExists=false branch through real replication of the
// reaper's soft-delete.
func TestFleet_OpJournalRecovery_ReapedOperationSupersedes(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	origin, peer := c.Nodes[0], c.Nodes[1]

	j := seedWedgedOperation(t, origin)
	assertResumesBeforeReplication(t, j, origin)

	converge(t, c, peer, origin)
	if err := corrosion.AppendOperationStep(ctx, peer.DB, corrosion.OperationStepRecord{
		OperationID: wedgedOpID, OwnerEpoch: wedgedEpoch, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		t.Fatalf("AppendOperationStep completed: %v", err)
	}
	// Negative retention puts the cutoff in the future so the just-terminal
	// operation is past it — the reaper's normal behaviour, without the wait.
	reaped, err := corrosion.ReapTerminalOperations(ctx, peer.DB, -time.Minute)
	if err != nil {
		t.Fatalf("ReapTerminalOperations: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("ReapTerminalOperations reaped %d operations, want 1", reaped)
	}
	converge(t, c, origin, peer)

	if op, err := corrosion.GetOperation(ctx, origin.DB, wedgedOpID); err != nil || op != nil {
		t.Fatalf("reap did not replicate to %s: op=%v err=%v", origin.Name, op, err)
	}
	if got := singleAction(t, j, origin); got != opjournal.RecoverySupersede {
		t.Fatalf("after the operation was reaped: got %s, want supersede", got)
	}
}
