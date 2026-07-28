package corrosion

import (
	"context"
	"testing"
)

func vmOpFields(t *testing.T, c *Client, name string) (ownerEpoch, specGen int64, activeOp, spec string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT vm_owner_epoch, spec_generation, active_operation_id, spec FROM vms WHERE name = ?`, name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read vm %s: err=%v rows=%d", name, err, len(rows))
	}
	r := rows[0]
	return r.Int64("vm_owner_epoch"), r.Int64("spec_generation"), r.String("active_operation_id"), r.String("spec")
}

func TestBeginCompleteVMOperation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{
		ID:     DeterministicOperationID("UpdateVM", "user:alice@local", "", "vm1", "k1"),
		Method: "UpdateVM", Principal: "user:alice@local", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "hashA", IdempotencyKey: "k1",
	}

	// Begin at epoch 0, generation 0.
	applied, err := c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0)
	if err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	oe, sg, active, spec := vmOpFields(t, c, "vm1")
	if active != op.ID || sg != 1 || spec != `{"cpu":4}` || oe != 0 {
		t.Fatalf("after begin: epoch=%d gen=%d active=%q spec=%q", oe, sg, active, spec)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got == nil {
		t.Fatal("operation header should exist after begin")
	}
	if state, _, _ := OperationCurrentState(ctx, c, op.ID, 0, OpResourceUpdateRunning); state != OpStepPlanned {
		t.Fatalf("initial state = %q, want planned", state)
	}

	// Retry with the SAME op is idempotent (no re-bump), still reports applied.
	applied, err = c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0)
	if err != nil || !applied {
		t.Fatalf("retry begin: applied=%v err=%v", applied, err)
	}
	if _, sg, _, _ = vmOpFields(t, c, "vm1"); sg != 1 {
		t.Fatalf("retry must not re-bump generation, gen=%d", sg)
	}

	// A DIFFERENT operation is blocked by the barrier.
	op2 := op
	op2.ID = DeterministicOperationID("UpdateVM", "user:alice@local", "", "vm1", "k2")
	op2.RequestHash = "hashB"
	if applied, _ := c.BeginVMOperation(ctx, op2, `{"cpu":8}`, 0, 1); applied {
		t.Fatal("a second operation must be blocked while one is active")
	}

	// Complete with the wrong generation → no-op.
	if applied, _ := c.CompleteVMOperation(ctx, "vm1", op.ID, 0, 99); applied {
		t.Fatal("completion with a stale generation must not apply")
	}
	// Complete correctly → barrier cleared, completed step recorded.
	applied, err = c.CompleteVMOperation(ctx, "vm1", op.ID, 0, 1)
	if err != nil || !applied {
		t.Fatalf("complete: applied=%v err=%v", applied, err)
	}
	if _, _, active, _ = vmOpFields(t, c, "vm1"); active != "" {
		t.Fatalf("barrier not cleared after completion, active=%q", active)
	}
	if state, faulted, _ := OperationCurrentState(ctx, c, op.ID, 0, OpResourceUpdateRunning); state != OpStepCompleted || faulted {
		t.Fatalf("final state=%q faulted=%v, want completed", state, faulted)
	}
}

func TestGetVMActiveOperation_AndAbort(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// No active operation initially.
	if _, found, err := GetVMActiveOperation(ctx, c, "vm1"); err != nil || found {
		t.Fatalf("no active op expected: found=%v err=%v", found, err)
	}
	op := OperationRecord{ID: "wedged-op", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if _, err := c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}

	view, found, err := GetVMActiveOperation(ctx, c, "vm1")
	if err != nil || !found {
		t.Fatalf("active op should be found: found=%v err=%v", found, err)
	}
	if view.ActiveOperationID != "wedged-op" || view.State != OpStepPlanned || view.Operation == nil {
		t.Fatalf("unexpected view: %+v", view)
	}

	// Abort with the wrong generation → no-op.
	if applied, _ := c.AbortVMOperation(ctx, "vm1", "wedged-op", 0, 99); applied {
		t.Fatal("abort with a stale generation must not apply")
	}
	// Abort correctly → barrier cleared, cancelled step recorded.
	applied, err := c.AbortVMOperation(ctx, "vm1", "wedged-op", 0, 1)
	if err != nil || !applied {
		t.Fatalf("abort: applied=%v err=%v", applied, err)
	}
	if _, found, _ := GetVMActiveOperation(ctx, c, "vm1"); found {
		t.Fatal("barrier should be cleared after abort")
	}
	if state, _, _ := OperationCurrentState(ctx, c, "wedged-op", 0, OpResourceUpdateRunning); state != OpStepCancelled {
		t.Fatalf("aborted op state = %q, want cancelled", state)
	}
}

// A stale epoch/generation at begin is refused (the CAS precondition).
func TestBeginVMOperation_StaleEpochRefused(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: "opX", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	// VM is at epoch 0; claim with expected epoch 5 must fail.
	if applied, _ := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 5, 0); applied {
		t.Fatal("begin with a stale owner epoch must not apply")
	}
	if _, _, active, _ := vmOpFields(t, c, "vm1"); active != "" {
		t.Fatalf("a refused begin must not set the barrier, active=%q", active)
	}
}
