package corrosion

import (
	"context"
	"testing"
	"time"
)

func ageOperationSteps(t *testing.T, c *Client, operationID, ts string) {
	t.Helper()
	if _, err := c.db.Exec(`UPDATE operation_steps SET updated_at = ? WHERE operation_id = ?`, ts, operationID); err != nil {
		t.Fatalf("age steps: %v", err)
	}
}

func TestReapTerminalOperations(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: DeterministicOperationID("UpdateVM", "p", "", "vm1", "k1"),
		Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if _, err := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := c.CompleteVMOperation(ctx, "vm1", op.ID, 0, 1); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Terminal but FRESH → not reaped (retention not elapsed).
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 0 {
		t.Fatalf("fresh terminal op should not be reaped: n=%d err=%v", n, err)
	}

	// Age the steps past the horizon → reaped, header + steps tombstoned.
	ageOperationSteps(t, c, op.ID, "2020-01-01T00:00:00Z")
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 1 {
		t.Fatalf("aged terminal op should be reaped once: n=%d err=%v", n, err)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got != nil {
		t.Fatal("header should be tombstoned after reap")
	}
	if steps, _ := ListOperationSteps(ctx, c, op.ID, 0); len(steps) != 0 {
		t.Fatalf("steps should be tombstoned after reap, got %d", len(steps))
	}
	// Idempotent: a second sweep reaps nothing.
	if n, _ := ReapTerminalOperations(ctx, c, time.Hour); n != 0 {
		t.Fatalf("second sweep should reap nothing, got %d", n)
	}
}

func TestReapTerminalOperations_SkipsActiveAndNonTerminal(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: "opActive", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	// Begin but do NOT complete → barrier held, state is non-terminal (planned).
	if _, err := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	ageOperationSteps(t, c, op.ID, "2020-01-01T00:00:00Z") // old, but must still be skipped
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 0 {
		t.Fatalf("an active, non-terminal op must never be reaped: n=%d err=%v", n, err)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got == nil {
		t.Fatal("active operation must not be tombstoned")
	}
}
