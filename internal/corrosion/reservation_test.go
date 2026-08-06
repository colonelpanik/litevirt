package corrosion

import (
	"context"
	"testing"
)

func mustOp(t *testing.T, db *Client, id, kind, resJSON string, terminal bool) {
	t.Helper()
	ctx := context.Background()
	if err := InsertOperation(ctx, db, OperationRecord{
		ID: id, Method: "m", ResourceKind: "vm", ResourceID: id,
		OperationKind: kind, RequestHash: "h", ReservationJSON: resJSON,
	}); err != nil {
		t.Fatalf("InsertOperation: %v", err)
	}
	if err := AppendOperationStep(ctx, db, OperationStepRecord{OperationID: id, StepName: OpStepPlanned}); err != nil {
		t.Fatalf("append planned: %v", err)
	}
	if terminal {
		if err := AppendOperationStep(ctx, db, OperationStepRecord{OperationID: id, StepName: OpStepCompleted}); err != nil {
			t.Fatalf("append completed: %v", err)
		}
	}
}

// TestHostFreeCapacity: free = total - running actuals - nonterminal reservations;
// a TERMINAL operation's reservation is not counted.
func TestHostFreeCapacity(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertHost(ctx, db, HostRecord{Name: "h1", CPUTotal: 32, MemTotal: 65536, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// A running VM consumes committed capacity.
	if err := InsertVM(ctx, db, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}", CPUActual: 4, MemActual: 8192}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A nonterminal op reserves a grow delta on h1.
	rv := ReservationVector{TargetHost: "h1", TargetCPU: 8, TargetMemMiB: 16384}
	enc, _ := rv.Encode()
	mustOp(t, db, "grow-op", string(OpResourceUpdateRunning), enc, false)
	// A TERMINAL op's reservation must NOT count.
	rvDone := ReservationVector{TargetHost: "h1", TargetCPU: 100, TargetMemMiB: 100000}
	encDone, _ := rvDone.Encode()
	mustOp(t, db, "done-op", string(OpResourceUpdateRunning), encDone, true)

	// Neutral policy (ratio 1, no reserve, no per-VM overhead) isolates the
	// subtraction this test is about from capacity POLICY, which has its own
	// tests. Under it the arithmetic is the original raw one.
	neutral := CapacityPolicy{CPUOvercommit: 1, MemOvercommit: 1, VMMemOverheadMiB: 0}
	freeCPU, freeMem, ok, err := HostFreeCapacityWithPolicy(ctx, db, "h1", neutral)
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacity: ok=%v err=%v", ok, err)
	}
	// 32 - 4 (running) - 8 (reserved) = 20 ; 65536 - 8192 - 16384 = 40960
	if freeCPU != 20 {
		t.Errorf("freeCPU = %d, want 20", freeCPU)
	}
	if freeMem != 40960 {
		t.Errorf("freeMem = %d, want 40960", freeMem)
	}

	// And with the DEFAULT policy the same host reports MORE cpu (4x ratio, less
	// 1 reserved) and LESS memory (5% reserve + one VM's qemu overhead) — proving
	// the policy is actually applied rather than silently ignored.
	defCPU, defMem, ok, err := HostFreeCapacity(ctx, db, "h1")
	if err != nil || !ok {
		t.Fatalf("HostFreeCapacity (default policy): ok=%v err=%v", ok, err)
	}
	if defCPU <= freeCPU {
		t.Errorf("default-policy freeCPU = %d, want more than the neutral %d (4x overcommit)", defCPU, freeCPU)
	}
	if defMem >= freeMem {
		t.Errorf("default-policy freeMem = %d, want less than the neutral %d (host reserve + qemu overhead)", defMem, freeMem)
	}
}

func TestProjectReserved_OnlyNonterminal(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	rv := ReservationVector{Project: "acme", ProjectCPU: 6, ProjectMemMiB: 12288}
	enc, _ := rv.Encode()
	mustOp(t, db, "p-live", string(OpResourceUpdateRunning), enc, false)
	rvDone := ReservationVector{Project: "acme", ProjectCPU: 99, ProjectMemMiB: 99}
	encDone, _ := rvDone.Encode()
	mustOp(t, db, "p-done", string(OpResourceUpdateRunning), encDone, true)

	cpu, mem, err := ProjectReserved(ctx, db, "acme")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if cpu != 6 || mem != 12288 {
		t.Errorf("project reserved = (%d,%d), want (6,12288)", cpu, mem)
	}
}
