package corrosion

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDeterministicOperationID(t *testing.T) {
	a := DeterministicOperationID("UpdateVM", "user:alice@local", "proj", "vm1", "key1")
	if a != DeterministicOperationID("UpdateVM", "user:alice@local", "proj", "vm1", "key1") {
		t.Fatal("id must be deterministic for identical inputs")
	}
	if a == DeterministicOperationID("UpdateVM", "user:alice@local", "proj", "vm1", "key2") {
		t.Fatal("a different idempotency key must yield a different id")
	}
	// Length-prefixing prevents field-boundary collisions.
	if DeterministicOperationID("ab", "", "", "", "c") == DeterministicOperationID("a", "", "", "", "bc") {
		t.Fatal("field-boundary collision — length-prefixing failed")
	}
}

func TestReduceOperationState(t *testing.T) {
	cases := []struct {
		name    string
		kind    OperationKind
		steps   []string
		want    string
		faulted bool
	}{
		{"furthest happy-path", OpResourceUpdateRunning,
			[]string{OpStepPlanned, OpStepReserved, OpStepDesiredPersisted}, OpStepDesiredPersisted, false},
		{"completed dominates delayed nonterminal", OpResourceUpdateRunning,
			[]string{OpStepPlanned, OpStepReserved, OpStepCompleted, OpStepObserved}, OpStepCompleted, false},
		{"completed + failed is a fault (completed wins)", OpRestart,
			[]string{OpStepCompleted, OpStepFailed}, OpStepCompleted, true},
		{"failed + cancelled is a fault", OpDeviceLease,
			[]string{OpStepFailed, OpStepCancelled}, OpStepFailed, true},
		{"cancelled alone", OpResourceUpdateStopped,
			[]string{OpStepPlanned, OpStepCancelled}, OpStepCancelled, false},
		{"superseded (older epoch takeover)", OpResourceUpdateRunning,
			[]string{OpStepPlanned, OpStepSuperseded}, OpStepSuperseded, false},
		{"rollback completed, no terminal", OpDeviceLease,
			[]string{OpStepPlanned, OpStepReserved, OpStepRollbackCompleted}, OpStepRollbackCompleted, false},
		{"empty", OpRestart, nil, "", false},
		{"device_attach furthest happy-path", OpDeviceAttach,
			[]string{OpStepPlanned, OpStepReserved, OpStepClaimed, OpStepBound, OpStepAttached}, OpStepAttached, false},
		{"device_attach completed dominates", OpDeviceAttach,
			[]string{OpStepPlanned, OpStepReserved, OpStepClaimed, OpStepBound, OpStepAttached, OpStepCompleted}, OpStepCompleted, false},
		{"device_detach furthest happy-path", OpDeviceDetach,
			[]string{OpStepPlanned, OpStepReserved, OpStepAttached}, OpStepAttached, false},
		{"device_detach completed dominates", OpDeviceDetach,
			[]string{OpStepPlanned, OpStepReserved, OpStepAttached, OpStepCompleted}, OpStepCompleted, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, faulted := ReduceOperationState(tc.kind, tc.steps)
			if got != tc.want || faulted != tc.faulted {
				t.Fatalf("Reduce(%v)=(%q,%v), want (%q,%v)", tc.steps, got, faulted, tc.want, tc.faulted)
			}
		})
	}
}

func TestIsLegalStep(t *testing.T) {
	if !IsLegalStep(OpDeviceLease, OpStepClaimed) {
		t.Error("claimed is legal for device_lease")
	}
	if IsLegalStep(OpDeviceLease, OpStepLiveApplied) {
		t.Error("live_applied is NOT a device_lease step")
	}
	if !IsLegalStep(OpResourceUpdateRunning, OpStepFailed) {
		t.Error("failed is a legal terminal for any kind")
	}
	if !IsLegalStep(OpDeviceAttach, OpStepAttached) {
		t.Error("attached is legal for device_attach")
	}
	if !IsLegalStep(OpDeviceDetach, OpStepAttached) {
		t.Error("attached is legal for device_detach")
	}
	if IsLegalStep(OpDeviceDetach, OpStepBound) {
		t.Error("bound is NOT a device_detach step")
	}
	if !IsOperationKind(OpDeviceAttach) {
		t.Error("device_attach must be a recognized operation kind")
	}
	if !IsOperationKind(OpDeviceDetach) {
		t.Error("device_detach must be a recognized operation kind")
	}
}

func TestClaimOrFindOperation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	id := DeterministicOperationID("UpdateVM", "user:alice@local", "", "vm1", "k1")
	op := OperationRecord{ID: id, Method: "UpdateVM", Principal: "user:alice@local",
		ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(OpResourceUpdateRunning),
		RequestHash: "hashA", IdempotencyKey: "k1", VMOwnerEpoch: 1}

	got, created, err := ClaimOrFindOperation(ctx, c, op)
	if err != nil || !created || got.ID != id {
		t.Fatalf("first claim: created=%v err=%v", created, err)
	}
	// Same request hash → find existing, not created.
	got, created, err = ClaimOrFindOperation(ctx, c, op)
	if err != nil || created {
		t.Fatalf("second identical claim should find, not create: created=%v err=%v", created, err)
	}
	// Same id, different request hash → conflict.
	op2 := op
	op2.RequestHash = "hashB"
	if _, _, err := ClaimOrFindOperation(ctx, c, op2); !errors.Is(err, ErrOperationHashConflict) {
		t.Fatalf("different request hash must conflict, got %v", err)
	}
}

func TestAppendOperationStep_Idempotency(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	step := OperationStepRecord{OperationID: "op1", OwnerEpoch: 1, StepName: OpStepReserved, Facts: `{"res":"r1"}`}

	if err := AppendOperationStep(ctx, c, step); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Re-append with identical facts → idempotent no-op.
	if err := AppendOperationStep(ctx, c, step); err != nil {
		t.Fatalf("idempotent re-append: %v", err)
	}
	// Same key, different facts → corruption.
	conflict := step
	conflict.Facts = `{"res":"r2"}`
	if err := AppendOperationStep(ctx, c, conflict); !errors.Is(err, ErrOperationStepConflict) {
		t.Fatalf("differing facts must conflict, got %v", err)
	}

	steps, err := ListOperationSteps(ctx, c, "op1", 1)
	if err != nil || len(steps) != 1 {
		t.Fatalf("expected exactly one step, got %d (err=%v)", len(steps), err)
	}

	// A different owner epoch is a distinct key.
	if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: "op1", OwnerEpoch: 2, StepName: OpStepReserved, Facts: "x"}); err != nil {
		t.Fatalf("append at epoch 2: %v", err)
	}
	if steps, _ := ListOperationSteps(ctx, c, "op1", 2); len(steps) != 1 {
		t.Fatalf("epoch 2 should have its own step, got %d", len(steps))
	}
}

func TestOperationCurrentState(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	for _, s := range []string{OpStepPlanned, OpStepReserved, OpStepClaimed} {
		if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: "op1", OwnerEpoch: 1, StepName: s}); err != nil {
			t.Fatalf("append %s: %v", s, err)
		}
	}
	state, faulted, err := OperationCurrentState(ctx, c, "op1", 1, OpDeviceLease)
	if err != nil || faulted || state != OpStepClaimed {
		t.Fatalf("state=%q faulted=%v err=%v, want claimed", state, faulted, err)
	}
}

func TestWorkloadCreateOperationState(t *testing.T) {
	want := []string{
		OpStepPlanned,
		OpStepReserved,
		OpStepDesiredPersisted,
		OpStepPrepared,
		OpStepRuntimeStarted,
		OpStepObserved,
	}
	if got := opHappyPath[OpWorkloadCreate]; !reflect.DeepEqual(got, want) {
		t.Fatalf("workload-create happy path = %v, want %v", got, want)
	}
	if !IsOperationKind(OpWorkloadCreate) {
		t.Fatal("workload_create must be a recognized operation kind")
	}
	for _, step := range want {
		if !IsLegalStep(OpWorkloadCreate, step) {
			t.Errorf("%q must be legal for workload_create", step)
		}
	}
	if IsLegalStep(OpWorkloadCreate, OpStepConfigApplied) {
		t.Fatal("config_applied must not be legal for workload_create")
	}

	state, faulted := ReduceOperationState(OpWorkloadCreate, want[:len(want)-1])
	if state != OpStepRuntimeStarted || faulted {
		t.Fatalf("pre-observation state = (%q,%v), want (%q,false)", state, faulted, OpStepRuntimeStarted)
	}
	state, faulted = ReduceOperationState(OpWorkloadCreate,
		[]string{OpStepPlanned, OpStepRuntimeStarted, OpStepRollbackCompleted})
	if state != OpStepRollbackCompleted || faulted {
		t.Fatalf("rollback precedence = (%q,%v), want (%q,false)", state, faulted, OpStepRollbackCompleted)
	}
	state, faulted = ReduceOperationState(OpWorkloadCreate,
		[]string{OpStepCompleted, OpStepFailed, OpStepRollbackCompleted})
	if state != OpStepCompleted || !faulted {
		t.Fatalf("terminal conflict = (%q,%v), want (%q,true)", state, faulted, OpStepCompleted)
	}
}

func TestWorkloadStartOperationState(t *testing.T) {
	want := []string{
		OpStepPlanned,
		OpStepReserved,
		OpStepRuntimeStarted,
		OpStepObserved,
	}
	if got := opHappyPath[OpWorkloadStart]; !reflect.DeepEqual(got, want) {
		t.Fatalf("workload-start happy path = %v, want %v", got, want)
	}
	if !IsOperationKind(OpWorkloadStart) {
		t.Fatal("workload_start must be a recognized operation kind")
	}
	for _, step := range want {
		if !IsLegalStep(OpWorkloadStart, step) {
			t.Errorf("%q must be legal for workload_start", step)
		}
	}
	if IsLegalStep(OpWorkloadStart, OpStepDesiredPersisted) {
		t.Fatal("desired_persisted must not be legal for workload_start")
	}

	state, faulted := ReduceOperationState(OpWorkloadStart,
		[]string{OpStepPlanned, OpStepReserved, OpStepRuntimeStarted})
	if state != OpStepRuntimeStarted || faulted {
		t.Fatalf("start progress = (%q,%v), want (%q,false)", state, faulted, OpStepRuntimeStarted)
	}
	state, faulted = ReduceOperationState(OpWorkloadStart,
		[]string{OpStepObserved, OpStepCancelled, OpStepRollbackCompleted})
	if state != OpStepCancelled || faulted {
		t.Fatalf("terminal precedence = (%q,%v), want (%q,false)", state, faulted, OpStepCancelled)
	}
}

func TestWorkloadCreateAndStartTerminalReleasesReservation(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	for _, tc := range []struct {
		id   string
		kind OperationKind
	}{
		{id: "create", kind: OpWorkloadCreate},
		{id: "start", kind: OpWorkloadStart},
	} {
		reservation, err := (ReservationVector{
			TargetHost: "h1",
			TargetCPU:  2,
		}).Encode()
		if err != nil {
			t.Fatalf("%s encode reservation: %v", tc.id, err)
		}
		mustOp(t, db, tc.id, string(tc.kind), reservation, false)
	}

	cpu, _, err := HostReserved(ctx, db, "h1")
	if err != nil {
		t.Fatalf("HostReserved before terminal: %v", err)
	}
	if cpu != 4 {
		t.Fatalf("reserved CPU before terminal = %d, want 4", cpu)
	}

	for _, id := range []string{"create", "start"} {
		if err := AppendOperationStep(ctx, db, OperationStepRecord{
			OperationID: id,
			StepName:    OpStepCompleted,
		}); err != nil {
			t.Fatalf("%s complete: %v", id, err)
		}
	}
	cpu, _, err = HostReserved(ctx, db, "h1")
	if err != nil {
		t.Fatalf("HostReserved after terminal: %v", err)
	}
	if cpu != 0 {
		t.Fatalf("reserved CPU after terminal = %d, want 0", cpu)
	}
}
