package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

func seedVM(t *testing.T, db *Client, name, spec string) {
	t.Helper()
	if err := InsertVM(context.Background(), db, VMRecord{
		Name: name, HostName: "n1", State: "running", Spec: spec, CPUActual: 2, MemActual: 4096,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
}

// TestMutateDesiredSpec_GenerationDiscipline: a real change bumps spec_generation
// exactly once; a no-op patch does not bump.
func TestMutateDesiredSpec_GenerationDiscipline(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVM(t, db, "vm1", `{"cpu":2}`)

	applied, gen, err := MutateDesiredSpec(ctx, db, "vm1", func(string) (string, error) { return `{"cpu":4}`, nil })
	if err != nil || !applied || gen != 1 {
		t.Fatalf("first change: applied=%v gen=%d err=%v (want applied,gen=1)", applied, gen, err)
	}
	// No-op: fn returns the spec unchanged → applied, but NO bump.
	applied, gen, err = MutateDesiredSpec(ctx, db, "vm1", func(old string) (string, error) { return old, nil })
	if err != nil || !applied || gen != 1 {
		t.Fatalf("no-op: applied=%v gen=%d err=%v (want applied,gen still 1)", applied, gen, err)
	}
	// Another real change → bump to 2.
	applied, gen, err = MutateDesiredSpec(ctx, db, "vm1", func(string) (string, error) { return `{"cpu":8}`, nil })
	if err != nil || !applied || gen != 2 {
		t.Fatalf("second change: applied=%v gen=%d err=%v (want applied,gen=2)", applied, gen, err)
	}
}

// TestMutateDesiredSpec_DefersOnBarrier: while an operation holds the barrier,
// MutateDesiredSpec must refuse to write and report applied=false.
func TestMutateDesiredSpec_DefersOnBarrier(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVM(t, db, "vm1", `{"cpu":2}`)

	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	ok, err := db.BeginVMOperation(ctx, op, `{"cpu":3}`, 0, 0)
	if err != nil || !ok {
		t.Fatalf("BeginVMOperation: ok=%v err=%v", ok, err)
	}

	applied, _, err := MutateDesiredSpec(ctx, db, "vm1", func(string) (string, error) { return `{"cpu":9}`, nil })
	if err != nil {
		t.Fatalf("MutateDesiredSpec err: %v", err)
	}
	if applied {
		t.Fatal("MutateDesiredSpec must defer (applied=false) while an operation holds the barrier")
	}
	vm, _ := GetVM(ctx, db, "vm1")
	if vm.Spec != `{"cpu":3}` {
		t.Errorf("barrier breached: spec = %q, want the operation's desired {\"cpu\":3}", vm.Spec)
	}
}

// TestMutateDesiredSpec_PreservesUnknownField: an edit to one key must not drop a
// field the writer doesn't know about (forward-compat with a newer peer's spec).
func TestMutateDesiredSpec_PreservesUnknownField(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVM(t, db, "vm1", `{"cpu":2,"future_field":"keep-me"}`)

	applied, _, err := MutateDesiredSpec(ctx, db, "vm1", func(old string) (string, error) {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(old), &raw); err != nil {
			return "", err
		}
		raw["cpu"] = json.RawMessage("4")
		b, err := json.Marshal(raw)
		return string(b), err
	})
	if err != nil || !applied {
		t.Fatalf("MutateDesiredSpec: applied=%v err=%v", applied, err)
	}
	vm, _ := GetVM(ctx, db, "vm1")
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(vm.Spec), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got["future_field"]) != `"keep-me"` {
		t.Errorf("unknown field dropped: spec = %s", vm.Spec)
	}
}

// TestUpdateObservedActuals_CAS: actuals write is gated on owner epoch + generation
// and never bumps the generation.
func TestUpdateObservedActuals_CAS(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVM(t, db, "vm1", `{"cpu":2}`)
	// Bump generation to 1 via a spec change.
	if _, _, err := MutateDesiredSpec(ctx, db, "vm1", func(string) (string, error) { return `{"cpu":4}`, nil }); err != nil {
		t.Fatalf("MutateDesiredSpec: %v", err)
	}

	// Wrong generation → no write.
	applied, err := UpdateObservedActuals(ctx, db, "vm1", 4, 8192, 0, 0)
	if err != nil {
		t.Fatalf("UpdateObservedActuals: %v", err)
	}
	if applied {
		t.Fatal("actuals write should miss on a stale generation")
	}
	// Wrong owner epoch → no write.
	if applied, _ := UpdateObservedActuals(ctx, db, "vm1", 4, 8192, 99, 1); applied {
		t.Fatal("actuals write should miss on a wrong owner epoch")
	}
	// Correct owner + generation → write, and NO generation bump.
	if applied, err := UpdateObservedActuals(ctx, db, "vm1", 4, 8192, 0, 1); err != nil || !applied {
		t.Fatalf("actuals write: applied=%v err=%v", applied, err)
	}
	vm, _ := GetVM(ctx, db, "vm1")
	if vm.CPUActual != 4 || vm.MemActual != 8192 {
		t.Errorf("actuals not written: cpu=%d mem=%d", vm.CPUActual, vm.MemActual)
	}
	if vm.SpecGeneration != 1 {
		t.Errorf("UpdateObservedActuals bumped the generation to %d (must never bump)", vm.SpecGeneration)
	}
}
