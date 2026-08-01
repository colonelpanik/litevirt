package corrosion

import (
	"context"
	"errors"
	"testing"
)

// TransferVMOwner is Phase 4's single ownership-transition primitive: one
// guarded transaction that CASes on the expected owner epoch, increments it,
// and moves host/state together. Every genuine transfer routes through it so
// a stale writer — a rejoined node still believing it owns the VM — loses the
// CAS instead of fighting the real owner with equal-timestamp writes (observed
// live three times on 2026-08-01, each needing a manual repair-owner).

func transferFixture(t *testing.T) (*Client, context.Context) {
	t.Helper()
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm1", HostName: "host-a", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 6 WHERE name = ?`, "vm1"); err != nil {
		t.Fatalf("seed epoch: %v", err)
	}
	return db, ctx
}

func TestTransferVMOwner_MatchingEpochMovesAndIncrements(t *testing.T) {
	db, ctx := transferFixture(t)

	if err := TransferVMOwner(ctx, db, "vm1", "host-b", "pending", 6); err != nil {
		t.Fatalf("TransferVMOwner at the matching epoch: %v", err)
	}
	vm, err := GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "host-b" || vm.State != "pending" {
		t.Errorf("row = %s/%s, want host-b/pending", vm.HostName, vm.State)
	}
	if vm.OwnerEpoch != 7 {
		t.Errorf("owner epoch = %d, want 7 (exactly one increment per transfer)", vm.OwnerEpoch)
	}
}

func TestTransferVMOwner_StaleEpochWritesNothing(t *testing.T) {
	db, ctx := transferFixture(t)

	// A writer that read the row before an intervening transfer holds a stale
	// expected epoch. Its transfer must change NOTHING — not host, not state,
	// not the epoch — or the rejoined-node fight comes back.
	err := TransferVMOwner(ctx, db, "vm1", "host-c", "running", 5)
	if !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("stale transfer: err = %v, want ErrNoRowsAffected", err)
	}
	vm, gerr := GetVM(ctx, db, "vm1")
	if gerr != nil || vm == nil {
		t.Fatalf("GetVM: %v", gerr)
	}
	if vm.HostName != "host-a" || vm.State != "running" || vm.OwnerEpoch != 6 {
		t.Errorf("stale transfer mutated the row: %s/%s epoch=%d, want host-a/running epoch=6",
			vm.HostName, vm.State, vm.OwnerEpoch)
	}
}

func TestTransferVMOwner_DeletedOrMissingVMWritesNothing(t *testing.T) {
	db, ctx := transferFixture(t)

	if err := TransferVMOwner(ctx, db, "no-such-vm", "host-b", "pending", 0); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("missing VM: err = %v, want ErrNoRowsAffected", err)
	}
	if err := DeleteVM(ctx, db, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if err := TransferVMOwner(ctx, db, "vm1", "host-b", "pending", 6); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("tombstoned VM: err = %v, want ErrNoRowsAffected", err)
	}
}

func TestTransferVMOwnerFresh_IncrementsFromCurrentRow(t *testing.T) {
	db, ctx := transferFixture(t)

	if err := TransferVMOwnerFresh(ctx, db, "vm1", "host-b", "running"); err != nil {
		t.Fatalf("TransferVMOwnerFresh: %v", err)
	}
	vm, _ := GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "host-b" || vm.OwnerEpoch != 7 {
		t.Fatalf("fresh transfer: got %+v, want host-b epoch 7", vm)
	}
	if err := TransferVMOwnerFresh(ctx, db, "absent", "host-b", "running"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("missing VM: err = %v, want ErrNoRowsAffected", err)
	}
}
