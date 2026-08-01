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

// Phase 4 step 3b: relocation completion mints the container's next ownership
// generation in the same guarded write that flips pending→running — the
// container half of read-old → prove → move → mint-new. Guarded on the pending
// state + exact token so a retry can't double-mint and an unrelated row can't
// be touched.
func TestCompleteContainerRelocation_MintsOnce(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := UpsertContainer(ctx, db, ContainerRecord{
		HostName: "host-b", Name: "ct1", State: "pending",
		StateDetail: ContainerRelocateRecreateDetail, Image: "alpine",
		RelocateToken: "tok-1",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := db.Execute(ctx,
		`UPDATE containers SET owner_epoch = 5 WHERE host_name = ? AND name = ?`,
		"host-b", "ct1"); err != nil {
		t.Fatalf("seed epoch: %v", err)
	}

	// Wrong token: nothing happens.
	if err := CompleteContainerRelocation(ctx, db, "host-b", "ct1", "tok-WRONG"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("wrong token: err = %v, want ErrNoRowsAffected", err)
	}
	// Right token: running + minted exactly once.
	if err := CompleteContainerRelocation(ctx, db, "host-b", "ct1", "tok-1"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	ct, _ := GetContainer(ctx, db, "host-b", "ct1")
	if ct == nil || ct.State != "running" || ct.OwnerEpoch != 6 {
		t.Fatalf("after completion: %+v, want running epoch 6", ct)
	}
	// Re-run is a no-op (no longer pending) — never a double mint.
	if err := CompleteContainerRelocation(ctx, db, "host-b", "ct1", "tok-1"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("re-complete: err = %v, want ErrNoRowsAffected", err)
	}
	ct, _ = GetContainer(ctx, db, "host-b", "ct1")
	if ct.OwnerEpoch != 6 {
		t.Fatalf("double mint: epoch %d, want 6", ct.OwnerEpoch)
	}
}

// Phase 4 backfill: with enforcement.owner_epoch on, each host graduates the
// workloads IT OWNS out of the pre-epoch 0 (0→1), and readiness — the gate on
// advertising owner_epoch_v1 — is "no owned workload left at 0". Only owned,
// live rows are touched: another host's workloads are its own to graduate,
// and tombstones stay pre-epoch forever.
func TestBackfillOwnerEpochs(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, vm := range []VMRecord{
		{Name: "mine-0", HostName: "host-a", State: "running", Spec: "{}"},
		{Name: "theirs-0", HostName: "host-b", State: "running", Spec: "{}"},
		{Name: "mine-7", HostName: "host-a", State: "running", Spec: "{}"},
	} {
		if err := InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'mine-7'`); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, db, ContainerRecord{
		HostName: "host-a", Name: "ct-0", State: "running", Image: "alpine",
	}); err != nil {
		t.Fatal(err)
	}

	ready, err := OwnerEpochBackfillComplete(ctx, db, "host-a")
	if err != nil || ready {
		t.Fatalf("pre-backfill readiness = (%v,%v), want (false,nil)", ready, err)
	}

	if err := BackfillOwnerEpochs(ctx, db, "host-a"); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	vm0, _ := GetVM(ctx, db, "mine-0")
	if vm0.OwnerEpoch != 1 {
		t.Fatalf("owned pre-epoch VM = %d, want 1", vm0.OwnerEpoch)
	}
	vm7, _ := GetVM(ctx, db, "mine-7")
	if vm7.OwnerEpoch != 7 {
		t.Fatalf("already-graduated VM must be untouched: %d, want 7", vm7.OwnerEpoch)
	}
	other, _ := GetVM(ctx, db, "theirs-0")
	if other.OwnerEpoch != 0 {
		t.Fatalf("another host's VM must be untouched: %d, want 0", other.OwnerEpoch)
	}
	ct, _ := GetContainer(ctx, db, "host-a", "ct-0")
	if ct.OwnerEpoch != 1 {
		t.Fatalf("owned pre-epoch container = %d, want 1", ct.OwnerEpoch)
	}

	ready, err = OwnerEpochBackfillComplete(ctx, db, "host-a")
	if err != nil || !ready {
		t.Fatalf("post-backfill readiness = (%v,%v), want (true,nil)", ready, err)
	}
	// Readiness must consider BOTH workload kinds independently: with every VM
	// graduated, a single ungraduated CONTAINER still blocks advertisement —
	// otherwise a node could latch owner_epoch_v1 with pre-epoch containers it
	// would then be expected to enforce marker/epoch agreement for.
	if err := db.Execute(ctx,
		`UPDATE containers SET owner_epoch = 0 WHERE host_name = ? AND name = ?`,
		"host-a", "ct-0"); err != nil {
		t.Fatal(err)
	}
	if ready, err := OwnerEpochBackfillComplete(ctx, db, "host-a"); err != nil || ready {
		t.Fatalf("an ungraduated container must block readiness: (%v,%v), want (false,nil)", ready, err)
	}
	if err := db.Execute(ctx,
		`UPDATE containers SET owner_epoch = 1 WHERE host_name = ? AND name = ?`,
		"host-a", "ct-0"); err != nil {
		t.Fatal(err)
	}
	// Idempotent: a second pass changes nothing.
	if err := BackfillOwnerEpochs(ctx, db, "host-a"); err != nil {
		t.Fatalf("re-backfill: %v", err)
	}
	if vm0b, _ := GetVM(ctx, db, "mine-0"); vm0b.OwnerEpoch != 1 {
		t.Fatalf("re-backfill double-stamped: %d, want 1", vm0b.OwnerEpoch)
	}
}
