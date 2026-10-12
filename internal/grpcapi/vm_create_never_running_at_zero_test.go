package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// failGraduation makes the one statement that moves a vms row off the pre-epoch
// default fail, and ONLY that statement: the trigger fires on an UPDATE that
// names vm_owner_epoch, which the create path's INSERT never does. Closing the
// database instead fails the insert too and skips everything under test.
func failGraduation(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(adminCtx(), `CREATE TRIGGER test_fail_graduation
		BEFORE UPDATE OF vm_owner_epoch ON vms
		BEGIN SELECT RAISE(ABORT, 'injected graduation failure'); END`); err != nil {
		t.Fatalf("install graduation trigger: %v", err)
	}
}

// TestCreateVM_AFailedGraduationIsNeverPublishedRunning: when the first owner
// epoch cannot be assigned, the row stays "creating" for the owner's reconciler
// to finish. It is not published running at epoch 0 — a running VM nothing can
// prove — and the VM is not torn down either.
//
// This is the test that tells the two orderings apart. With the row inserted at
// "running" and graduated afterwards, a failed graduation leaves exactly the
// state colonelpanik/litevirt#157 is about; with the row inserted "creating"
// and flipped only after the epoch and markers exist, it leaves an unpublished
// row the reconciler can finish.
func TestCreateVM_AFailedGraduationIsNeverPublishedRunning(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	failGraduation(t, s)

	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM: %v — a failed graduation is left for the reconciler, not failed to the caller", err)
	}

	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v (row=%v)", err, row)
	}
	if row.State == "running" && row.OwnerEpoch == 0 {
		t.Fatalf("the row was published running at epoch 0 after a failed graduation — a running "+
			"VM that cannot prove its generation (state=%q epoch=%d)", row.State, row.OwnerEpoch)
	}
	if row.State != "creating" {
		t.Errorf("state = %q, want \"creating\" — left for the owner's reconciler to finish", row.State)
	}
	if !fake.DomainExists("vm1") {
		t.Error("the domain was torn down; a failed graduation leaves the VM for the reconciler, it does not undo the create")
	}
	if epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Errorf("a domain marker of %d was stamped against a row still at epoch 0", epoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); ok {
		t.Errorf("a file marker of %d was written against a row still at epoch 0", epoch)
	}
}

// TestCreateVM_TheRowIsNeverRunningAtEpochZero observes the row at the instant
// the domain marker is written — the one point inside the create where the
// ordering is visible — and again once CreateVM returns. At neither point may it
// be running at epoch 0, and at the marker write it must not be running at all:
// the non-minting ordering marks first and commits only once a marker landed.
func TestCreateVM_TheRowIsNeverRunningAtEpochZero(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	var stateAtMark string
	virt := &epochObservingVirt{
		Fake: fake,
		epochAtCall: func() int64 {
			row, err := corrosion.GetVM(ctx, s.db, "vm1")
			if err != nil || row == nil {
				return -1
			}
			stateAtMark = row.State
			return row.OwnerEpoch
		},
	}
	s.virt = virt

	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if !virt.called {
		t.Fatal("the marker write was never attempted, so this test observed nothing")
	}
	if virt.seen < 1 {
		t.Errorf("row epoch at the marker write = %d; the epoch must be assigned before marking", virt.seen)
	}
	if stateAtMark == "running" {
		t.Errorf("the row was already published running when its first marker was written — " +
			"publish-first ordering; the row must be flipped to running only after the markers land")
	}

	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if row.State != "running" || row.OwnerEpoch < 1 {
		t.Errorf("after CreateVM: state=%q epoch=%d, want running at a positive epoch", row.State, row.OwnerEpoch)
	}
}
