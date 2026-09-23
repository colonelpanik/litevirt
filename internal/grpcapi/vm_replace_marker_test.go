package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A cutover's transition MINTS: ReplaceVM installs the replacement at the
// contested name with vm_owner_epoch strictly above both VMs. Every minting
// publish goes through publishRunningMinted, which marks the generation the
// commit produced. Without that, the replaced VM's marker — still on disk at the
// same name, naming the OLD generation — is what runtimeSuperseded reads: row
// above marker says "superseded", and the self-heal rebuild of the replacement is
// refused until a sweep happens to find its domain running.
//
// Asserted at the after-commit boundary, so nothing later in the handoff and no
// convergence sweep can make it pass by accident.
func TestCutover_MarksTheGenerationItsTransitionMinted(t *testing.T) {
	s, _, _, _ := cutoverFixture(t)
	ctx := adminCtx()
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 5 WHERE name = 'app'`); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 3, state = 'running' WHERE name = 'app-next'`); err != nil {
		t.Fatal(err)
	}
	// The replaced VM's own marker, as its create path leaves it on this host.
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "app", 5); err != nil {
		t.Fatal(err)
	}

	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon at the after-commit boundary")
	}

	row, err := corrosion.GetVM(ctx, s.db, "app")
	if err != nil || row == nil {
		t.Fatalf("the transition did not commit: %+v err=%v", row, err)
	}
	if row.OwnerEpoch <= 5 {
		t.Fatalf("transition generation = %d, want above both inputs (5 and 3)", row.OwnerEpoch)
	}
	marker, ok, err := health.ReadVMOwnerEpochMarker(s.dataDir, "app")
	if err != nil || !ok {
		t.Fatalf("no readable marker at the contested name: ok=%v err=%v", ok, err)
	}
	if marker != row.OwnerEpoch {
		t.Fatalf("marker at %q = %d, row = %d: the replaced VM's generation still stands on disk, so the "+
			"replacement reads as superseded and its self-heal rebuild is refused", "app", marker, row.OwnerEpoch)
	}
}
