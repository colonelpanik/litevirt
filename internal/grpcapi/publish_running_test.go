package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// publishServer is a create-capable server holding one running VM at a known
// generation, which is the precondition every routed non-minting site shares.
func publishServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := provableCreateServer(t)
	if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)
	return s, fake
}

// TestPersistVMState_RunningMarksBeforeItCommits.
//
// persistVMState is the funnel for the snapshot restore and both StartVM
// writes, so routing it covers three sites at once. Observed from inside the
// commit: the end state is identical either way, which is exactly why nothing
// would otherwise notice the ordering.
func TestPersistVMState_RunningMarksBeforeItCommits(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()

	// Move the row off "running" so the write under test is a real transition.
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 1); err != nil {
		t.Fatal(err)
	}

	obs := &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db}
	s.virt = obs
	if err := s.persistVMState(ctx, "vm1", "running", "test", corrosion.OpVMState); err != nil {
		t.Fatalf("persistVMState: %v", err)
	}
	if !obs.called {
		t.Fatal("the marker write was never attempted, so this test proves nothing about ordering")
	}
	if obs.stateAtMark != "stopped" {
		t.Errorf("row was %q when the marker was written, want stopped — the row must not "+
			"say running before a marker names its generation", obs.stateAtMark)
	}
}

// TestPersistVMState_AStopIsNotGatedOnMarkers.
//
// classifyStop's vocabulary and the operator-stop path both reach here with a
// non-running state. Writing a RUNNING marker for them would be wrong twice
// over: it stamps a generation onto a runtime that is going away, and
// SetDomainOwnerEpoch sends LIVE|CONFIG for running, which libvirt rejects on an
// inactive domain — so the fatal ordering would DROP the stop sync and leave the
// row saying running for a VM that is down.
func TestPersistVMState_AStopIsNotGatedOnMarkers(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()

	obs := &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db, failWith: errors.New("domain is not running")}
	s.virt = obs
	if err := s.persistVMState(ctx, "vm1", "stopped", "operator-stop", corrosion.OpVMState); err != nil {
		t.Fatalf("a stop must not be gated on a running-marker write: %v", err)
	}
	if obs.called {
		t.Error("a running marker was written for a stop")
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "stopped" {
		t.Errorf("state = %q, want stopped — the stop sync was dropped", row.State)
	}
}

// TestPersistVMState_NoMarkerAtAllDoesNotCommitRunning: mark-then-commit's
// refusal, at the RPC layer. Both markers must fail — either alone is enough to
// prove the generation.
func TestPersistVMState_NoMarkerAtAllDoesNotCommitRunning(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	// Fail the domain marker, and make the marker tree uncreatable so the file
	// marker fails too.
	s.virt = &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db, failWith: errors.New("libvirt is down")}
	s.dataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(s.dataDir, "vms"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.persistVMState(ctx, "vm1", "running", "test", corrosion.OpVMState); err == nil {
		t.Error("losing both markers must be returned, not swallowed")
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State == "running" {
		t.Error("the row says running with no marker at all; that publishes an unprovable VM")
	}
}

// stateObservingVirt records the persisted VM STATE at the instant the domain
// marker is written, so mark-before-commit can be asserted rather than inferred
// from an end state that is identical either way. A wrapper, not a flag on the
// fake, so the fake keeps the real client's contract.
type stateObservingVirt struct {
	*libvirtfake.Fake
	ctx         context.Context
	db          *corrosion.Client
	failWith    error
	called      bool
	stateAtMark string
}

func (v *stateObservingVirt) SetDomainOwnerEpoch(name string, epoch int64, running bool) error {
	v.called = true
	if row, err := corrosion.GetVM(v.ctx, v.db, name); err == nil && row != nil {
		v.stateAtMark = row.State
	}
	if v.failWith != nil {
		return v.failWith
	}
	return v.Fake.SetDomainOwnerEpoch(name, epoch, running)
}

// TestRepairVMOwner_MarksTheGenerationTheCommitMinted is why there are two
// orderings rather than one.
//
// TransferVMOwner sets state='running' AND vm_owner_epoch = vm_owner_epoch + 1
// in a single guarded statement, so the value the marker should carry does not
// EXIST until the commit lands. Marking first would stamp the generation the row
// is about to leave — the exact marker/row disagreement the dual-run detector
// reports as condition 7.
func TestRepairVMOwner_MarksTheGenerationTheCommitMinted(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir() // testServer has none, and an empty dataDir skips the file marker
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "host-b", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Graduate the row so the transition is 3 -> 4, not 0 -> 1: an off-by-one in
	// the ordering is invisible when the prior generation is the zero value.
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 3 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)

	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); err != nil {
		t.Fatalf("RepairVMOwner: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", vm, err)
	}
	if vm.OwnerEpoch != 4 {
		t.Fatalf("row epoch = %d, want 4 (the transfer mints)", vm.OwnerEpoch)
	}
	epoch, ok, rerr := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1")
	if rerr != nil || !ok || epoch != 4 {
		t.Errorf("file marker = (%d,%v,%v), want (4,true,nil) — a marker written before a "+
			"minting commit names the generation the row just left", epoch, ok, rerr)
	}
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 4 {
		t.Errorf("domain marker = (%d,%v), want (4,true)", e, ok)
	}
}

// TestRepairVMOwner_AMarkerFailureDoesNotUndoTheRepair is the minting contract's
// opposite half.
//
// The commit has landed and the guest is running, so refusing undoes nothing —
// and a positive epoch with a missing marker is exactly convergeOwnerEpochMarker's
// repair case, whose call site fires for any confirmed-running VM regardless of
// the enforcement flag. Reporting failure here would make an operator re-run a
// repair that already succeeded.
func TestRepairVMOwner_AMarkerFailureDoesNotUndoTheRepair(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "host-b", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)
	s.virt = &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db, failWith: errors.New("libvirt is down")}

	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); err != nil {
		t.Fatalf("a marker failure after a landed commit must not fail the repair: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", vm, err)
	}
	if vm.HostName != "host-a" {
		t.Errorf("owner = %q, want host-a — the repair had already committed", vm.HostName)
	}
}
