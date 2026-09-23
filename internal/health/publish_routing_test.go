package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// startProofReadyToComplete builds the exact precondition CompleteVMStartProof
// needs: a VM pointing at a claimed, non-terminal proof.
func startProofReadyToComplete(t *testing.T, db *corrosion.Client, vm, host string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: vm, HostName: host, Spec: "{}", State: "starting",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, host); err != nil {
		t.Fatalf("BackfillOwnerEpochs: %v", err)
	}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: vm,
		DestHost: host, Coordinator: "coord-1", LeaseHolder: "coord-1",
		QuorumLive: 3, QuorumNeeded: 2,
	}, vm, host); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}
	if err := corrosion.ClaimActionProof(ctx, db, "p1", host); err != nil {
		t.Fatalf("ClaimActionProof: %v", err)
	}
}

// TestReconciler_CompletingAStartProofMarksTheRuntime closes a gap that was
// real, not hypothetical.
//
// CompleteVMStartProof sets state='running' AND vm_owner_epoch = vm_owner_epoch
// + 1 in one guarded batch. One of its two call sites wrote both markers by
// hand; the other — the already-running-domain retry — wrote NEITHER. A VM
// recovered through that branch ran at a fresh generation it could not prove
// until the next convergence sweep, and on a fleet with the default
// enforcement.owner_epoch=false the backfill that would fix it never runs.
func TestReconciler_CompletingAStartProofMarksTheRuntime(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	r := NewReconciler("node-a", dir, db, fake)
	startProofReadyToComplete(t, db, "vm1", "node-a")

	before, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || before == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", before, err)
	}
	if before.OwnerEpoch != 1 {
		t.Fatalf("setup: epoch = %d, want 1", before.OwnerEpoch)
	}

	if err := r.publishRunningMinted(ctx, "vm1", func(ctx context.Context) error {
		return corrosion.CompleteVMStartProof(ctx, db, "p1", "vm1", "node-a")
	}); err != nil {
		t.Fatalf("publishRunningMinted: %v", err)
	}

	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" || row.OwnerEpoch != 2 {
		t.Fatalf("row = %q/epoch %d, want running/2 (the completion mints)", row.State, row.OwnerEpoch)
	}
	epoch, ok, rerr := ReadVMOwnerEpochMarker(dir, "vm1")
	if rerr != nil || !ok || epoch != 2 {
		t.Errorf("file marker = (%d,%v,%v), want (2,true,nil) — a completed start proof "+
			"leaves a running VM that must be able to prove its generation", epoch, ok, rerr)
	}
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 2 {
		t.Errorf("domain marker = (%d,%v), want (2,true)", e, ok)
	}
}

// TestVMChecker_HealingToRunningMarksFirst.
//
// vmcheck heals a stale row toward libvirt reality. That write publishes the VM
// as running on this host, so it goes through the chokepoint like any other.
// Observed from inside the commit: the end state is identical either way.
func TestVMChecker_HealingToRunningMarksFirst(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node1"); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node1", dir, db, nil)

	var stateAtMark string
	err := v.publishRunning(ctx, "vm1", "running", func(ctx context.Context) error {
		if row, _ := corrosion.GetVM(ctx, db, "vm1"); row != nil {
			stateAtMark = row.State
		}
		return corrosion.UpdateVMStateStrict(ctx, db, "vm1", "running", "reconciled from libvirt")
	})
	if err != nil {
		t.Fatalf("publishRunning: %v", err)
	}
	if stateAtMark != "stopped" {
		t.Errorf("row was %q when the marker was written, want stopped", stateAtMark)
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v), want (1,true) — a nil *lv.Client must not stop the "+
			"FILE marker from landing", epoch, ok)
	}
}

// TestVMChecker_ANilConcreteClientDoesNotPanic: v.virt is a *lv.Client, nil in
// nearly every test and on a host whose libvirt connection is down. Boxed into
// DomainEpochSetter it is a NON-nil interface holding a nil pointer.
func TestVMChecker_ANilConcreteClientDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	committed := false
	if err := v.publishRunning(ctx, "vm1", "running", func(context.Context) error {
		committed = true
		return nil
	}); err != nil {
		t.Fatalf("a nil libvirt client must not fail the transition: %v", err)
	}
	if !committed {
		t.Error("a nil libvirt client blocked the transition")
	}
}

// TestVMChecker_AStopIsNotGatedOnMarkers: vmcheck writes "error" and
// "migrating" states through the same helper wherever it is wrapped uniformly.
// Those must never attempt a running-marker write.
func TestVMChecker_AStopIsNotGatedOnMarkers(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node1"); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node1", dir, db, nil)

	if err := v.publishRunning(ctx, "vm1", "error", func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", "error", "health check failed")
	}); err != nil {
		t.Fatalf("a non-running publish must not be gated on markers: %v", err)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a running marker was written for an error state")
	}
}

// TestConvergence_RefusesToStampAVMTheRowSaysBelongsElsewhere.
//
// The publish chokepoint refuses to stamp this host's runtime with a generation
// another host now owns. Convergence — the REPAIR path for exactly that marker —
// had no host check at all: its caller confirms only that the local domain is
// running, which is also true of a domain this host has not yet torn down after
// losing ownership.
//
// runtimeSuperseded decides by `row.OwnerEpoch > marker`, so a marker EQUAL to
// the row reads as current. Stamping here therefore made a superseded runtime
// look live, defeating the comparison for the one case it exists for — through
// the repair path rather than through a publish.
func TestConvergence_RefusesToStampAVMTheRowSaysBelongsElsewhere(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// The row has moved to node-b at a real generation; node-a still runs the
	// domain it has not yet torn down.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-b", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.GraduateVMOwnerEpoch(ctx, db, "vm1"); err != nil {
		t.Fatalf("GraduateVMOwnerEpoch: %v", err)
	}

	r := NewReconciler("node-a", dir, db, fake)
	r.convergeOwnerEpochMarker(ctx, "vm1")

	if epoch, ok, err := ReadVMOwnerEpochMarker(dir, "vm1"); ok || err != nil || epoch != 0 {
		t.Errorf("file marker = (%d, %v, %v), want none — node-a stamped a generation node-b owns",
			epoch, ok, err)
	}
	if epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Errorf("domain marker = %d, want none — node-a stamped a generation node-b owns", epoch)
	}
}

// TestConvergence_StampsAVMThisHostStillOwns is the other half: the check must
// narrow convergence, not disable it. Without this the test above passes on a
// convergence that never stamps anything.
func TestConvergence_StampsAVMThisHostStillOwns(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.GraduateVMOwnerEpoch(ctx, db, "vm1"); err != nil {
		t.Fatalf("GraduateVMOwnerEpoch: %v", err)
	}

	r := NewReconciler("node-a", dir, db, fake)
	r.convergeOwnerEpochMarker(ctx, "vm1")

	epoch, ok, err := ReadVMOwnerEpochMarker(dir, "vm1")
	if err != nil || !ok || epoch != 1 {
		t.Errorf("file marker = (%d, %v, %v), want 1 — convergence must still repair its own VMs",
			epoch, ok, err)
	}
}
