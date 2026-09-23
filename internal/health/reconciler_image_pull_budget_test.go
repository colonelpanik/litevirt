package health

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// reconcilePass hands the pending-VM walk a context bounded by
// reconcileWalkBudget, and startPendingVM passes that context straight into
// autoPullImage — a streaming transfer of a whole backing image from a peer.
//
// A transfer that needs longer than the remaining budget is cancelled on every
// attempt. ImportImage removes its temporary file when its stream is cancelled,
// so the next pass starts the transfer from byte zero, and a VM whose backing
// image is merely LARGE never recovers: three attempts, three cancellations,
// zero bytes kept.
//
// The budget exists so the safety sweeps after the walk run on their tick. It
// must not also be the transfer's deadline. The transfer continues in the
// background past the walk; the walk stays bounded; the VM starts on a later
// pass once the image is present.
func TestReconcilePass_ABackingImagePullOutlivesTheWalkBudget(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-pull", HostName: "host-a", State: "pending",
		Spec: `{"name":"vm-pull","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: "vm-pull", DiskName: "root", HostName: "host-a",
		Path:         store.DiskPath("vm-pull", "root"), // absent: the overlay was lost with the old host
		BackingImage: "base",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	origBudget := reconcileWalkBudget
	reconcileWalkBudget = 200 * time.Millisecond
	t.Cleanup(func() { reconcileWalkBudget = origBudget })

	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)

	// A transfer that takes longer than the walk budget. It honours its context
	// — a cancelled stream is how the real one fails — and lands the image only
	// when the test lets it finish.
	var pulls atomic.Int32
	release := make(chan struct{})
	pullCtxs := make(chan context.Context, 8)
	r.SetAutoPullImage(func(pctx context.Context, name string) error {
		pulls.Add(1)
		pullCtxs <- pctx
		select {
		case <-release:
		case <-pctx.Done():
			return pctx.Err()
		}
		if _, err := os.Stat(store.ImagePath(name)); err == nil {
			return nil
		}
		return qcow2.Create(store.ImagePath(name), 64<<20, nil)
	})

	start := time.Now()
	r.ReconcileOnce(ctx)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("one reconcile pass took %v with a transfer in flight; the walk is no longer "+
			"bounded and the safety sweeps behind it are delayed", elapsed)
	}
	if pulls.Load() != 1 {
		t.Fatalf("fixture inert: autoPullImage ran %d times, want 1", pulls.Load())
	}
	pctx := <-pullCtxs
	if err := pctx.Err(); err != nil {
		t.Fatalf("the transfer's context is %v after the walk budget expired.\n"+
			"A backing image that needs longer than the budget is cancelled on every "+
			"attempt, ImportImage discards the partial file on cancellation, and the next "+
			"pass starts from scratch — recovery of a VM with a large image never completes.", err)
	}

	// The walk gave up on this VM for the pass, but it did NOT fail the VM: the
	// row is left in a state the next pass re-drives, with a reason. This start
	// carries no proof, so that state is "starting", not "pending" — see
	// TestReconcilePass_ADeferredLocalRecoveryIsNotRefusedAsProofMissing.
	vm, err := corrosion.GetVM(ctx, db, "vm-pull")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "starting" {
		t.Fatalf("state = %q after the walk moved on, want starting (detail %q)", vm.State, vm.StateDetail)
	}
	if !strings.Contains(vm.StateDetail, "base") {
		t.Errorf("state_detail = %q, want it to name the image being pulled", vm.StateDetail)
	}

	// A second pass while the transfer is still running must join it, not
	// start a second transfer of the same image.
	r.ReconcileOnce(ctx)
	if pulls.Load() != 1 {
		t.Fatalf("a second pass started transfer %d while the first was still running; "+
			"every pass would open another stream for the same image", pulls.Load())
	}

	// The transfer completes. A later pass finds the image and starts the VM.
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for !startedOrDefined(fake, "vm-pull") && time.Now().Before(deadline) {
		r.ReconcileOnce(ctx)
		time.Sleep(20 * time.Millisecond)
	}
	if !startedOrDefined(fake, "vm-pull") {
		vm, _ := corrosion.GetVM(ctx, db, "vm-pull")
		t.Fatalf("the VM never started after its image finished transferring; row = %q / %q",
			vm.State, vm.StateDetail)
	}
	if _, err := os.Stat(store.DiskPath("vm-pull", "root")); err != nil {
		t.Errorf("the overlay was not rebuilt on the pulled image: %v", err)
	}
}

// The other side of the same coin: with NO deadline on the caller's context —
// the onboot start path, and the fleet harness — the pull is awaited in place
// exactly as before, so nothing that used to start on its first pass now needs
// a second one.
func TestStartPendingVM_AnUnboundedCallerStillAwaitsThePull(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-pull", HostName: "host-a", State: "pending",
		Spec: `{"name":"vm-pull","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: "vm-pull", DiskName: "root", HostName: "host-a",
		Path: store.DiskPath("vm-pull", "root"), BackingImage: "base",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)
	r.SetAutoPullImage(func(pctx context.Context, name string) error {
		select {
		case <-time.After(150 * time.Millisecond):
		case <-pctx.Done():
			return pctx.Err()
		}
		return qcow2.Create(store.ImagePath(name), 64<<20, nil)
	})

	r.reconcile(ctx) // unbounded: awaits the transfer

	if !startedOrDefined(fake, "vm-pull") {
		vm, _ := corrosion.GetVM(ctx, db, "vm-pull")
		t.Fatalf("an unbounded caller no longer starts the VM on the pass that pulled its "+
			"image; row = %q / %q", vm.State, vm.StateDetail)
	}
}

// A LOCAL recovery — onboot autostart, or a domain that died under a running
// row — carries no action proof: it is not an ownership transfer. Under the
// split-brain gate a markerless PENDING row is refused as proof_missing, by
// design, because the coordinator writes pending and its proof marker
// atomically and a pending row without one is stale or hand-mutated.
//
// So a deferred local start must not be parked in pending. The walk budget
// expired mid-transfer, the VM was re-armed as pending, and every later pass
// refused it — even after the image finished — leaving the VM permanently
// unstarted for having a large image. A markerless "starting" row is the
// documented shape of an interrupted local start and is re-driven.
func TestReconcilePass_ADeferredLocalRecoveryIsNotRefusedAsProofMissing(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	// Domain-died recovery: the row says running, libvirt has no such domain.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-local", HostName: "host-a", State: "running",
		Spec: `{"name":"vm-local","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: "vm-local", DiskName: "root", HostName: "host-a",
		Path: store.DiskPath("vm-local", "root"), BackingImage: "base",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	origBudget := reconcileWalkBudget
	reconcileWalkBudget = 200 * time.Millisecond
	t.Cleanup(func() { reconcileWalkBudget = origBudget })

	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true}) // enforced

	var refusals []string
	r.SetGateRefusedObserver(func(_, reason string) { refusals = append(refusals, reason) })

	release := make(chan struct{})
	r.SetAutoPullImage(func(pctx context.Context, name string) error {
		select {
		case <-release:
		case <-pctx.Done():
			return pctx.Err()
		}
		if _, err := os.Stat(store.ImagePath(name)); err == nil {
			return nil
		}
		return qcow2.Create(store.ImagePath(name), 64<<20, nil)
	})

	r.ReconcileOnce(ctx) // budget expires mid-transfer; the start is deferred

	vm, err := corrosion.GetVM(ctx, db, "vm-local")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State == "pending" {
		t.Errorf("a proof-less local recovery was deferred into %q; under the split-brain "+
			"gate a markerless pending row is refused as proof_missing on every later pass", vm.State)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for !startedOrDefined(fake, "vm-local") && time.Now().Before(deadline) {
		r.ReconcileOnce(ctx)
		time.Sleep(20 * time.Millisecond)
	}
	if !startedOrDefined(fake, "vm-local") {
		vm, _ := corrosion.GetVM(ctx, db, "vm-local")
		t.Fatalf("the local recovery never started after its image finished transferring; "+
			"row = %q / %q, refusals = %v", vm.State, vm.StateDetail, refusals)
	}
	for _, reason := range refusals {
		if reason == ReasonProofMissing {
			t.Fatalf("a local recovery was refused as proof_missing: %v", refusals)
		}
	}
}

// The mirror: a start that IS an ownership transfer carries a proof, and its
// deferral goes back to pending with the marker still on the row, so the
// re-drive re-validates and re-claims the same proof and the transfer finishes
// once the image is present.
func TestReconcilePass_ADeferredTransferKeepsItsProofMarker(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-xfer", HostName: "host-b", State: "running",
		Spec: `{"name":"vm-xfer","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName: "vm-xfer", DiskName: "root", HostName: "host-a",
		Path: store.DiskPath("vm-xfer", "root"), BackingImage: "base",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	// The coordinator reschedules it onto host-a: pending + marker, atomically.
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-xfer", DestHost: "host-a", Coordinator: "host-c"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm-xfer", "host-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}

	origBudget := reconcileWalkBudget
	reconcileWalkBudget = 200 * time.Millisecond
	t.Cleanup(func() { reconcileWalkBudget = origBudget })

	fake := libvirtfake.New()
	r := NewReconciler("host-a", dataDir, db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	release := make(chan struct{})
	r.SetAutoPullImage(func(pctx context.Context, name string) error {
		select {
		case <-release:
		case <-pctx.Done():
			return pctx.Err()
		}
		if _, err := os.Stat(store.ImagePath(name)); err == nil {
			return nil
		}
		return qcow2.Create(store.ImagePath(name), 64<<20, nil)
	})

	r.ReconcileOnce(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm-xfer")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "pending" || vm.PendingActionID != "p1" {
		t.Fatalf("deferred transfer = %q / marker %q, want pending with marker p1 so the re-drive "+
			"re-claims the same proof", vm.State, vm.PendingActionID)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for !startedOrDefined(fake, "vm-xfer") && time.Now().Before(deadline) {
		r.ReconcileOnce(ctx)
		time.Sleep(20 * time.Millisecond)
	}
	if !startedOrDefined(fake, "vm-xfer") {
		vm, _ := corrosion.GetVM(ctx, db, "vm-xfer")
		t.Fatalf("the transfer never started after its image arrived; row = %q / %q", vm.State, vm.StateDetail)
	}
}
