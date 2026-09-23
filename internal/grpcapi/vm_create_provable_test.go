package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// provableCreateServer builds a server that can run CreateVM to completion,
// following pciProducerServer's recipe (hotplug-disk server + image store +
// an active host row for placement) and handing back the libvirt fake so the
// domain-metadata marker can be read afterwards.
func provableCreateServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := hotplugDiskServer(t)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	fake := libvirtfake.New()
	s.virt = fake
	return s, fake
}

// disklessCreateRequest is the smallest create that reaches the durable write:
// no disks, so no image is needed, and one loopback NIC.
func disklessCreateRequest(name string) *pb.CreateVMRequest {
	return &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: "test-host"},
		Network:   []*pb.NetworkAttachment{{Name: "lo", Model: "virtio"}},
	}}
}

// TestCreateVM_IsProvableBeforeItReturns: a fresh VM must carry both
// owner-epoch markers, matching its row, by the time CreateVM returns.
//
// Before this, a create left the row at the column default of 0 with no marker
// at all, and nothing fixed it until the reconciler's next backfill sweep — up
// to reconcileInterval during which a running VM could not prove its ownership
// generation. #145 papered over that window in the detector with a grace keyed
// on created_at, which is replicated LWW input and therefore renewable
// (colonelpanik/litevirt#155).
func TestCreateVM_IsProvableBeforeItReturns(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()

	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v (row=%v)", err, row)
	}
	if row.OwnerEpoch < 1 {
		t.Fatalf("row epoch = %d, want >= 1 — a running VM at the pre-epoch default gets no "+
			"marker at all, because convergeOwnerEpochMarker returns early for one",
			row.OwnerEpoch)
	}

	domEpoch, ok, derr := fake.GetDomainOwnerEpoch("vm1")
	if derr != nil || !ok {
		t.Errorf("domain marker absent after create (ok=%v, err=%v)", ok, derr)
	} else if domEpoch != row.OwnerEpoch {
		t.Errorf("domain marker = %d, row epoch = %d — a marker that disagrees with the row "+
			"is the violation condition 7 exists to report", domEpoch, row.OwnerEpoch)
	}

	fileEpoch, ok, ferr := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1")
	if ferr != nil || !ok {
		t.Errorf("file marker absent after create (ok=%v, err=%v)", ok, ferr)
	} else if fileEpoch != row.OwnerEpoch {
		t.Errorf("file marker = %d, row epoch = %d", fileEpoch, row.OwnerEpoch)
	}
}

// TestCreateVM_AMarkerFailureLeavesAStateConvergenceRepairs: the chosen ordering
// must fail into the self-healing state, not the stuck one.
//
// graduate-then-mark leaves epoch 1 with no marker, which
// convergeOwnerEpochMarker fixes on its next sweep. The reverse order would
// leave marker 1 against epoch 0, which convergence returns early on and never
// repairs — and assertRuntimeOwnership reads as marker_epoch_mismatch, refusing
// that VM's sole-holder re-key for good.
//
// The order is pinned by observing the row AT THE MOMENT the marker is written,
// not by the final state. Checking only the end state does not pin anything: a
// pure reorder still runs the graduation afterwards, so the row still finishes
// at 1 and every end-state assertion passes. That was the original defect in
// this test.
func TestCreateVM_AMarkerFailureLeavesAStateConvergenceRepairs(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	virt := &epochObservingVirt{
		Fake:     fake,
		failWith: context.DeadlineExceeded,
		epochAtCall: func() int64 {
			row, err := corrosion.GetVM(ctx, s.db, "vm1")
			if err != nil || row == nil {
				return -1
			}
			return row.OwnerEpoch
		},
	}
	s.virt = virt

	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM must not fail on a marker write: %v", err)
	}
	if !virt.called {
		t.Fatal("the marker write was never attempted, so this test proves nothing about ordering")
	}
	if virt.seen < 1 {
		t.Errorf("the row was at epoch %d when the marker was written; the epoch must be "+
			"assigned FIRST, or the marker names a generation the row does not have and "+
			"convergeOwnerEpochMarker (which requires a positive epoch) can never repair it",
			virt.seen)
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d after a failed marker write; a marker failure must not cost "+
			"the row its generation", row.OwnerEpoch)
	}
}

// TestAssignOwnerEpochAtCreate_AFailedGraduationStampsNothing: if the row cannot
// be moved off the pre-epoch default, NOTHING may be stamped.
//
// Stamping anyway produces marker-1 against row-0, and every consequence of that
// is permanent: convergeOwnerEpochMarker returns early for an epoch-0 row so it
// never repairs the marker; assertRuntimeOwnership reads the disagreement as
// marker_epoch_mismatch and refuses that VM's legitimate sole-holder re-key for
// good; and the row sitting at 0 keeps OwnerEpochBackfillComplete reporting this
// host unready, so the fleet's owner_epoch_v1 latch never closes. The backfill
// sweep is not a backstop either — it runs only under enforcement.owner_epoch,
// which is off by default.
//
// Called at the seam rather than through CreateVM on purpose. The graduation is
// failed by closing the database, and through CreateVM that fails the INSERT
// too, which skips the whole block — a test that looked like it covered this and
// did not. Verified: reverting the fix must fail THIS test.
func TestAssignOwnerEpochAtCreate_AFailedGraduationStampsNothing(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	// A running domain exists, so a stamp would succeed if one were attempted —
	// otherwise the fake would refuse it for an unrelated reason.
	fake.SetState("vm1", libvirtfake.StateRunning)
	s.db.Close()

	s.assignOwnerEpochAtCreate(ctx, "vm1")

	if epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Errorf("a domain marker of %d was stamped although no row was graduated; a marker "+
			"the row cannot match is never repaired and blocks that VM's re-key", epoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); ok {
		t.Errorf("a file marker of %d was written although no row was graduated", epoch)
	}
}

// TestAssignOwnerEpochAtCreate_StampsBothOnSuccess is the control: the refusal
// above must not be a blanket refusal to ever stamp anything.
func TestAssignOwnerEpochAtCreate_StampsBothOnSuccess(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	s.assignOwnerEpochAtCreate(ctx, "vm1")

	// The postcondition FIRST: without it the two marker assertions below pass in
	// exactly the case the sibling test forbids — a graduation that silently
	// matched no row, leaving marker 1 against a row that is not at 1.
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if row.OwnerEpoch != 1 {
		t.Fatalf("row epoch = %d, want 1 — the markers below are only meaningful if the row "+
			"actually reached the generation they name", row.OwnerEpoch)
	}
	if epoch, ok, err := fake.GetDomainOwnerEpoch("vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("domain marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
	if epoch, ok, err := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
}

// epochObservingVirt records the persisted owner epoch at the instant the domain
// marker is written, so the ordering can be asserted rather than inferred from
// the end state. Injected as a wrapper rather than a flag on the fake, so the
// fake's contract stays the real client's.
type epochObservingVirt struct {
	*libvirtfake.Fake
	// epochAtCall is optional: a reuse that only needs the injected failure, or
	// only the call record, must not have to supply one.
	epochAtCall func() int64
	// failWith, when set, is returned instead of delegating to the fake.
	failWith error
	called   bool
	seen     int64
}

func (v *epochObservingVirt) SetDomainOwnerEpoch(name string, epoch int64, running bool) error {
	v.called = true
	if v.epochAtCall != nil {
		v.seen = v.epochAtCall()
	}
	if v.failWith != nil {
		return v.failWith
	}
	return v.Fake.SetDomainOwnerEpoch(name, epoch, running)
}

// TestClassifyMarker_KeysOffTheSentinelNotTheMessage: a pre-epoch marker must
// classify as CORRUPT even when the error text does not contain "corrupt".
//
// Today it does contain it, so the sentinel branch and the string match agree
// and no end-to-end test can tell them apart. This calls the classifier directly
// with the coupling broken, which is the only way to pin the decoupling — and it
// matters because the two answers are not equally bad. MarkerCorrupt pages
// condition 7 for the one VM; MarkerUnreadable makes collectRuntimeInventory
// fail the whole host's inventory as not-decision-complete, which suppresses
// owner-assert for every workload on that host. One VM's bad marker must not
// silence the checks fleet-wide.
func TestClassifyMarker_KeysOffTheSentinelNotTheMessage(t *testing.T) {
	err := fmt.Errorf("marker for %q names no generation: %w", "vm1", health.ErrPreEpochMarker)
	if got := fmt.Sprint(err); got == "" {
		t.Fatal("unreachable")
	}
	epoch, status := classifyMarker(0, false, err)
	if status != MarkerCorrupt {
		t.Errorf("classifyMarker(pre-epoch sentinel, no \"corrupt\" in the text) = %q, want %q — "+
			"keyed off the message it falls to MarkerUnreadable, which fails the whole host's "+
			"inventory instead of paging one VM", status, MarkerCorrupt)
	}
	if epoch != 0 {
		t.Errorf("epoch = %d, want 0", epoch)
	}
}

// TestAssignOwnerEpochAtCreate_SkipsTheFileMarkerWithoutADataDir: with no data
// directory, no file marker may be written to a RELATIVE path.
//
// readVMMarker treats an empty dataDir as MarkerMissing, so a marker written
// anyway lands under the daemon's working directory where no reader in this
// package looks — a marker on disk while the inventory reports none. The domain
// marker is unaffected and must still be stamped.
func TestAssignOwnerEpochAtCreate_SkipsTheFileMarkerWithoutADataDir(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A clean cwd, so a relative write is detectable rather than lost among the
	// package's own files.
	cwd := t.TempDir()
	t.Chdir(cwd)
	s.dataDir = ""

	s.assignOwnerEpochAtCreate(ctx, "vm1")

	if _, err := os.Stat(filepath.Join(cwd, "vms", "vm1", "owner_epoch")); err == nil {
		t.Error("a file marker was written to a relative path with no dataDir set; no reader " +
			"in this package resolves that path, so it is a marker the inventory cannot see")
	}
	if epoch, ok, err := fake.GetDomainOwnerEpoch("vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("domain marker = (%d,%v,%v), want (1,true,nil) — the file marker being "+
			"skipped must not cost the domain marker", epoch, ok, err)
	}
}

// TestAssignOwnerEpochAtCreate_SurvivesACancelledRPCContext: a client hang-up
// must not decide whether the VM is provable.
//
// By the time this runs the row is committed and the guest is running, so the
// work is post-commit. Inheriting the RPC context means a ^C, or a deadline that
// expired during the preceding image and disk work, fails the graduation — and
// with the failure path correctly stamping nothing, that reliably leaves a
// running VM at epoch 0 with no marker and no backstop unless
// enforcement.owner_epoch happens to be on. The create path already detaches its
// post-commit load-balancer work for the same reason.
func TestAssignOwnerEpochAtCreate_SurvivesACancelledRPCContext(t *testing.T) {
	s, fake := provableCreateServer(t)
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	ctx, cancel := context.WithCancel(adminCtx())
	cancel() // the client is already gone

	s.assignOwnerEpochAtCreate(ctx, "vm1")

	row, err := corrosion.GetVM(adminCtx(), s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if row.OwnerEpoch != 1 {
		t.Errorf("row epoch = %d, want 1 — post-commit provability must not be cancellable by "+
			"the caller that has already been told the VM exists", row.OwnerEpoch)
	}
	if epoch, ok, err := fake.GetDomainOwnerEpoch("vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("domain marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
	if epoch, ok, err := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
}
