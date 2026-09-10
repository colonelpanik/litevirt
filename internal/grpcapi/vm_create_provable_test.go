package grpcapi

import (
	"context"
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
// repairs. This pins the order by asserting the epoch survives a marker failure.
func TestCreateVM_AMarkerFailureLeavesAStateConvergenceRepairs(t *testing.T) {
	s, fake := provableCreateServer(t)
	// A backend whose marker write always fails, wrapping the fake so every other
	// call behaves normally.
	s.virt = markerHostileVirt{Fake: fake}
	ctx := adminCtx()

	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM must not fail on a marker write: %v", err)
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d after a failed marker write; the epoch must be assigned FIRST "+
			"so convergeOwnerEpochMarker (which requires a positive epoch) can repair the "+
			"marker on its next sweep", row.OwnerEpoch)
	}
}

// markerHostileVirt fails only SetDomainOwnerEpoch. Injected as a wrapper rather
// than a flag on the fake so the fake's contract stays the real client's.
type markerHostileVirt struct {
	*libvirtfake.Fake
}

func (markerHostileVirt) SetDomainOwnerEpoch(string, int64, bool) error {
	return context.DeadlineExceeded
}
