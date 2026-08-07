package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The unified collector's contract: per-workload identity, state, size, marker
// classification, uncapped detection, and honest completeness — replacing the
// three RPCs (ReportRuntime, CheckVMRuntime, CheckContainerRuntime) that each
// answered a narrower slice of the same question.

func inventoryServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.containersRoot = t.TempDir()
	return s
}

// TestCollectRuntimeInventory_ReportsMarkersAndSizes: a VM's entry carries its
// libvirt-configured size and its host-local owner-epoch marker, classified.
func TestCollectRuntimeInventory_ReportsMarkersAndSizes(t *testing.T) {
	s := inventoryServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm-a</name><memory unit='MiB'>2048</memory><vcpu current='4'>8</vcpu></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	if err := fake.StartDomain("vm-a"); err != nil {
		t.Fatalf("StartDomain: %v", err)
	}
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm-a", 7); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	inv := s.collectRuntimeInventory(context.Background())
	w, ok := inv.find(corrosion.WorkloadVM, "vm-a")
	if !ok {
		t.Fatalf("vm-a missing from inventory: %+v", inv.Workloads)
	}
	if w.State != health.RuntimeRunning || !w.DiskHolder {
		t.Errorf("vm-a state=%q holder=%v, want running holder", w.State, w.DiskHolder)
	}
	if w.CPU != 4 || w.MemoryMiB != 2048 {
		t.Errorf("vm-a size = %d vCPU/%d MiB, want 4/2048 (the CURRENT vcpu, not the ceiling)", w.CPU, w.MemoryMiB)
	}
	if w.OwnerEpochMarker != 7 || w.MarkerStatus != MarkerValid {
		t.Errorf("vm-a marker = %d/%s, want 7/valid", w.OwnerEpochMarker, w.MarkerStatus)
	}
	if !inv.Complete {
		t.Errorf("clean host reported incomplete: %v", inv.Errors)
	}
}

// TestCollectRuntimeInventory_ClassifiesMarkers: missing, corrupt, and valid
// markers are distinguished — corrupt is NEVER reported as epoch 0/valid, since
// garbage read as the zero generation would authorize exactly the stale actions
// the marker exists to refuse.
func TestCollectRuntimeInventory_ClassifiesMarkers(t *testing.T) {
	origCap := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = origCap }()

	s := inventoryServer(t)
	s.SetContainerRuntime(&fakeCT{
		names:  []string{"ct-valid", "ct-missing", "ct-corrupt"},
		states: map[string]string{"ct-valid": "running", "ct-missing": "running", "ct-corrupt": "running"},
	})
	if err := health.WriteContainerOwnerEpochMarker(s.containersRoot, "ct-valid", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(s.containersRoot, "ct-corrupt"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.containersRoot, "ct-corrupt", "owner_epoch"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatalf("write corrupt marker: %v", err)
	}

	inv := s.collectRuntimeInventory(context.Background())
	want := map[string]string{"ct-valid": MarkerValid, "ct-missing": MarkerMissing, "ct-corrupt": MarkerCorrupt}
	for name, status := range want {
		w, ok := inv.find(corrosion.WorkloadContainer, name)
		if !ok {
			t.Fatalf("%s missing from inventory", name)
		}
		if w.MarkerStatus != status {
			t.Errorf("%s marker status = %q, want %q", name, w.MarkerStatus, status)
		}
	}
	if v, _ := inv.find(corrosion.WorkloadContainer, "ct-valid"); v.OwnerEpochMarker != 3 {
		t.Errorf("ct-valid marker epoch = %d, want 3", v.OwnerEpochMarker)
	}
}

// TestCollectRuntimeInventory_UncappedContainer: a container with no cpu AND no
// memory limit is flagged — its consumption cannot be attributed, so capacity
// accounting must know.
func TestCollectRuntimeInventory_UncappedContainer(t *testing.T) {
	origCap := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = origCap }()

	s := inventoryServer(t)
	rt := &fakeCTRuntime{
		listNames:   []string{"capped", "rogue"},
		stateByName: map[string]string{"capped": "running", "rogue": "running"},
	}
	s.SetContainerRuntime(rt)
	if _, err := rt.CreateContainer(context.Background(), CreateContainerOpts{Name: "capped", CPULimit: 2, MemoryMiB: 512}); err != nil {
		t.Fatalf("create: %v", err)
	}

	inv := s.collectRuntimeInventory(context.Background())
	capped, _ := inv.find(corrosion.WorkloadContainer, "capped")
	rogue, _ := inv.find(corrosion.WorkloadContainer, "rogue")
	if capped.Uncapped || capped.CPU != 2 || capped.MemoryMiB != 512 {
		t.Errorf("capped = %+v, want limits 2/512 and not uncapped", capped)
	}
	if !rogue.Uncapped {
		t.Errorf("a limit-less container must be flagged uncapped: %+v", rogue)
	}
}

// TestGetRuntimeInventory_TargetedFilter: the (kind, name) filter returns just
// that workload — and an absent workload yields an empty COMPLETE inventory,
// which is the only shape that may serve as absence proof.
func TestGetRuntimeInventory_TargetedFilter(t *testing.T) {
	s := inventoryServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm-a</name><memory unit='MiB'>1024</memory><vcpu>2</vcpu></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	peer := peerCtxFor(t, s, "peer-1")

	resp, err := s.GetRuntimeInventory(peer, &pb.GetRuntimeInventoryRequest{Kind: "vm", Name: "vm-a"})
	if err != nil {
		t.Fatalf("filtered inventory: %v", err)
	}
	if len(resp.GetWorkloads()) != 1 || resp.GetWorkloads()[0].GetName() != "vm-a" {
		t.Fatalf("filtered workloads = %+v, want exactly vm-a", resp.GetWorkloads())
	}

	resp, err = s.GetRuntimeInventory(peer, &pb.GetRuntimeInventoryRequest{Kind: "vm", Name: "ghost"})
	if err != nil {
		t.Fatalf("filtered inventory (absent): %v", err)
	}
	if len(resp.GetWorkloads()) != 0 {
		t.Fatalf("absent workload returned entries: %+v", resp.GetWorkloads())
	}
	if !resp.GetComplete() {
		t.Fatal("a clean probe of an absent workload must be COMPLETE — that is what absence proof means")
	}
}
