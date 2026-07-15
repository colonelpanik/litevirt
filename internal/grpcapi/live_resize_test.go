package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestUpdateVM_MaxCPU_GatedOnLatch: setting a vCPU hotplug ceiling is refused until
// live_resize is enabled AND latched; once it is, max_cpu persists and the redefined
// domain carries the <vcpu current=…> hotplug headroom.
func TestUpdateVM_MaxCPU_GatedOnLatch(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MemoryMib: 2048}))

	// Not latched → refused.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(8)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("max_cpu without latch: want FailedPrecondition, got %v", err)
	}

	// Enable + latch live_resize.
	s.SetLiveResize(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.LiveResizeV1: true}})

	// max_cpu below cpu is rejected.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(1)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("max_cpu < cpu: want InvalidArgument, got %v", err)
	}

	// Valid ceiling → stored + XML headroom.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(8)}); err != nil {
		t.Fatalf("latched max_cpu: %v", err)
	}
	spec := loadStoredSpec(t, s, "hp")
	if spec.MaxCpu != 8 {
		t.Errorf("max_cpu not persisted: got %d, want 8", spec.MaxCpu)
	}
	got, err := s.virt.DumpXML("hp")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(got, `current="2"`) || !strings.Contains(got, ">8</vcpu>") {
		t.Errorf("redefined domain missing vCPU hotplug headroom:\n%s", got)
	}
}

func liveResizeServer(t *testing.T) *Server {
	t.Helper()
	s := reconfigServer(t)
	s.SetLiveResize(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.LiveResizeV1: true}})
	return s
}

// TestUpdateVM_LiveCPUGrow: a pure vCPU grow on a running VM within its ceiling is
// applied LIVE — no stop, boot count + actual both updated.
func TestUpdateVM_LiveCPUGrow(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MaxCpu: 8, MemoryMib: 2048}))
	// Running domain boots with 2, ceiling 8.
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='2'>8</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 6}); err != nil {
		t.Fatalf("live grow: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "hp")
	if vm.State != "running" {
		t.Errorf("VM stopped by a live grow (state=%s); should stay running", vm.State)
	}
	if vm.CPUActual != 6 {
		t.Errorf("cpu_actual = %d, want 6", vm.CPUActual)
	}
	if spec := loadStoredSpec(t, s, "hp"); spec.Cpu != 6 {
		t.Errorf("spec.Cpu = %d, want 6", spec.Cpu)
	}
}

// TestUpdateVM_LiveCPUGrow_NoHeadroom: growing beyond the running domain's actual
// vCPU ceiling needs a restart, not a silent live no-op.
func TestUpdateVM_LiveCPUGrow_NoHeadroom(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MaxCpu: 8, MemoryMib: 2048}))
	// The RUNNING domain only has a ceiling of 4 (max_cpu was raised but not applied).
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='2'>4</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 6}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("grow beyond live ceiling: want FailedPrecondition, got %v", err)
	}
}

// TestUpdateVM_LiveCPUGrow_HostCapacity: a live grow that would over-commit the
// host's CPU is rejected (F2 admission), not silently applied.
func TestUpdateVM_LiveCPUGrow_HostCapacity(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "test-host", CPUTotal: 8, MemTotal: 65536, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hp", HostName: "test-host", State: "running", CPUActual: 4, MemActual: 2048,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 4, MaxCpu: 16, MemoryMib: 2048}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='4'>16</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	// Host has 8 vCPU, 4 in use → 4 free; growing by 6 (4→10) over-commits.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 10}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("host over-commit: want ResourceExhausted, got %v", err)
	}
}

// TestUpdateVM_LiveCPUGrow_ProjectQuota: a live grow that would exceed the project's
// vCPU quota (committed + this grow) is rejected.
func TestUpdateVM_LiveCPUGrow_ProjectQuota(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "test-host", CPUTotal: 64, MemTotal: 262144, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{ProjectName: "acme", VCPULimit: 8}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hp", HostName: "test-host", State: "running", Project: "acme", CPUActual: 4, MemActual: 2048,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 4, MaxCpu: 16, MemoryMib: 2048}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='4'>16</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	// Quota 8; used 4; growing by 8 (4→12) exceeds it (host has ample room).
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 12}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("project quota: want ResourceExhausted, got %v", err)
	}
}

// TestUpdateVM_LiveCPUGrow_Pinned: a CPU-pinned VM can't live-grow CPUs.
func TestUpdateVM_LiveCPUGrow_Pinned(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MaxCpu: 8, MemoryMib: 2048,
			Resources: &pb.ResourceTuning{CpuPinning: []int32{0, 1}}}))
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='2'>8</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 6}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pinned live grow: want FailedPrecondition, got %v", err)
	}
}
