package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Ports of the #126 quota-serialization properties (e6f0ebb, b0cadf3) onto the
// reservation architecture: container CPU is quota-charged, a stopped VM's grow is
// quota-admitted, and --allow-overcommit bypasses the HOST check only.

// TestCreateContainer_CPUOnlyChargesProjectQuota: SumProjectUsage counts a
// container's cpu_limit against the project vCPU budget, so admission must charge
// it too — and must run even when memory is UNCAPPED, which previously skipped
// serialized admission entirely.
func TestCreateContainer_CPUOnlyChargesProjectQuota(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := adminCtx()

	if err := corrosion.UpsertProjectQuota(context.Background(), s.db,
		corrosion.ProjectQuotaRecord{ProjectName: "qa", VCPULimit: 3}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "existing", Project: "qa", State: "running", CPULimit: 2,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	// 2 used + 2 requested > 3: must refuse, even with NO memory cap in the request.
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "cpu-hog", Template: "download", Distro: "alpine",
		Project: "qa", Cpu: 2,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("CPU-only container over quota: got %v, want ResourceExhausted — "+
			"an uncapped-memory container must still be CPU-admitted", err)
	}

	// Positive control: 1 vCPU fits (2+1 ≤ 3), so the refusal above was the quota.
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "cpu-ok", Template: "download", Distro: "alpine",
		Project: "qa", Cpu: 1,
	}); err != nil {
		t.Fatalf("fitting CPU-only container refused: %v", err)
	}
}

// TestUpdateVM_StoppedGrowChargesProjectQuota: a stopped VM's spec still counts
// toward SumProjectUsage, so growing it must be quota-admitted. The admission is
// QUOTA ONLY — the stopped VM consumes no host capacity until StartVM admits the
// full size.
func TestUpdateVM_StoppedGrowChargesProjectQuota(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", CPUTotal: 64, MemTotal: 262144, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db,
		corrosion.ProjectQuotaRecord{ProjectName: "acme", VCPULimit: 8}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "sleeper", HostName: "test-host", State: "stopped", Project: "acme",
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "sleeper", Cpu: 4, MemoryMib: 2048}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>sleeper</name><memory unit='KiB'>2097152</memory><vcpu>4</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	// Quota 8; the stopped spec uses 4; growing to 12 asks for 8 more → refuse.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "sleeper", Cpu: 12}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("stopped-VM grow over quota: got %v, want ResourceExhausted — "+
			"the stopped path used to persist a larger spec with no admission at all", err)
	}

	// Positive control: growing to 8 fits exactly, and the spec persists.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "sleeper", Cpu: 8}); err != nil {
		t.Fatalf("fitting stopped-VM grow refused: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "sleeper")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got := specCPUFromJSON(t, vm.Spec); got != 8 {
		t.Errorf("persisted spec cpu = %d, want 8", got)
	}
}

// TestUpdateVM_OvercommitGrowStillChargesProjectQuota: --allow-overcommit is a
// judgment about PHYSICAL capacity; quota is a tenancy limit and is not
// negotiable. The overcommit grow must go through the same serialized admission —
// the unserialized local check cannot see in-flight reservations.
func TestUpdateVM_OvercommitGrowStillChargesProjectQuota(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", CPUTotal: 64, MemTotal: 262144, State: "HOST_ACTIVE"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db,
		corrosion.ProjectQuotaRecord{ProjectName: "acme", VCPULimit: 8}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "dense", HostName: "test-host", State: "running", Project: "acme",
		CPUActual: 4, MemActual: 2048,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "dense", Cpu: 4, MaxCpu: 16, MemoryMib: 2048}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>dense</name><memory unit='KiB'>2097152</memory><vcpu current='4'>16</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	// Quota 8, used 4, +8 exceeds — AllowOvercommit must not bypass this.
	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "dense", Cpu: 12, AllowOvercommit: true})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("overcommit grow over quota: got %v, want ResourceExhausted — "+
			"--allow-overcommit bypasses the host check only", err)
	}
}

// specCPUFromJSON extracts spec.cpu from a stored VM spec.
func specCPUFromJSON(t *testing.T, specJSON string) int {
	t.Helper()
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return int(spec.Cpu)
}
