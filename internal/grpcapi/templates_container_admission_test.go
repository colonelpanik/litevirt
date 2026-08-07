package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCloneContainer_ZeroLimits_OwnershipConditionRefused: cloning is
// container residency — a zero-limit clone must pass the same host-safety
// gate as a zero-limit create.
func TestCloneContainer_ZeroLimits_OwnershipConditionRefused(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "tmpl", State: "stopped", IsTemplate: true, Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	seedOwnershipCondition(t, s, "ct_dual_run", "container", "other-ct", "test-host")

	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "tmpl", Target: "free-rider"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-limit clone on a host under an active ownership condition: got %v, want FailedPrecondition", err)
	}
	if rec, _ := corrosion.GetContainer(ctx, s.db, "test-host", "free-rider"); rec != nil {
		t.Fatalf("refused clone still persisted a row: %+v", rec)
	}
}

// TestCloneContainer_RefusedWhenHostLacksCapacity: a sized clone draws real
// memory on this host and must be admitted against its headroom — the legacy
// read-only tenancy glance never consulted host capacity at all (and was
// absent entirely without a tenancy service).
func TestCloneContainer_RefusedWhenHostLacksCapacity(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s) // allocatable 1536 MiB
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "big-tmpl", State: "stopped", IsTemplate: true,
		CPULimit: 1, MemMiB: 2048, Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "big-tmpl", Target: "big-clone"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("cloning a 2048 MiB container onto a host with 1536 MiB allocatable: got %v, want ResourceExhausted", err)
	}
	if rec, _ := corrosion.GetContainer(ctx, s.db, "test-host", "big-clone"); rec != nil {
		t.Fatalf("refused clone still persisted a row: %+v", rec)
	}
}

// TestCloneContainer_QuotaReserved: the clone's quota charge is serialized —
// an earlier in-flight claimant's reservation counts against it.
func TestCloneContainer_QuotaReserved(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "acme", VCPULimit: 4, MemMiBLimit: 1024,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "q-tmpl", State: "stopped", IsTemplate: true,
		CPULimit: 1, MemMiB: 1024, Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	plantReservation(t, s, "00000000-earlier", "test-host", "acme", 1, 512)

	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "q-tmpl", Target: "q-clone", Project: "acme"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("clone of 1024 MiB with 512 already reserved of a 1024 quota: got %v, want ResourceExhausted", err)
	}
}
