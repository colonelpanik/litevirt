package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCreateContainer_DefaultProjectQuotaIsEnforced is the #216 regression.
//
// CreateContainer passed req.Project to quota admission RAW while every other
// consumer in the file normalizes. `lv ct create` without --project sends "",
// GetProjectQuota(ctx, "") finds no row (quotas are keyed "_default"), so
// quotaVerdict never ran and _default's limits were unenforced for containers.
// The stored row is normalized — UpsertContainer maps "" → "_default" — so the
// container counted against a budget that had never admitted it.
func TestCreateContainer_DefaultProjectQuotaIsEnforced(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: tenancy.Default, VCPULimit: 2,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}

	// No --project: this lands in _default, whose vCPU budget is 2.
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "greedy", Template: "download", Distro: "alpine", Release: "3.19",
		Cpu: 8,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("8 vCPU against _default's 2-vCPU quota: got %v, want ResourceExhausted", err)
	}
	if rec, _ := corrosion.GetContainer(ctx, s.db, s.hostName, "greedy"); rec != nil {
		t.Errorf("refused create still persisted a row: %+v", rec)
	}
}

// Spelling the default project explicitly already worked; it must keep working,
// so the fix is normalization and not a new refusal.
func TestCreateContainer_ExplicitDefaultProjectQuotaStillEnforced(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: tenancy.Default, VCPULimit: 2,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "greedy2", Template: "download", Distro: "alpine", Release: "3.19",
		Project: tenancy.Default, Cpu: 8,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("explicit _default: got %v, want ResourceExhausted", err)
	}
}

// A create that fits the budget is unaffected.
func TestCreateContainer_WithinDefaultQuotaStillAdmitted(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: tenancy.Default, VCPULimit: 8,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "modest", Template: "download", Distro: "alpine", Release: "3.19",
		Cpu: 2,
	}); err != nil {
		t.Fatalf("2 vCPU against an 8-vCPU quota should be admitted: %v", err)
	}
}

// capacityOpProjects returns the project recorded on every capacity operation
// row the given method wrote.
func capacityOpProjects(t *testing.T, s *Server, method string) []string {
	t.Helper()
	rows, err := s.db.Query(adminCtx(),
		`SELECT project FROM operations WHERE method = ? AND resource_kind = ?`,
		method, corrosion.CapacityResourceKind)
	if err != nil {
		t.Fatalf("query operations: %v", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("project"))
	}
	return out
}

// The host-capacity lease must name the project the container lands in. #216
// normalized the QUOTA admission but left the host lease on the raw request
// value, so a create without --project recorded project="" on its operation
// row while the container itself was stored under _default. The start path
// passed the stored row's project raw too.
//
// Mutation: pass req.Project / rec.Project to admitHostWithReservation again —
// the create (resp. start) row records "" and its half goes red.
func TestContainerHostLease_RecordsTheNormalizedProject(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "plain", Template: "download", Distro: "alpine", Release: "3.19",
		Cpu: 1, MemoryMib: 256,
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	got := capacityOpProjects(t, s, "CreateContainer")
	if len(got) == 0 {
		t.Fatal("CreateContainer wrote no capacity operation; the test cannot see the host lease")
	}
	for _, p := range got {
		if p != tenancy.Default {
			t.Errorf("CreateContainer capacity op project = %q, want %q", p, tenancy.Default)
		}
	}

	// A stopped row whose project column is empty (an older writer's), started.
	if _, err := s.db.DB().ExecContext(ctx,
		`UPDATE containers SET state = 'stopped', project = '' WHERE host_name = ? AND name = ?`,
		s.hostName, "plain"); err != nil {
		t.Fatalf("stop row: %v", err)
	}
	if _, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "plain", HostName: s.hostName}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	got = capacityOpProjects(t, s, "StartContainer")
	if len(got) == 0 {
		t.Fatal("StartContainer wrote no capacity operation; the test cannot see the host lease")
	}
	for _, p := range got {
		if p != tenancy.Default {
			t.Errorf("StartContainer capacity op project = %q, want %q", p, tenancy.Default)
		}
	}
}
