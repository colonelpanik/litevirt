package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The epoch check on the holder's side of a delegated admission.
//
// Delegation is only worth anything if exactly one node answers for a project. The
// epoch is what makes "exactly one" checkable: a node that has lost authority — or
// never had it — must refuse rather than decide, because a decision made under a
// superseded authority is indistinguishable from the two-decider state the whole
// mechanism removes.
//
// The fleet scenarios all address the CURRENT holder at the CURRENT epoch, so they
// never reach this refusal. It is asserted here directly.

// authorityServer builds a server named "test-host" holding a project's admission
// authority at epoch 1, with a quota generous enough that any refusal below can only
// have come from the authority check.
func authorityServer(t *testing.T, project string) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	// requirePeerCert only trusts a caller that is a KNOWN cluster host, so the
	// delegating peer has to exist in cluster state for any of this to be reached.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-host", Address: "10.0.0.8", State: "active", CPUTotal: 16, MemTotal: 8192,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: project, VCPULimit: 64, MemMiBLimit: 65536,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	return s
}

func reserveReq(project string, epoch int64) *pb.ReserveProjectCapacityRequest {
	return &pb.ReserveProjectCapacityRequest{
		Project: project, Method: "CreateVM", CpuDelta: 1, MemMibDelta: 1024,
		AuthorityEpoch: epoch, ResourceId: "vm:probe",
	}
}

// TestReserveProjectCapacity_GrantsAsTheCurrentHolder is the baseline: without it, a
// handler that refused everything would satisfy every negative case below.
func TestReserveProjectCapacity_GrantsAsTheCurrentHolder(t *testing.T) {
	s := authorityServer(t, "tenant")
	ctx := mtlsCtx("peer-host")

	applied, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "tenant", s.hostName)
	if err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}

	resp, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 1))
	if err != nil {
		t.Fatalf("the current holder refused a request at its own epoch: %v", err)
	}
	if resp.LeaseId == "" {
		t.Error("granted admission returned no lease id — the caller has nothing to release")
	}
	if resp.AuthorityEpoch != 1 {
		t.Errorf("granted under epoch %d, want 1", resp.AuthorityEpoch)
	}
}

// TestReserveProjectCapacity_RefusesWhenNotTheHolder: a node that does not hold the
// authority must not decide, however plausible the request looks.
func TestReserveProjectCapacity_RefusesWhenNotTheHolder(t *testing.T) {
	s := authorityServer(t, "tenant")
	ctx := mtlsCtx("peer-host")

	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "tenant", "some-other-host"); err != nil {
		t.Fatalf("ClaimInitialProjectAuthority: %v", err)
	}

	_, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 1))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a non-holder answered a delegated admission (err=%v, code=%s), want FailedPrecondition — "+
			"two nodes deciding for one project is the state delegation exists to remove", err, status.Code(err))
	}
}

// TestReserveProjectCapacity_RefusesAStaleEpoch: authority moved on. A request still
// addressed to the OLD epoch must be refused even though this node happens to be the
// current holder — the caller decided who to ask using a view that has since changed,
// and answering it would paper over a handoff the caller has not observed.
func TestReserveProjectCapacity_RefusesAStaleEpoch(t *testing.T) {
	s := authorityServer(t, "tenant")
	ctx := mtlsCtx("peer-host")

	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "tenant", "some-other-host"); err != nil {
		t.Fatalf("ClaimInitialProjectAuthority: %v", err)
	}
	// Authority moves to us at epoch 2 (planned handoff).
	if _, applied, err := corrosion.TakeoverProjectAuthority(ctx, s.db, "tenant", s.hostName, "planned", "", 1); err != nil || !applied {
		t.Fatalf("TakeoverProjectAuthority: applied=%v err=%v", applied, err)
	}

	if _, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 1)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a request stamped with the superseded epoch 1 was answered (err=%v, code=%s), want FailedPrecondition",
			err, status.Code(err))
	}
	// ...and the same request at the CURRENT epoch is fine, so the refusal above is
	// about the epoch and not about the handler rejecting everything.
	if _, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 2)); err != nil {
		t.Fatalf("current-epoch request refused after a handoff: %v", err)
	}
}

// TestReserveProjectCapacity_RefusesWithNoAuthorityAtAll guards the empty case: no
// authority record means nobody is serializing this project, so a delegated request
// must not be honoured as if someone were.
func TestReserveProjectCapacity_RefusesWithNoAuthorityAtAll(t *testing.T) {
	s := authorityServer(t, "tenant")
	_, err := s.ReserveProjectCapacity(mtlsCtx("peer-host"), reserveReq("tenant", 1))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("delegated admission answered with no authority record (err=%v, code=%s), want FailedPrecondition",
			err, status.Code(err))
	}
}

// TestReleaseProjectCapacity_FreesTheLease: a granted lease holds quota until it is
// released, so the release path has to actually work — a silent no-op here would
// leak a project's quota on every admission.
func TestReleaseProjectCapacity_FreesTheLease(t *testing.T) {
	s := authorityServer(t, "tenant")
	ctx := mtlsCtx("peer-host")
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "tenant", s.hostName); err != nil {
		t.Fatalf("ClaimInitialProjectAuthority: %v", err)
	}

	resp, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 1))
	if err != nil {
		t.Fatalf("ReserveProjectCapacity: %v", err)
	}
	cpu, _, err := corrosion.ProjectReserved(ctx, s.db, "tenant")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if cpu != 1 {
		t.Fatalf("held %d vCPU while the lease is open, want 1 — nothing is being reserved", cpu)
	}

	if _, err := s.ReleaseProjectCapacity(ctx, &pb.ReleaseProjectCapacityRequest{
		Project: "tenant", LeaseId: resp.LeaseId,
	}); err != nil {
		t.Fatalf("ReleaseProjectCapacity: %v", err)
	}
	cpu, _, err = corrosion.ProjectReserved(ctx, s.db, "tenant")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if cpu != 0 {
		t.Errorf("held %d vCPU after release, want 0 — a leaked lease consumes quota no workload is using", cpu)
	}
}
