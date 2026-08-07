package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Residency is a SAFETY decision, not a numeric one. A workload with no finite
// CPU or memory limit asks the capacity ledger for nothing — and still lands on
// the host, still runs beside everything already there, and still becomes
// unaccountable consumption the moment the host cannot enumerate its own
// runtime. These tests pin the paths where a zero resource delta used to skip
// the host-safety gate entirely: the admission helpers ran safety only after
// the zero-delta fast path, and the container callers didn't invoke them at all
// unless a limit was set.

// TestStartContainer_ZeroMemory_IncompleteInventoryRefused: starting a
// memory-unlimited container is new residency, so a host that cannot account
// for its own runtime must refuse it — even though the start reserves 0 MiB.
func TestStartContainer_ZeroMemory_IncompleteInventoryRefused(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.SetContainerRuntime(&fakeCTRuntime{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "unlimited", State: "stopped", Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	s.invalidateInventoryCache()

	_, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "unlimited"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-memory start on a blind host: got %v, want FailedPrecondition — "+
			"a zero delta is still new residency, and residency is what incomplete inventory refuses", err)
	}
}

// TestCreateContainer_ZeroLimits_OwnershipConditionRefused: an active ownership
// condition involving the target host blocks a fully uncapped container create
// exactly as it blocks a sized one.
func TestCreateContainer_ZeroLimits_OwnershipConditionRefused(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.SetContainerRuntime(&fakeCTRuntime{})
	seedOwnershipCondition(t, s, "ct_dual_run", "container", "other-ct", "test-host")

	_, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "free-rider", Template: "download", Distro: "alpine", Release: "3.19",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-limit create on a host under an active ownership condition: got %v, "+
			"want FailedPrecondition — declining limits must not opt out of host safety", err)
	}
}

// TestRestoreContainer_ZeroLimits_OwnershipConditionRefused: the operator
// restore path makes a workload resident too, and the same condition gates it
// even when the archived spec carries no limits to reserve.
func TestRestoreContainer_ZeroLimits_OwnershipConditionRefused(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.dataDir = t.TempDir()
	repo := ctTestRepo(t)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs-tar")}
	s.SetContainerRuntime(rt)
	ctx := context.Background()

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "limitless", State: "running", Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "limitless", HostName: "test-host", RepoPath: repo, Timestamp: "2026-08-06T10:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	if err := corrosion.DeleteContainer(ctx, s.db, "test-host", "limitless"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}

	seedOwnershipCondition(t, s, "ct_dual_run", "container", "other-ct", "test-host")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "limitless", RepoPath: repo, Timestamp: "2026-08-06T10:00:00Z",
	}, rs)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-limit restore on a host under an active ownership condition: got %v, "+
			"want FailedPrecondition", err)
	}
}

// TestAdmission_ZeroGrowthNonResidency_NotBlockedByHostInvolvement: the
// host-involvement clause exists for CAPACITY-GROWING admission. A shrink or a
// non-size reconfigure of a RUNNING workload grows nothing and lands nothing
// new — an unrelated workload's ownership condition merely involving the host
// must not refuse it (incident remediation often IS a shrink). The two clauses
// that do bind at zero growth stay bound: an action on the AFFECTED workload
// itself, and any zero-delta NEW RESIDENCY.
func TestAdmission_ZeroGrowthNonResidency_NotBlockedByHostInvolvement(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	ctx := context.Background()
	seedOwnershipCondition(t, s, "ct_dual_run", "container", "other-ct", "test-host")

	// Zero-growth reconfigure of an UNRELATED running VM: admits.
	lease, err := s.admitGrowWithReservation(ctx, "UpdateVM", "test-host", "proj",
		corrosion.WorkloadVM, "innocent-vm", 0, 0, 2, 1024)
	if err != nil {
		t.Fatalf("zero-growth reconfigure on a host merely involved in an unrelated condition: %v — "+
			"the host clause gates capacity growth, and nothing grows here", err)
	}
	lease.release(ctx)

	// The same reconfigure GROWING capacity: refused (host clause binds).
	if _, err := s.admitGrowWithReservation(ctx, "UpdateVM", "test-host", "proj",
		corrosion.WorkloadVM, "innocent-vm", 1, 512, 2, 1024); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("grow on an involved host: got %v, want FailedPrecondition", err)
	}
	// An action on the AFFECTED workload: refused even at zero growth.
	if _, err := s.admitGrowWithReservation(ctx, "UpdateVM", "test-host", "proj",
		corrosion.WorkloadContainer, "other-ct", 0, 0, 2, 1024); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-growth action on the disputed workload itself: got %v, want FailedPrecondition", err)
	}
	// Zero-delta NEW RESIDENCY: refused (pinned elsewhere too; the control here
	// proves this test's relaxation did not open the residency hole).
	if _, err := s.admitHostWithReservation(ctx, "StartContainer", "test-host", "proj",
		"ct:uncapped", 0, 0, intentContainerResident); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-delta residency on an involved host: got %v, want FailedPrecondition", err)
	}
}

// TestCreateContainer_BoundedResidency_NoQEMUOverhead: a bounded container
// passes the full safety gate WITHOUT being charged the per-domain qemu
// overhead. admissionHost allocates exactly 1536 MiB: the container fits it to
// the byte, so any overhead charge (128 MiB) would refuse it — which is
// precisely what a VM of the same size gets, pinned by the second half. The
// overhead follows the qemu domain, not residency.
func TestCreateContainer_BoundedResidency_NoQEMUOverhead(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s) // allocatable: exactly 1536 MiB
	s.SetContainerRuntime(&fakeCTRuntime{})

	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "snug", Template: "download", Distro: "alpine", Release: "3.19",
		Cpu: 1, MemoryMib: 1536,
	}); err != nil {
		t.Fatalf("bounded container filling the host exactly was refused: %v — "+
			"container residency must not be charged qemu overhead", err)
	}

	// The SAME size as a VM does not fit: the domain's overhead tips it over.
	_, err := s.admitWithReservation(adminCtx(), "CreateVM", "test-host", "proj",
		"vm:snug-vm", 1, 1536, corrosion.QuotaAmount{VCPU: 1, MemMiB: 1536}, intentVMResident)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a 1536 MiB VM on a host the container filled: got %v, want ResourceExhausted", err)
	}
}

// TestAdmission_UnreadableAuthorityFailsClosed: when the project-authority read
// fails, attribution must fail the admission — not silently stamp legacy empty
// facts. Empty facts on a project that HAS a current authority produce a lease
// aggregation refuses to count: live in the journal, consuming nothing. The
// refused admission must also leave no nonterminal capacity operation behind.
func TestAdmission_UnreadableAuthorityFailsClosed(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	ctx := context.Background()

	if err := s.db.Execute(ctx, `DROP TABLE project_authority_epochs`); err != nil {
		t.Fatalf("DROP TABLE project_authority_epochs: %v", err)
	}

	_, err := s.admitWithReservation(adminCtx(), "CreateVM", "test-host", "proj",
		"vm:new-vm", 1, 512, corrosion.QuotaAmount{VCPU: 1, MemMiB: 512}, intentVMResident)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("admission with an unreadable authority table: got %v, want Unavailable — "+
			"an unreadable ledger is not a license to admit", err)
	}

	// The provisional operation must not survive as a live capacity claim.
	rows, qerr := s.db.Query(ctx, `
		SELECT o.id FROM operations o
		WHERE o.deleted_at IS NULL AND o.reservation_json != ''
		  AND NOT EXISTS (
			SELECT 1 FROM operation_steps st
			WHERE st.operation_id = o.id AND st.deleted_at IS NULL
			  AND st.step_name IN ('completed', 'failed'))`)
	if qerr != nil {
		t.Fatalf("scan for nonterminal capacity operations: %v", qerr)
	}
	if len(rows) != 0 {
		t.Fatalf("a refused admission left %d nonterminal capacity lease(s) behind", len(rows))
	}
}
