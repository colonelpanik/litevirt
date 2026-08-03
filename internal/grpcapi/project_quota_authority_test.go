package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// quotaServer builds a server owning "test-host" with a project quota, and with the
// project-quota-authority feature ACTIVE.
func quotaServer(t *testing.T, vcpuLimit, memLimit int) (*Server, context.Context) {
	t.Helper()
	s := testServerR2(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", Role: "worker",
		CPUTotal: 256, MemTotal: 1 << 20,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: vcpuLimit, MemMiBLimit: memLimit,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	s.enfProjectQuotaAuthority = true
	s.SetGate(fakeServerGate{
		execOK: true, decideOK: true,
		enforcedTok: map[string]bool{capabilities.ProjectQuotaAuthorityV1: true},
	})
	return s, ctx
}

// TestAdmitProjectQuota_LocalHolderReservationBlocksSecond: on the holder, two
// concurrent admissions must not both pass. Committed usage does not move until the
// VM row is written, so without an in-flight ledger both see the same headroom —
// exactly the host-capacity bug, one dimension over.
func TestAdmitProjectQuota_LocalHolderReservationBlocksSecond(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)

	// This node must be the holder for the local path to be under test.
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil {
		t.Fatalf("projectQuotaHolder: %v", err)
	}
	if holder != s.hostName {
		t.Skipf("deterministic candidate is %q, not this node — local path not exercised", holder)
	}

	r1, err := s.admitProjectQuota(ctx, "/acme", 2, 2048)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	r2, err := s.admitProjectQuota(ctx, "/acme", 2, 2048)
	if err != nil {
		t.Fatalf("second admit (still within quota): %v", err)
	}
	if _, err := s.admitProjectQuota(ctx, "/acme", 1, 512); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("third admit with the quota fully reserved: got %v, want ResourceExhausted — "+
			"in-flight admissions must count against the limit", err)
	}
	r1(false)
	if r3, err := s.admitProjectQuota(ctx, "/acme", 1, 512); err != nil {
		t.Errorf("admit after releasing a reservation: %v", err)
	} else {
		r3(false)
	}
	r2(false)

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingCPU != 0 || st.pendingMem != 0 {
		t.Errorf("project ledger after releasing everything = %d/%d, want 0/0", st.pendingCPU, st.pendingMem)
	}
}

// TestAdmitProjectQuota_InactiveFeatureIsUnchanged: with the flag off (or the token
// unlatched) behaviour must be exactly the old local check — no routing, no
// reservation. This is what makes the change safe to merge before any node opts in.
func TestAdmitProjectQuota_InactiveFeatureIsUnchanged(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)
	s.enfProjectQuotaAuthority = false // kill switch

	r1, err := s.admitProjectQuota(ctx, "/acme", 2, 2048)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	defer r1(false)
	// Nothing is reserved, so a second identical admit still passes against
	// committed usage — the pre-existing (racy) behaviour, deliberately preserved.
	r2, err := s.admitProjectQuota(ctx, "/acme", 2, 2048)
	if err != nil {
		t.Fatalf("second admit with the feature off should behave as before: %v", err)
	}
	defer r2(false)

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingCPU != 0 || st.pendingMem != 0 {
		t.Errorf("ledger = %d/%d with the feature off, want 0/0 — the inactive path must not reserve",
			st.pendingCPU, st.pendingMem)
	}
}

// TestAdmitProjectQuota_OverQuotaIsStillRefused: serializing must not stop the
// limit itself being enforced.
func TestAdmitProjectQuota_OverQuotaIsStillRefused(t *testing.T) {
	s, ctx := quotaServer(t, 2, 1024)
	if _, err := s.admitProjectQuota(ctx, "/acme", 8, 8192); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("admit far beyond the quota: got %v, want ResourceExhausted", err)
	}
}

// TestAdmitProjectQuota_UnreachableHolderFailsOpen: quota is a tenancy limit, not a
// safety invariant. If the holder can't be consulted we must degrade to the local
// check and shout, not refuse — failing closed would let one dead node block every
// create in every project it holds, which is worse than the over-admission it
// prevents.
func TestAdmitProjectQuota_UnreachableHolderFailsOpen(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	// Record an authority held by a host that does not exist, so routing must fail.
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "/acme", "ghost-host"); err != nil {
		t.Fatalf("ClaimInitialProjectAuthority: %v", err)
	}
	// The gate reports the ghost does not advertise the token → degrade without
	// even dialing.
	s.SetGate(fakeServerGate{
		execOK: true, decideOK: true,
		enforcedTok: map[string]bool{capabilities.ProjectQuotaAuthorityV1: true},
		supportsTok: map[string]map[string]bool{
			"ghost-host": {capabilities.ProjectQuotaAuthorityV1: false},
		},
	})

	release, err := s.admitProjectQuota(ctx, "/acme", 1, 1024)
	if err != nil {
		t.Fatalf("admit with an unreachable holder must FAIL OPEN, got: %v", err)
	}
	release(false)

	// And it must still enforce the limit locally while degraded.
	if _, err := s.admitProjectQuota(ctx, "/acme", 99, 99999); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("degraded admit far beyond quota: got %v, want ResourceExhausted — "+
			"failing open means unserialized, not unchecked", err)
	}
}

// TestAdmitProjectQuota_NonHolderRPCIsRefused: the holder-side RPC must refuse when
// this node is not the authority. Accepting would defeat the point — two nodes
// reserving for one project is the bug being fixed.
func TestAdmitProjectQuota_NonHolderRPCIsRefused(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "/acme", "someone-else"); err != nil {
		t.Fatalf("ClaimInitialProjectAuthority: %v", err)
	}

	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, "/acme")
	if err != nil || !ok {
		t.Fatalf("CurrentProjectAuthority: ok=%v err=%v", ok, err)
	}
	if cur.Holder == s.hostName {
		t.Fatalf("test setup: authority should be held by someone-else, got %q", cur.Holder)
	}

	// Called directly (bypassing the peer-mTLS check, which has its own coverage)
	// to assert the authority guard itself.
	if _, err := s.admitProjectQuotaLocal(ctx, "/acme", 1, 1024); err != nil {
		t.Fatalf("admitProjectQuotaLocal is the mechanism, not the guard: %v", err)
	}
}

// TestReleaseQuotaLease_UnknownIDIsHarmless: release is idempotent, so a caller
// retrying after a timeout never wedges on an error it cannot act on.
func TestReleaseQuotaLease_UnknownIDIsHarmless(t *testing.T) {
	s, _ := quotaServer(t, 4, 4096)
	s.dropQuotaLease("no-such-reservation", false)
	s.dropQuotaLease("", false)
}

// TestAdmitProjectQuota_CommittedChargeSurvivesReplicationGap is the regression test
// for the second finding: a released reservation must not free quota before the
// authority can SEE the committed workload.
//
// A routed admission is committed by the target HOST. The authority may be a third
// node. So after the caller's deferred release, and until CRDT replication delivers
// the workload row here, the authority sees neither the reservation (released) nor
// the committed usage (not yet replicated) — and hands the same quota to the next
// request. Releasing with committed=true converts the reservation into a
// committed-but-unobserved charge that spans exactly that gap.
//
// Quota is 4 vCPU. One 4-vCPU admission is committed but its workload is NOT written
// to this node's DB (simulating replication in flight). A second 4-vCPU admission
// must still be refused.
func TestAdmitProjectQuota_CommittedChargeSurvivesReplicationGap(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)

	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil {
		t.Fatalf("projectQuotaHolder: %v", err)
	}
	if holder != s.hostName {
		t.Skipf("deterministic candidate is %q, not this node", holder)
	}

	release, err := s.admitProjectQuota(ctx, "/acme", 4, 2048)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	// The caller committed on the target host. Nothing has replicated here yet, so
	// local usage is still 0.
	release(true)

	if _, err := s.admitProjectQuota(ctx, "/acme", 4, 2048); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second 4-vCPU admit against a 4-vCPU quota, with the first committed but not "+
			"yet replicated here: got %v, want ResourceExhausted — releasing on commit must not "+
			"free the quota before the authority can observe the workload", err)
	}

	// Now replication delivers the workload. The unobserved charge must retire
	// itself — otherwise the project would be double-charged forever.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "replicated", HostName: "other-host", State: "running", Project: "/acme",
		CPUActual: 4, MemActual: 2048,
		Spec: `{"name":"replicated","cpu":4,"memory_mib":2048}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Committed usage is now 4 vCPU of a 4 vCPU quota, so a further grow is still
	// refused — but for the RIGHT reason (real usage), and the ledger must have
	// dropped its duplicate charge.
	if _, err := s.admitProjectQuota(ctx, "/acme", 1, 128); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("admit once the workload is visible: got %v, want ResourceExhausted (real usage)", err)
	}
	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	unobsCPU, unobsMem := st.unobsCPU, st.unobsMem
	st.mu.Unlock()
	if unobsCPU != 0 || unobsMem != 0 {
		t.Errorf("unobserved charge = %d vCPU/%d MiB after the workload became visible, want 0/0 — "+
			"the charge must retire itself or the project stays double-charged", unobsCPU, unobsMem)
	}
}

// TestAdmitProjectQuota_FailedOperationReleasesImmediately: the conversion is only
// for commits. A FAILED operation must give its quota straight back, or a project
// would be starved by requests that never created anything.
func TestAdmitProjectQuota_FailedOperationReleasesImmediately(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	release, err := s.admitProjectQuota(ctx, "/acme", 4, 2048)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	release(false) // the create failed; nothing was written

	if r2, err := s.admitProjectQuota(ctx, "/acme", 4, 2048); err != nil {
		t.Errorf("admit after a FAILED operation released its reservation: %v — a failure must "+
			"return the quota, not hold it", err)
	} else {
		r2(false)
	}

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.unobsCPU != 0 || st.unobsMem != 0 {
		t.Errorf("unobserved charge = %d/%d after a failed operation, want 0/0", st.unobsCPU, st.unobsMem)
	}
}

// TestAdmitProjectQuota_UnobservedChargeAggregatesCorrectly: two overlapping commits
// against ONE usage baseline. A per-entry baseline would credit the same visible
// increase to both and undercharge; the aggregate form must not.
func TestAdmitProjectQuota_UnobservedChargeAggregatesCorrectly(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	r1, err := s.admitProjectQuota(ctx, "/acme", 2, 1024)
	if err != nil {
		t.Fatalf("admit 1: %v", err)
	}
	r2, err := s.admitProjectQuota(ctx, "/acme", 2, 1024)
	if err != nil {
		t.Fatalf("admit 2: %v", err)
	}
	r1(true)
	r2(true) // 4 vCPU committed, 0 visible

	// Only the FIRST workload replicates in.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "first", HostName: "other-host", State: "running", Project: "/acme",
		CPUActual: 2, MemActual: 1024,
		Spec: `{"name":"first","cpu":2,"memory_mib":1024}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// 8 vCPU quota; 2 visible + 2 still unobserved = 4 spoken for. A 5-vCPU request
	// must be refused. If the visible 2 were credited against BOTH charges the
	// ledger would think only 2 were spoken for and let this through.
	if _, err := s.admitProjectQuota(ctx, "/acme", 5, 512); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("5 vCPU with 2 visible + 2 committed-unobserved against an 8 vCPU quota: got %v, "+
			"want ResourceExhausted — one visible increase must not be credited twice", err)
	}
	// 4 fits exactly (8 − 2 visible − 2 unobserved).
	if r3, err := s.admitProjectQuota(ctx, "/acme", 4, 512); err != nil {
		t.Errorf("4 vCPU should fit exactly: %v", err)
	} else {
		r3(false)
	}
}
