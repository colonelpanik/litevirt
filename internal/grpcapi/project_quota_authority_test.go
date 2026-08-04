package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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
	r1.Release(CommitFact{})
	if r3, err := s.admitProjectQuota(ctx, "/acme", 1, 512); err != nil {
		t.Errorf("admit after releasing a reservation: %v", err)
	} else {
		r3.Release(CommitFact{})
	}
	r2.Release(CommitFact{})

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
	defer r1.Release(CommitFact{})
	// Nothing is reserved, so a second identical admit still passes against
	// committed usage — the pre-existing (racy) behaviour, deliberately preserved.
	r2, err := s.admitProjectQuota(ctx, "/acme", 2, 2048)
	if err != nil {
		t.Fatalf("second admit with the feature off should behave as before: %v", err)
	}
	defer r2.Release(CommitFact{})

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
	release.Release(CommitFact{})

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

	// The serving path itself refuses now: admitProjectQuotaLocal re-validates the
	// lease before touching the ledger, so a node that is not the authority cannot
	// serialize locally even if something routed a request to it by mistake.
	_, err = s.admitProjectQuotaLocal(ctx, "/acme", 1, 1024)
	var moved errQuotaAuthorityMoved
	if !errors.As(err, &moved) {
		t.Fatalf("admitProjectQuotaLocal on a non-holder: got %v, want errQuotaAuthorityMoved — "+
			"the serving path must re-validate the lease, not trust the caller's routing", err)
	}
	if moved.holder != cur.Holder {
		t.Errorf("moved.holder = %q, want %q so the caller can re-route", moved.holder, cur.Holder)
	}
}

// TestReleaseQuotaLease_UnknownIDIsHarmless: release is idempotent, so a caller
// retrying after a timeout never wedges on an error it cannot act on.
func TestReleaseQuotaLease_UnknownIDIsHarmless(t *testing.T) {
	s, _ := quotaServer(t, 4, 4096)
	s.dropQuotaLease("no-such-reservation", CommitFact{})
	s.dropQuotaLease("", CommitFact{})
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
	release.Release(CommitFact{Committed: true, Workload: "replicated", CPU: 4, MemMiB: 2048})

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
	remaining := len(st.unobserved)
	st.mu.Unlock()
	if remaining != 0 {
		t.Errorf("%d unobserved charge(s) left after the workload became visible, want 0 — "+
			"the charge must retire on observing ITS OWN workload or the project stays "+
			"double-charged", remaining)
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
	release.Release(CommitFact{}) // the create failed; nothing was written

	if r2, err := s.admitProjectQuota(ctx, "/acme", 4, 2048); err != nil {
		t.Errorf("admit after a FAILED operation released its reservation: %v — a failure must "+
			"return the quota, not hold it", err)
	} else {
		r2.Release(CommitFact{})
	}

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.unobserved) != 0 {
		t.Errorf("%d unobserved charge(s) after a failed operation, want 0", len(st.unobserved))
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
	r1.Release(CommitFact{Committed: true, Workload: "first", CPU: 2, MemMiB: 1024})
	r2.Release(CommitFact{Committed: true, Workload: "second", CPU: 2, MemMiB: 1024}) // 4 vCPU committed, 0 visible

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
		r3.Release(CommitFact{})
	}
}

// TestQuotaLease_OnlyOneNodeCanHold is the regression test for a DERIVED holder not
// being sufficient. Two nodes with different (asynchronously replicated) host views
// derive different winners and both used to serve as authority, each admitting against
// its own snapshot. A lease is one replicated fact, so only one can hold it.
func TestQuotaLease_OnlyOneNodeCanHold(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	held, holder, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "node-a")
	if err != nil || !held || holder != "node-a" {
		t.Fatalf("first acquire: held=%v holder=%q err=%v", held, holder, err)
	}

	// A second node attempting while the lease is LIVE must lose, and must be told
	// who actually holds it so it can route there.
	held2, holder2, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "node-b")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if held2 {
		t.Error("node-b also acquired a live lease — two authorities is the bug being fixed")
	}
	if holder2 != "node-a" {
		t.Errorf("loser was told holder=%q, want node-a — it must be able to route to the real "+
			"holder rather than fall back to its own derivation", holder2)
	}

	// The holder can renew.
	if held3, _, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "node-a"); err != nil || !held3 {
		t.Errorf("holder renewal: held=%v err=%v", held3, err)
	}
}

// TestQuotaLease_ExpiredLeaseIsNotServable: a holder that stopped renewing (crashed,
// partitioned away) must stop being the authority, or its projects are frozen.
func TestQuotaLease_ExpiredLeaseIsNotServable(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	if _, _, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "dead-node"); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Expire it by hand — the lease is just a row.
	if err := s.db.Execute(ctx,
		`UPDATE leader_election SET expires_at = ? WHERE key = ?`,
		"2000-01-01T00:00:00Z", corrosion.QuotaLeaseKey("/acme")); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	if _, ok, err := corrosion.ProjectQuotaLeaseHolder(ctx, s.db, "/acme"); err != nil || ok {
		t.Errorf("expired lease still reports a holder (ok=%v err=%v) — a dead holder must not "+
			"keep the project's authority", ok, err)
	}
	// And another node can now take it.
	if held, _, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "live-node"); err != nil || !held {
		t.Errorf("acquire after expiry: held=%v err=%v", held, err)
	}
}

// TestAdmitProjectQuota_NonHolderRedirectsInsteadOfErroring is the regression test for
// the redirect being unusable. The handler used to return the redirect ALONGSIDE a
// gRPC error, and gRPC drops the message when an error is set — so the caller never
// learned the real holder, re-resolved from the same stale view that misrouted it, and
// fell open. The redirect must arrive on a successful response.
func TestAdmitProjectQuota_NonHolderRedirectsInsteadOfErroring(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	// Someone else holds a live lease, so this node is not the authority.
	if _, _, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, "/acme", "other-node"); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	resp, err := s.AdmitProjectQuota(peerCtxFor(t, s, "caller-node"), &pb.AdmitProjectQuotaRequest{
		Sender: "caller-node", Project: "/acme", CpuDelta: 1, MemMibDelta: 128,
	})
	if err != nil {
		t.Fatalf("a non-holder must REDIRECT on a successful response, not error (%v) — an error "+
			"makes gRPC drop the message and the caller cannot follow it", err)
	}
	if !resp.Redirect {
		t.Error("response.Redirect = false; want true")
	}
	if resp.Admitted {
		t.Error("response.Admitted = true from a non-holder")
	}
	if resp.CurrentHolder != "other-node" {
		t.Errorf("CurrentHolder = %q, want other-node — the caller needs the REAL holder, since "+
			"re-resolving locally returns the same answer that misrouted it", resp.CurrentHolder)
	}
}

// TestAdmitProjectQuota_UnrelatedUsageDoesNotRetireACharge is the regression test for
// the aggregate baseline. The ledger used to infer replication progress from any usage
// growth, so an unrelated workload arriving (created before the charge, or admitted
// through the fail-open path) cleared someone else's charge and let the next request
// over-admit. Charges are keyed by workload identity, so only their OWN workload
// retires them.
func TestAdmitProjectQuota_UnrelatedUsageDoesNotRetireACharge(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	release, err := s.admitProjectQuota(ctx, "/acme", 4, 2048)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	// Committed as "mine", not yet replicated here.
	release.Release(CommitFact{Committed: true, Workload: "mine", Kind: corrosion.WorkloadVM, CPU: 4, MemMiB: 2048})

	// An UNRELATED workload now becomes visible — one that was never charged here
	// (created before this charge, or admitted while the authority was unreachable).
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "stranger", HostName: "other-host", State: "running", Project: "/acme",
		CPUActual: 4, MemActual: 2048,
		Spec: `{"name":"stranger","cpu":4,"memory_mib":2048}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// 8 vCPU quota: 4 now visible (stranger) + 4 still owed (mine) = 8 spoken for.
	// A further 1 vCPU must be refused. Under the aggregate baseline, stranger's
	// arrival would have retired "mine" and let this through.
	if _, err := s.admitProjectQuota(ctx, "/acme", 1, 128); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("admit with 4 visible (unrelated) + 4 committed-unobserved against an 8 vCPU "+
			"quota: got %v, want ResourceExhausted — an unrelated workload's arrival must not "+
			"retire another workload's charge", err)
	}

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	_, stillHeld := st.unobserved[workloadKey(CommitFact{Workload: "mine", Kind: corrosion.WorkloadVM})]
	st.mu.Unlock()
	if !stillHeld {
		t.Error(`the charge for "mine" was retired by an unrelated workload's arrival`)
	}
}

// TestCreateVM_OvercommitStillUsesSerializedQuota is the regression test for
// --allow-overcommit bypassing serialized quota admission.
//
// Overcommit is a judgment call about PHYSICAL host capacity. Project quota is a
// tenancy limit and is not negotiable, so it must go through the same serialized
// admission as any other create. It used to rely on the earlier unserialized
// tenancy check, so concurrent overcommit creates all saw the same headroom.
//
// The probe: hold an in-flight reservation that consumes the whole quota. An
// unserialized check cannot see a reservation, so it would let the create through;
// the serialized path must refuse it.
func TestCreateVM_OvercommitStillUsesSerializedQuota(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)
	s.virt = libvirtfake.New()
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	// Consume the entire quota with an admission that is still in flight.
	hold, err := s.admitProjectQuota(ctx, "/acme", 4, 4096)
	if err != nil {
		t.Fatalf("seed reservation: %v", err)
	}
	defer hold.Release(CommitFact{})

	_, err = s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "greedy", Project: "/acme", Image: "noimage", Cpu: 4, MemoryMib: 4096,
			Placement: &pb.PlacementSpec{Host: "test-host"},
		},
		AllowOvercommit: true,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("--allow-overcommit create with the project's quota fully reserved in flight: "+
			"got %v, want ResourceExhausted — overcommit bypasses HOST capacity only, and quota "+
			"admission must be the serialized one (the unserialized check cannot see a "+
			"reservation, so concurrent overcommit creates would all pass)", err)
	}
}

// TestQuotaLease_RenewedWhileChargesOutstanding is the regression test for the lease
// expiring under its own reservations.
//
// The lease is 30s; a charge can last far longer (a create waiting on an image pull, a
// routed reservation). Nothing renewed it, so the lease lapsed mid-create and the next
// node acquired it with an EMPTY ledger and re-handed quota that was still owed — the
// TTL turned a rare handoff into a routine one.
func TestQuotaLease_RenewedWhileChargesOutstanding(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	hold, err := s.admitProjectQuota(ctx, "/acme", 4, 2048)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer hold.Release(CommitFact{})

	// Age the lease to the brink, as a long create would.
	if err := s.db.Execute(ctx,
		`UPDATE leader_election SET expires_at = ? WHERE key = ?`,
		time.Now().UTC().Add(time.Second).Format(time.RFC3339), corrosion.QuotaLeaseKey("/acme")); err != nil {
		t.Fatalf("age lease: %v", err)
	}

	// The renewer must push it back out, because a charge is outstanding.
	s.renewHeldQuotaLeases(ctx)

	h, ok, err := corrosion.ProjectQuotaLeaseHolder(ctx, s.db, "/acme")
	if err != nil || !ok || h != s.hostName {
		t.Fatalf("lease after renewal: holder=%q ok=%v err=%v; want it still held by %s — an "+
			"un-renewed lease lapses under its own outstanding reservation", h, ok, err, s.hostName)
	}
	rows, err := s.db.Query(ctx, `SELECT expires_at FROM leader_election WHERE key = ?`,
		corrosion.QuotaLeaseKey("/acme"))
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	exp, perr := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if perr != nil {
		t.Fatalf("parse expiry: %v", perr)
	}
	if until := time.Until(exp); until < 5*time.Second {
		t.Errorf("lease expires in %v after renewal; want it pushed well out so a long-running "+
			"charge cannot outlive its own authority", until)
	}
}

// TestQuotaLease_LosingTheLeaseDropsTheLedger: if the lease is genuinely lost, holding
// on is worse than letting go. The successor is the authority now, and our charges
// describe reservations it knows nothing about — keeping them would only refuse our own
// future requests while the successor admits anyway.
func TestQuotaLease_LosingTheLeaseDropsTheLedger(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}
	hold, err := s.admitProjectQuota(ctx, "/acme", 4, 2048)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer hold.Release(CommitFact{})

	// Someone else takes the lease (ours expired and they won it).
	if err := s.db.Execute(ctx,
		`UPDATE leader_election SET holder = ?, expires_at = ? WHERE key = ?`,
		"successor", time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		corrosion.QuotaLeaseKey("/acme")); err != nil {
		t.Fatalf("hand lease to successor: %v", err)
	}

	s.renewHeldQuotaLeases(ctx)

	st := s.projectAdmitStateFor("/acme")
	st.mu.Lock()
	pending, unobs := st.pendingCPU, len(st.unobserved)
	st.mu.Unlock()
	if pending != 0 || unobs != 0 {
		t.Errorf("ledger after losing the lease = %d pending vCPU / %d unobserved; want 0/0 — "+
			"charges for an authority we no longer hold only refuse our own requests", pending, unobs)
	}
}

// TestAdmitProjectQuota_ConsecutiveResizesSumTheirCharges is the regression test for
// max() vs sum(). Two +2 vCPU resizes that both commit before either is visible owe
// FOUR unseen vCPU; max() held only two and silently released half.
func TestAdmitProjectQuota_ConsecutiveResizesSumTheirCharges(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	// The VM already exists at 2 vCPU and is visible here.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "grower", HostName: "other-host", State: "running", Project: "/acme",
		CPUActual: 2, MemActual: 512,
		Spec: `{"name":"grower","cpu":2,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Resize 2→4 commits (delta 2, absolute 4), not yet replicated here.
	r1, err := s.admitProjectQuota(ctx, "/acme", 2, 0)
	if err != nil {
		t.Fatalf("resize 1: %v", err)
	}
	r1.Release(CommitFact{Committed: true, Workload: "grower", Kind: corrosion.WorkloadVM, CPU: 4, MemMiB: 512})
	// Resize 4→6 commits too (delta 2, absolute 6), also not replicated.
	r2, err := s.admitProjectQuota(ctx, "/acme", 2, 0)
	if err != nil {
		t.Fatalf("resize 2: %v", err)
	}
	r2.Release(CommitFact{Committed: true, Workload: "grower", Kind: corrosion.WorkloadVM, CPU: 6, MemMiB: 512})

	// Quota 8. Visible 2 + unseen 4 = 6 spoken for, so 3 must not fit; 2 must.
	if _, err := s.admitProjectQuota(ctx, "/acme", 3, 0); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("3 vCPU with 2 visible + FOUR unseen against an 8 vCPU quota: got %v, want "+
			"ResourceExhausted — two consecutive +2 resizes owe 4, not max(2,2)", err)
	}
	if r3, err := s.admitProjectQuota(ctx, "/acme", 2, 0); err != nil {
		t.Errorf("2 vCPU should fit exactly (8 - 2 visible - 4 unseen): %v", err)
	} else {
		r3.Release(CommitFact{})
	}
}

// TestWorkloadQuotaContribution_IdentityIsKindAndHost: a name alone is not an identity.
// A VM must not satisfy a container's charge, and a same-named container on another
// host must not either — both would retire a charge that is still owed.
func TestWorkloadQuotaContribution_IdentityIsKindAndHost(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "twin", HostName: "h1", State: "running", Project: "/acme",
		CPUActual: 4, MemActual: 4096,
		Spec: `{"name":"twin","cpu":4,"memory_mib":4096}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// A CONTAINER charge named "twin" on host h2 must not be satisfied by the VM.
	if _, _, found, err := corrosion.WorkloadQuotaContribution(ctx, s.db, "/acme",
		corrosion.WorkloadContainer, "h2", "twin"); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if found {
		t.Error("a VM satisfied a CONTAINER's identity — kind must disambiguate, or the wrong " +
			"charge retires")
	}
	// The VM itself is found under its own kind.
	if cpu, _, found, err := corrosion.WorkloadQuotaContribution(ctx, s.db, "/acme",
		corrosion.WorkloadVM, "", "twin"); err != nil || !found || cpu != 4 {
		t.Errorf("VM lookup: cpu=%d found=%v err=%v; want 4/true/nil", cpu, found, err)
	}
}

// TestCreateContainer_CPUIsSerializedAgainstProjectQuota is the regression test for
// container CPU quota being unserialized.
//
// SumProjectUsage counts a container's cpu_limit against the project's vCPU budget, but
// admission passed 0 for CPU and ran only when memory was non-zero. So concurrent
// containers could exceed the project vCPU limit, and a CPU-limited container with
// UNLIMITED memory skipped serialized admission entirely.
//
// The probe: hold an in-flight reservation consuming the whole vCPU quota, then create a
// container with cpu set and memory ZERO — the case that used to bypass admission
// altogether.
func TestCreateContainer_CPUIsSerializedAgainstProjectQuota(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)
	// A runtime must be wired for the request to reach admission at all; the test
	// asserts we are refused BEFORE it is ever used.
	s.containerRuntime = &fakeCT{}
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	hold, err := s.admitProjectQuota(ctx, "/acme", 4, 0)
	if err != nil {
		t.Fatalf("seed reservation: %v", err)
	}
	defer hold.Release(CommitFact{})

	_, err = s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "cpuhog", Project: "/acme", Cpu: 4, MemoryMib: 0, // uncapped memory
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("container with cpu=4, memory=0 against a fully-reserved 4 vCPU project quota: "+
			"got %v, want ResourceExhausted — container CPU counts toward project quota, and an "+
			"uncapped-memory container must not skip serialized admission", err)
	}
}

// TestUpdateVM_StoppedVMGrowIsAdmitted is the regression test for a stopped VM growing
// without project-quota admission.
//
// The admission lived inside the `vm.State != "stopped"` branch (the restart path), so an
// already-stopped VM fell straight through and persisted a larger spec unadmitted — and a
// stopped VM's spec DOES count toward SumProjectUsage, so the project silently went over.
func TestUpdateVM_StoppedVMGrowIsAdmitted(t *testing.T) {
	s, ctx := quotaServer(t, 4, 4096)
	s.virt = libvirtfake.New()
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	// A STOPPED VM at 2 vCPU / 1024 MiB, owned here.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "parked", HostName: s.hostName, State: "stopped", Project: "/acme",
		CPUActual: 2, MemActual: 1024,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "parked", Project: "/acme", Cpu: 2, MemoryMib: 1024}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>parked</name><devices></devices></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}

	// Quota is 4 vCPU and the VM already uses 2, so growing to 8 must be refused.
	_, err = s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "parked", Cpu: 8})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("growing a STOPPED VM from 2 to 8 vCPU against a 4 vCPU project quota: got %v, "+
			"want ResourceExhausted — a stopped VM's spec counts toward project usage, so the "+
			"grow must be admitted", err)
	}

	// And nothing was persisted.
	rec, gerr := corrosion.GetVM(ctx, s.db, "parked")
	if gerr != nil || rec == nil {
		t.Fatalf("GetVM: %v", gerr)
	}
	spec := &pb.VMSpec{}
	if uerr := json.Unmarshal([]byte(rec.Spec), spec); uerr != nil {
		t.Fatalf("parse spec: %v", uerr)
	}
	if spec.Cpu != 2 {
		t.Errorf("spec cpu = %d after a REFUSED grow, want the original 2 — a refused admission "+
			"must not persist the larger size", spec.Cpu)
	}
}

// TestQuotaLease_RenewalRequiresQuorum is the regression test for a minority-side
// holder renewing forever.
//
// Quorum was checked only on initial acquisition, so a partitioned-away holder kept
// extending its LOCAL lease row indefinitely. The majority never saw those renewals,
// observed the lease expire, and elected a successor — two active authorities, each
// admitting against its own ledger.
func TestQuotaLease_RenewalRequiresQuorum(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)

	// Acquire with quorum.
	held, _, err := s.holdsQuotaLease(ctx, "/acme")
	if err != nil || !held {
		t.Fatalf("acquire with quorum: held=%v err=%v", held, err)
	}

	// Quorum is lost (this node is now on the minority side). SplitBrainGateV1 must be
	// enforced for decideGateRefused to consult the DECIDE gate at all — see the note
	// on holdsQuotaLease about that dependency.
	s.SetGate(fakeServerGate{
		execOK: true, decideOK: false, // DECIDE gate refuses
		enforcedTok: map[string]bool{
			capabilities.ProjectQuotaAuthorityV1: true,
			capabilities.SplitBrainGateV1:        true,
		},
	})

	held, _, err = s.holdsQuotaLease(ctx, "/acme")
	if err != nil {
		t.Fatalf("renewal attempt without quorum: %v", err)
	}
	if held {
		t.Error("renewed the admission lease WITHOUT quorum — a minority-side holder must stand " +
			"down, or it keeps extending a lease the majority has already reassigned")
	}
}

// TestAdmission_CommitIsFencedWhenAuthorityMoves is the regression test for charges
// being discarded before the successor could account for them.
//
// The renewer zeroes the ledger on lease loss. That is only sound if the in-flight
// request cannot still commit: otherwise the successor admits the same quota (it sees
// neither the pending reservation nor the unreplicated workload) and the original
// request finishes on top of it. The fence is what makes the drop safe — a grant must
// refuse to commit once authority has moved.
func TestAdmission_CommitIsFencedWhenAuthorityMoves(t *testing.T) {
	s, ctx := quotaServer(t, 8, 8192)
	holder, _, err := s.projectQuotaHolder(ctx, "/acme")
	if err != nil || holder != s.hostName {
		t.Skipf("not the holder (%q)", holder)
	}

	adm, err := s.admitResources(ctx, "test-host", "/acme", 4, 2048, true)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer adm.Release(CommitFact{})

	// While this request is in flight, it is still allowed to commit.
	if ferr := adm.AllowCommit(ctx); ferr != nil {
		t.Fatalf("AllowCommit while we still hold authority: %v", ferr)
	}

	// Authority moves: our lease is gone and a successor holds it.
	if err := s.db.Execute(ctx,
		`UPDATE leader_election SET holder = ?, expires_at = ? WHERE key = ?`,
		"successor", time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		corrosion.QuotaLeaseKey("/acme")); err != nil {
		t.Fatalf("hand lease to successor: %v", err)
	}

	ferr := adm.AllowCommit(ctx)
	if status.Code(ferr) != codes.Aborted {
		t.Fatalf("AllowCommit after authority moved: got %v, want Aborted — an in-flight request "+
			"must NOT commit once a successor may already have admitted the same quota", ferr)
	}
}

// TestAdmission_ZeroValueAllowsCommit: an admission that reserved no quota (unbounded
// project, feature inactive, host-only) has no authority to lose, so the fence must not
// refuse it. Getting this wrong would block every create on a project with no quota.
func TestAdmission_ZeroValueAllowsCommit(t *testing.T) {
	var zero Admission
	if err := zero.AllowCommit(context.Background()); err != nil {
		t.Errorf("zero-value Admission.AllowCommit = %v, want nil", err)
	}
	zero.Release(CommitFact{Committed: true, Workload: "x"}) // must not panic
}
