package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ADMISSION CONTRACT — who may be admitted at all.
//
// Capacity admission is for OPERATOR-INITIATED requests only (create, start,
// restart-of-stopped, clone, import, restore, migrate, promote, resize). The
// automated recovery paths (startVMLocked's reconciler/failover callers,
// PrepareHardwareForStart, operation recovery) must never be admitted: after a
// host reboot every VM restarts at once, and admitting there would start the
// first few and strand the rest, turning a clean recovery into a partial one.
// Do not push admission down into a shared primitive those paths also call.
// (This doctrine predates reserve-then-verify — it used to live on the
// in-process admission ledger that replicated reservations replaced — and it
// binds the admitReserved family in reservation_admission.go exactly the same.)

// noopRelease is the release func for an admission that reserved nothing.
func noopRelease() {}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// requireOvercommit gates the --allow-overcommit capacity bypass. Skipping the
// host capacity check is an operator-level judgment call, not a routine
// lifecycle action: a binding that grants only lifecycle verbs (vm.start,
// vm.create, …) must not carry it. Wildcard grants (Operator's vm.*) do; in
// the legacy no-bindings model every operator keeps it, unchanged.
func (s *Server) requireOvercommit(ctx context.Context, path string) error {
	return s.RequirePerm(ctx, path, "vm.overcommit", "operator")
}

// checkHostCapacity reports whether a proposed CPU/memory GROW (positive deltas,
// MiB) fits the target host's free capacity AT THIS INSTANT — quota-free, for
// start-time paths where the allocation is already counted in project usage
// (see StartVM).
//
// This function only READS. It is NOT serialized against a concurrent admission:
// two callers can both pass it and both proceed. Use it as a REMOTE fail-fast
// only. A caller that will actually commit the workload must use the
// admitReserved family (reservation_admission.go), whose replicated
// reservation spans the commit.
func (s *Server) checkHostCapacity(ctx context.Context, host string, cpuDelta, memMiBDelta int) error {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return nil
	}
	// HostFreeCapacity nets out committed running-VM/container actuals and
	// in-flight nonterminal operation reservations (reserve-then-verify made
	// the replicated reservation the ONLY in-flight ledger; the old in-process
	// one had no writers left and is gone).
	freeCPU, freeMem, ok, err := corrosion.HostFreeCapacityWithPolicy(ctx, s.db, host, s.capacity)
	if err != nil {
		return status.Errorf(codes.Internal, "check host capacity: %v", err)
	}
	if ok && (cpuDelta > freeCPU || memMiBDelta > freeMem) {
		return status.Errorf(codes.ResourceExhausted,
			"host %s has insufficient free capacity for +%d vCPU/+%d MiB (free: %d vCPU/%d MiB)",
			host, cpuDelta, memMiBDelta, freeCPU, freeMem)
	}
	return nil
}

// checkResourceAdmission is the UNSERIALIZED, read-only form: it reports whether a
// proposed CPU/memory GROW (positive deltas, MiB) fits BOTH the target host's free
// capacity AND the project's quota AT THIS INSTANT, counting in-flight reservations
// from nonterminal operations as well as committed usage.
//
// Two concurrent callers CAN both pass it. It remains correct as a remote
// fail-fast; a caller that will commit the workload must use the admitReserved
// family, which reserves-then-verifies per host and routes project quota to
// the project's authority holder.
//
// It returns codes.ResourceExhausted when a dimension would be exceeded, and nil for
// a shrink/no-op (deltas ≤ 0 never need capacity). An unbounded project (no quota
// row) skips the quota check; an unknown host skips the host-capacity check.
func (s *Server) checkResourceAdmission(ctx context.Context, host, project string, cpuDelta, memMiBDelta int) error {
	if err := s.checkHostCapacity(ctx, host, cpuDelta, memMiBDelta); err != nil {
		return err
	}
	return s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta)
}

// checkProjectQuota verifies a proposed CPU/memory GROW against the project's
// quota alone. Split out so --allow-overcommit paths can skip the HOST check
// (a physical judgment call) while still enforcing quota (a tenancy limit).
func (s *Server) checkProjectQuota(ctx context.Context, project string, cpuDelta, memMiBDelta int) error {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return nil
	}
	// Project quota: committed usage + in-flight reservations + this grow.
	q, err := corrosion.GetProjectQuota(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Internal, "get project quota: %v", err)
	}
	if q == nil {
		return nil // unbounded
	}
	u, err := corrosion.SumProjectUsage(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Internal, "sum project usage: %v", err)
	}
	rCPU, rMem, err := corrosion.ProjectReserved(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Internal, "sum project reservations: %v", err)
	}
	if quotaWouldExceed(q.VCPULimit, u.VCPUUsed, rCPU, cpuDelta) {
		return status.Errorf(codes.ResourceExhausted,
			"project %q vCPU quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.VCPUUsed, rCPU, cpuDelta, q.VCPULimit)
	}
	if quotaWouldExceed(q.MemMiBLimit, u.MemMiBUsed, rMem, memMiBDelta) {
		return status.Errorf(codes.ResourceExhausted,
			"project %q memory quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.MemMiBUsed, rMem, memMiBDelta, q.MemMiBLimit)
	}
	return nil
}

func quotaWouldExceed(limit, used, reserved, delta int) bool {
	if limit <= 0 {
		return false
	}
	if used < 0 || reserved < 0 {
		return true
	}
	if delta < 0 {
		delta = 0
	}
	remaining := limit
	for _, amount := range []int{used, reserved, delta} {
		if amount > remaining {
			return true
		}
		remaining -= amount
	}
	return false
}

// ensureProjectAuthority makes sure the project has a D1 admission-authority epoch,
// minting the initial one if none exists. The returned authority is the current one
// (for recording in an operation's reserved step, and for routing quota admission).
//
// Only the DETERMINISTIC candidate mints. The previous version had every node claim
// with holder = s.hostName and treated a concurrent claim as harmless — "exactly one
// wins the guarded initial claim". That is not what happens.
// ClaimInitialProjectAuthority's guard runs inside ExecuteBatchGuarded, which is a
// LOCAL transaction, so on two nodes both guards see COUNT(*) = 0 before either has
// replicated and both insert epoch 1. project_authority_epochs then merges via
// immutableMergeKeepLocalRow, which does NOT coin-flip an immutable row: differing
// facts for one primary key are kept-local on both sides and flagged
// immutable_conflict, permanently. The project ends up with two holders and an
// operator has to repair it. (And since immutableFactsEqual compares created_at,
// per-node wall time, even two claims naming the same holder conflict — so making
// the holder agree is not enough; only one node may write.)
//
// Reachable before this change: the resize path calls this best-effort on whichever
// owner resizes, so two owners resizing VMs in one project were enough.
//
// A non-candidate returns whatever authority currently exists (ok=false → zero
// value) rather than minting. It converges as soon as the candidate handles a
// request for the project.
func (s *Server) ensureProjectAuthority(ctx context.Context, project string) (corrosion.ProjectAuthority, error) {
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	if ok {
		return cur, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	candidate, hasCandidate := corrosion.DeterministicAuthorityCandidate(hosts, project)
	if !hasCandidate || candidate != s.hostName {
		return corrosion.ProjectAuthority{}, nil
	}
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, project, s.hostName); err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	cur, _, err = corrosion.CurrentProjectAuthority(ctx, s.db, project)
	return cur, err
}

// derivedProjectHolder computes who SHOULD hold a project's initial authority from
// this node's view of cluster membership. Returns "" when no hosts can be read.
//
// Both the minting node and the holder run this independently, which is what makes
// bootstrap work: the claim is written on the CALLER's replica, so the holder does not
// yet have the row naming it. Rather than wait for replication — during which the
// admission would fail — the holder re-derives and confirms the answer for itself.
// It MUST agree with corrosion.DeterministicAuthorityCandidate, which is why it
// simply calls it: that function decides who may MINT, and this one decides who may
// CONFIRM a not-yet-replicated mint. Two derivations here would let a node confirm
// authority no node was allowed to mint — and they did diverge, on both the hash
// and the host filter, until they were collapsed onto one.
func (s *Server) derivedProjectHolder(ctx context.Context, project string) string {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil || len(hosts) == 0 {
		return ""
	}
	candidate, ok := corrosion.DeterministicAuthorityCandidate(hosts, project)
	if !ok {
		return ""
	}
	return candidate
}

// stampReservationAuthority records which authority epoch admitted a reservation.
//
// Capacity aggregation will not count a reservation it cannot attribute to a
// project's CURRENT authority once one exists (corrosion.nonterminalReservationsByID).
// A mint that skips this therefore holds no capacity at all — the lease looks live in
// the journal while the headroom it should be protecting is handed to the next
// admission. Every reservation writer calls this immediately after inserting.
//
// A project with DEFINITELY no authority yet stamps empty facts, which aggregation
// treats as a legacy claim and keeps counting. An authority read FAILURE is a
// different state and fails closed: treating it as "no authority" would stamp
// empty facts on a project that does have a current authority, and aggregation
// would then refuse to count the reservation — a live lease consuming nothing,
// its headroom handed to the next admission. The caller releases the provisional
// operation and refuses the admission; nothing is admitted on an unreadable
// authority ledger.
func (s *Server) stampReservationAuthority(ctx context.Context, opID, project string) error {
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot read project-quota authority for %q before attributing its reservation: %v", project, err)
	}
	var facts *corrosion.ReservationFacts
	if ok {
		facts = corrosion.ReservationFactsFor(project, cur.Epoch, cur.Holder)
	}
	if err := corrosion.AppendReservationFacts(ctx, s.db, opID, 0, project, facts); err != nil {
		return status.Errorf(codes.Internal, "record reservation authority: %v", err)
	}
	return nil
}
