package grpcapi

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostAdmitState is the per-host (or per-project) admission ledger: a leaf mutex
// plus the resources this node has admitted but not yet committed.
//
// mu is a LEAF lock. Only local DB READS happen under it — no writes (those take
// the corrosion client mutex), no lockVM, and never a peer RPC. That is what makes
// it impossible for it to participate in a lock cycle.
type hostAdmitState struct {
	mu         sync.Mutex
	pendingCPU int // admitted-but-uncommitted vCPU
	pendingMem int // admitted-but-uncommitted MiB
}

// noopRelease is the release func for an admission that reserved nothing.
func noopRelease() {}

func (s *Server) hostAdmitStateFor(host string) *hostAdmitState {
	s.hostAdmitMu.Lock()
	defer s.hostAdmitMu.Unlock()
	if s.hostAdmit == nil {
		s.hostAdmit = map[string]*hostAdmitState{}
	}
	st, ok := s.hostAdmit[host]
	if !ok {
		st = &hostAdmitState{}
		s.hostAdmit[host] = st
	}
	return st
}

// releaseFor returns an idempotent release func that gives the reservation back.
// Idempotent because a caller may both `defer release()` and release early; a
// double release must never drive the ledger negative and hand out capacity twice.
func (st *hostAdmitState) releaseFor(cpu, mem int) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			st.mu.Lock()
			st.pendingCPU -= cpu
			st.pendingMem -= mem
			if st.pendingCPU < 0 {
				st.pendingCPU = 0
			}
			if st.pendingMem < 0 {
				st.pendingMem = 0
			}
			st.mu.Unlock()
		})
	}
}

// freeHostCapacityLocked reports free capacity net of this node's in-flight
// admissions. Caller must hold st.mu when st != nil.
func (s *Server) freeHostCapacityLocked(ctx context.Context, host string, st *hostAdmitState) (freeCPU, freeMem int, ok bool, err error) {
	freeCPU, freeMem, ok, err = corrosion.HostFreeCapacityWithPolicy(ctx, s.db, host, s.capacity)
	if err != nil || !ok {
		return 0, 0, ok, err
	}
	if st != nil {
		freeCPU -= st.pendingCPU
		freeMem -= st.pendingMem
	}
	if freeCPU < 0 {
		freeCPU = 0
	}
	if freeMem < 0 {
		freeMem = 0
	}
	return freeCPU, freeMem, true, nil
}

// admitHostCapacity checks a proposed CPU/memory GROW (positive deltas, MiB)
// against the target host's free capacity and, when the host is THIS node,
// RESERVES it. The returned release func is never nil and must be deferred.
//
// Why a ledger and not just a lock. Between admission and the commit that makes
// the workload visible to HostFreeCapacityWithPolicy, CreateVM does an image pull
// (a blocking peer stream, potentially minutes), disk creation, cloud-init ISO
// generation, DefineDomain/StartDomain and root PreStart hooks. A lock held across
// that would serialize image transfers and would hold a process lock across a peer
// RPC, which this codebase forbids (see StartVM). But a lock released before the
// commit is useless on its own: two creates would both check, both see the same
// free capacity, both pass, and both commit. So the lock's only job is making
// check-then-reserve atomic, and the RESERVATION is what spans the commit.
//
// Scope, deliberately stated so nothing here overclaims:
//   - The ledger is PER PROCESS. Two daemons admitting for the same host are kept
//     apart only by the single-owner invariant, not by this lock.
//   - It is LOST ON RESTART. In-flight admissions are forgotten, which is a bounded
//     over-admission window, not a durable guarantee.
//   - It covers vCPU and memory only.
//
// For a host that is NOT this node this is a lock-free, reservation-free fail-fast:
// we will not commit there, so we must not reserve there either, and the owner
// re-admits authoritatively when the request is forwarded.
//
// CONTRACT: this is for OPERATOR-initiated requests only. The automated recovery
// paths (startVMLocked, PrepareHardwareForStart, the failover/reconciler restarts,
// operation recovery) must never be admitted — after a host reboot every VM
// restarts at once, and admitting there would start the first few and strand the
// rest, turning a clean recovery into a partial one. Do not push admission down
// into a shared primitive those paths also call.
func (s *Server) admitHostCapacity(ctx context.Context, host string, cpuDelta, memMiBDelta int) (func(), error) {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return noopRelease, nil // a shrink or no-op never needs capacity
	}
	if host != s.hostName {
		return noopRelease, s.checkHostCapacity(ctx, host, cpuDelta, memMiBDelta)
	}

	st := s.hostAdmitStateFor(host)
	st.mu.Lock()
	freeCPU, freeMem, ok, err := s.freeHostCapacityLocked(ctx, host, st)
	if err != nil {
		st.mu.Unlock()
		return noopRelease, status.Errorf(codes.Internal, "check host capacity: %v", err)
	}
	if ok && (cpuDelta > freeCPU || memMiBDelta > freeMem) {
		st.mu.Unlock()
		// "filled up" rather than "is full": the shortfall may be another
		// in-flight request on this node, so the caller should retry.
		return noopRelease, status.Errorf(codes.ResourceExhausted,
			"host %s has insufficient free capacity for +%d vCPU/+%d MiB (free: %d vCPU/%d MiB, "+
				"including admitted-but-uncommitted requests) — retry",
			host, cpuDelta, memMiBDelta, freeCPU, freeMem)
	}
	cpu, mem := maxInt(cpuDelta, 0), maxInt(memMiBDelta, 0)
	st.pendingCPU += cpu
	st.pendingMem += mem
	st.mu.Unlock()
	return st.releaseFor(cpu, mem), nil
}

// reserveHostCapacity reserves a grow WITHOUT checking it — for
// --allow-overcommit, which deliberately bypasses the host check but must still
// make its own draw visible to a concurrent normal admission. Otherwise an
// overcommit create would hide its memory from the very next request.
func (s *Server) reserveHostCapacity(host string, cpuDelta, memMiBDelta int) func() {
	if host != s.hostName || (cpuDelta <= 0 && memMiBDelta <= 0) {
		return noopRelease
	}
	cpu, mem := maxInt(cpuDelta, 0), maxInt(memMiBDelta, 0)
	st := s.hostAdmitStateFor(host)
	st.mu.Lock()
	st.pendingCPU += cpu
	st.pendingMem += mem
	st.mu.Unlock()
	return st.releaseFor(cpu, mem)
}

// admitResources is the OWNER-SIDE admission: host capacity (serialized and
// reserved when the host is this node) plus project quota. The returned release
// func is never nil and must be deferred by the caller so the reservation
// outlives the commit.
//
// intent.vmOverhead says whether a qemu domain is APPEARING on this host (a
// create, or a start of a stopped VM) as opposed to a delta on one already
// running. When set the HOST side is charged one extra qemu overhead, because
// free capacity is computed net of one overhead per VM already there and the
// incoming one is not counted yet. A delta on a running VM must NOT be charged
// again — its overhead is already subtracted, so re-adding it would refuse a
// legal grow, every time. (See admissionIntent for why overhead and residency
// are separate facts.)
//
// The overhead is charged to the HOST only, never to project quota: it is a
// physical cost of running qemu, not tenant-consumed memory, and folding it into
// quota would quietly shrink every project's effective limit.
//
// The host lock is released before the quota step, which may make a peer RPC to
// the project's authority holder. That ordering is load-bearing: never hold the
// host lock across a peer call.
func (s *Server) admitResources(ctx context.Context, host, project string, cpuDelta, memMiBDelta int, intent admissionIntent) (func(), error) {
	hostMem := memMiBDelta
	if intent.vmOverhead {
		hostMem = s.capacity.MemChargeFor(memMiBDelta)
	}
	release, err := s.admitHostCapacity(ctx, host, cpuDelta, hostMem)
	if err != nil {
		return noopRelease, err
	}
	if err := s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta); err != nil {
		release()
		return noopRelease, err
	}
	return release, nil
}

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
// only. A caller that will actually commit the workload must use
// admitHostCapacity, which makes check-then-reserve atomic and holds the
// reservation across the commit.
func (s *Server) checkHostCapacity(ctx context.Context, host string, cpuDelta, memMiBDelta int) error {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return nil
	}
	// HostFreeCapacity nets out committed running-VM/container actuals and
	// in-flight nonterminal operation reservations. For this host, also net out
	// admissions this node has granted but not yet committed.
	var st *hostAdmitState
	if host == s.hostName {
		st = s.hostAdmitStateFor(host)
		st.mu.Lock()
		defer st.mu.Unlock()
	}
	freeCPU, freeMem, ok, err := s.freeHostCapacityLocked(ctx, host, st)
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
// fail-fast; a caller that will commit the workload must use admitResources, which
// makes check-then-reserve atomic per host and routes project quota to the
// project's authority holder.
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
