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

// CommitFact is what a caller tells the quota authority when it releases: whether
// the workload was durably written, and if so its IDENTITY and post-commit counted
// size.
//
// Identity is not optional bookkeeping. The authority holds a charge until it can
// SEE the commit, and "see" has to mean "see THIS workload" — an aggregate
// usage-growth heuristic is fooled by any unrelated increase (a workload created
// before the charge that replicates late, or one admitted through the fail-open
// path), which would retire this charge early and let the next request over-admit.
//
// CPU/MemMiB are the workload's ABSOLUTE post-commit counted values, not the delta,
// so a resize is observable the same way a create is: the authority compares what
// its own replica says the workload contributes against what it should contribute.
type CommitFact struct {
	Committed bool
	Workload  string // VM or container name
	// Kind and Host complete the identity. A name alone is ambiguous: a VM and a
	// container can share one, and container names are unique only per host — so
	// without these, an unrelated row could retire a charge that is still owed.
	// Kind is corrosion.WorkloadVM or corrosion.WorkloadContainer; Host matters only
	// for containers.
	Kind   string
	Host   string
	CPU    int
	MemMiB int
}

// noopReleaseCommitted is the release for a quota admission that reserved nothing.
func noopReleaseCommitted(CommitFact) {}

// Admission is a granted admission: how to give it back, and — for the quota half —
// whether it is still allowed to COMMIT.
//
// The fence exists because a lease handoff cannot be made safe by bookkeeping alone.
// If the authority loses its lease while a 4-vCPU create is in flight, the successor
// sees neither the pending reservation nor the workload (it has not replicated), so it
// admits another 4 — and the original create then finishes and puts the project over
// quota. Keeping the old holder's charges does not help either: the successor never
// learns of them. The only sound options are durable/transferred reservations or
// ABORTING the outstanding operation, and this is the abort.
//
// AllowCommit is called immediately before the durable write. Past that point the
// write has happened and the charge is real; before it, refusing costs only a retry.
type Admission struct {
	release func(CommitFact)
	fence   func(context.Context) error
	// reservationID names the durable quota_reservations row, when there is one. The
	// holder-side RPC returns it so a routed caller can fence on a LOCAL read of that
	// replicated row instead of asking over the network.
	reservationID string
}

// Release returns the admission. Safe on a zero value.
func (a Admission) Release(f CommitFact) {
	if a.release != nil {
		a.release(f)
	}
}

// AllowCommit reports whether this admission may still be committed. Call it
// IMMEDIATELY before the durable write — the narrower the gap, the smaller the window
// in which authority can move between the check and the write.
//
// A zero value allows: an admission that reserved no quota (unbounded project, feature
// inactive, host-only) has no authority to lose.
func (a Admission) AllowCommit(ctx context.Context) error {
	if a.fence == nil {
		return nil
	}
	return a.fence(ctx)
}

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
// newVMOnHost says whether a VM is APPEARING on this host (a create, or a start of
// a stopped VM) as opposed to a delta on one already running. When true the HOST
// side is charged one extra qemu overhead, because free capacity is computed net of
// one overhead per VM already there and the incoming one is not counted yet. A
// delta on a running VM must NOT be charged again — its overhead is already
// subtracted, so re-adding it would refuse a legal grow, every time.
//
// The overhead is charged to the HOST only, never to project quota: it is a
// physical cost of running qemu, not tenant-consumed memory, and folding it into
// quota would quietly shrink every project's effective limit.
//
// The host lock is released before the quota step, which may make a peer RPC to
// the project's authority holder. That ordering is load-bearing: never hold the
// host lock across a peer call.
// The returned release takes `committed`: whether the caller actually wrote the
// workload. It matters only for the QUOTA half, and only because the workload is
// committed by the target HOST while quota is serialized by the project's authority
// — possibly a third node. On a commit the authority must keep the charge until its
// own replica shows the workload, or a concurrent request is handed the same quota
// in the replication gap. The HOST half always just releases: the node that reserved
// is the node that committed, so its own usage query sees the write immediately.
//
// Set CommitFact.Committed at the DURABLE WRITE, never from the handler's error
// return. An RPC can fail after the row is written — a cancelled context, a read
// failure while building the response — and reporting that as "not committed" frees
// the authority's charge while the workload exists on the target. Passing true for a
// failed operation instead holds quota until the grace TTL, which is the safe
// direction but still wrong.
func (s *Server) admitResources(ctx context.Context, host, project string, cpuDelta, memMiBDelta int, newVMOnHost bool) (Admission, error) {
	hostMem := memMiBDelta
	if newVMOnHost {
		hostMem = s.capacity.MemChargeFor(memMiBDelta)
	}
	release, err := s.admitHostCapacity(ctx, host, cpuDelta, hostMem)
	if err != nil {
		return Admission{}, err
	}
	q, err := s.admitProjectQuota(ctx, project, cpuDelta, memMiBDelta)
	if err != nil {
		release()
		return Admission{}, err
	}
	return Admission{
		release: func(f CommitFact) { q.Release(f); release() },
		fence:   q.fence,
	}, nil
}

// projectIsBounded reports whether the project has a quota row at all.
// false means unbounded: nothing to enforce, so nothing to serialize.
func (s *Server) projectIsBounded(ctx context.Context, project string) (bool, error) {
	q, err := corrosion.GetProjectQuota(ctx, s.db, project)
	if err != nil {
		return false, status.Errorf(codes.Internal, "get project quota: %v", err)
	}
	return q != nil, nil
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
	return s.checkProjectQuotaWithPending(ctx, project, cpuDelta, memMiBDelta, 0, 0)
}

// checkProjectQuotaWithPending is checkProjectQuota plus this node's own
// admitted-but-uncommitted grows for the project. Only the authority holder passes
// non-zero pending values — everywhere else the ledger is meaningless, because
// admissions for the project may be happening on another node.
func (s *Server) checkProjectQuotaWithPending(ctx context.Context, project string, cpuDelta, memMiBDelta, pendingCPU, pendingMem int) error {
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
	if q.VCPULimit > 0 && u.VCPUUsed+rCPU+pendingCPU+cpuDelta > q.VCPULimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q vCPU quota exceeded (used %d + reserved %d + in-flight %d + new %d > limit %d)",
			project, u.VCPUUsed, rCPU, pendingCPU, cpuDelta, q.VCPULimit)
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+rMem+pendingMem+memMiBDelta > q.MemMiBLimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q memory quota exceeded (used %d + reserved %d + in-flight %d + new %d > limit %d)",
			project, u.MemMiBUsed, rMem, pendingMem, memMiBDelta, q.MemMiBLimit)
	}
	return nil
}
