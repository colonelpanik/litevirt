package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// admissionIntent names the two INDEPENDENT facts an admission needs about the
// action it is deciding, which one boolean used to conflate:
//
//   - newResidency: the action makes a workload RESIDENT on the target host
//     (create, start, migrate-in, restore-in, fresh promotion). This is the
//     SAFETY fact: incomplete or unattributable local inventory refuses new
//     residency regardless of the numeric delta, because an uncapped container
//     asks the ledger for nothing and still lands on the host.
//   - vmOverhead: the target receives a qemu DOMAIN, so the HOST figures carry
//     the per-domain memory overhead. Host-only, never project quota — the
//     hypervisor's cost of running the guest, not memory the tenant asked for.
//
// Containers become resident without ever paying qemu overhead; a resource grow
// of a running workload is neither. Conflating the two is what let container
// callers opt out of residency safety by (correctly) declining VM overhead.
type admissionIntent struct {
	newResidency bool
	vmOverhead   bool
}

var (
	// intentVMResident: a qemu domain appears on the host (VM create, start of a
	// stopped VM, migrate-in, restore-in, fresh promotion).
	intentVMResident = admissionIntent{newResidency: true, vmOverhead: true}
	// intentContainerResident: a container appears on the host — full residency
	// safety, no qemu overhead.
	intentContainerResident = admissionIntent{newResidency: true}
	// intentResourceGrow: a delta on a workload already resident and counted,
	// overhead included.
	intentResourceGrow = admissionIntent{}
)

// quotaSubject is the workload a project-quota admission is FOR: its identity
// (kind, host, name) and the ABSOLUTE size the admission grows it to. The settle
// rule retires a released lease only when this workload contributes at least the
// want — see corrosion.WorkloadQuotaContribution for why identity and size, not
// presence or aggregate growth, are the sound retire signals. A zero subject means
// the admission carries no retire-by-observation hint and settles on presence of
// its resource_id (correct for host-only reservations).
type quotaSubject struct {
	Kind, Host, Name string
	Want             corrosion.QuotaAmount
}

// subjectForCreate derives the subject from a create's "vm:<name>" / "ct:<name>"
// resource id. A create's absolute size IS its delta: the workload does not exist
// yet, so what it will contribute equals what is being admitted.
func subjectForCreate(resourceID, host string, delta corrosion.QuotaAmount) quotaSubject {
	kindTag, name, ok := strings.Cut(resourceID, ":")
	if !ok || name == "" {
		return quotaSubject{}
	}
	kind := corrosion.WorkloadVM
	if kindTag == "ct" {
		kind = corrosion.WorkloadContainer
	}
	return quotaSubject{Kind: kind, Host: host, Name: name, Want: delta}
}

// Reserve-then-verify admission (F2).
//
// Every capacity consumer used to READ headroom and then write. Two admissions for
// the same project on different hosts each read a view that did not yet contain the
// other, both passed, and both persisted — the cluster ends up over its own limits
// with neither request having done anything wrong. Even the one path that already
// carried a reservation vector wrote it AFTER its check (resize.go), so two
// concurrent resizes raced identically; the vector only protected against
// operations that had started earlier still being in flight.
//
// Inverting the order closes it without a central coordinator:
//
//	reserve — persist a nonterminal operation carrying this admission's deltas
//	verify  — re-read headroom, which nets out EVERY nonterminal reservation,
//	          adding back our own and any LATER claimant's
//	release — free the provisional reservation, whatever the outcome
//
// Adding our own back is what keeps the comparison honest: headroom already
// subtracted our demand, so verifying "delta fits in headroom" without it would
// double-count and refuse admissions that fit.
//
// Deterministic tie-break. If both racers simply refused, the cluster would be safe
// but nobody would get in; the useful property is that exactly ONE proceeds.
// Reservations are ordered by operation id — globally unique, so the order is total
// and every node derives the same winner — and an admission yields only to
// reservations that sort BEFORE it. The earliest claimant wins; later ones see their
// own reservation excluded, find the earlier one still consuming headroom, and
// stand down.
//
// KNOWN LIMIT, stated rather than papered over: this closes the race whenever both
// reservations are VISIBLE to both deciders. Corrosion is eventually consistent, so
// two nodes that have not yet exchanged operation rows can still both admit. Closing
// that needs the fenced project-authority epoch — a single decider per project —
// which is the remaining half of F2. This is the primitive that half builds on, not
// a substitute for it.

// releaseTimeout bounds the best-effort release of a lease whose caller context
// has already been cancelled.
const releaseTimeout = 10 * time.Second

// reservationLease is a provisional capacity reservation held while an admission
// decides. The caller MUST release it exactly once, whatever the outcome: a leaked
// lease permanently consumes capacity no workload is using.
type reservationLease struct {
	s  *Server
	id string
	// hostHolder is the daemon holding the HOST half when it is not this node —
	// a destination-owned migration lease (acquireDestinationHostLease). The
	// operation row lives in the DESTINATION's database, so release must travel
	// back over the peer channel instead of terminating a local operation.
	hostHolder string
	// The PROJECT-QUOTA half may be held on another node — the project's admission
	// authority holder — so it is tracked separately from the local host reservation
	// and released wherever it actually lives.
	quotaHolder  string
	quotaProject string
	quotaLease   string
	// quotaEpoch is the authority epoch the quota grant was made under; 0 means no
	// epoch-bearing authority was involved (no quota reserved, or the pre-epoch
	// fallback), in which case the fence allows. See allowCommit.
	quotaEpoch int64
}

// allowCommit reports whether this admission may still be COMMITTED, and must be
// called immediately before the durable write — the narrower the gap, the smaller
// the window in which authority can move between the check and the write.
//
// The fence exists because an authority handoff cannot be made safe by bookkeeping
// alone. The grant lives in the OLD holder's replica; a takeover mints a new epoch
// on evidence that does not include un-replicated leases, so the successor can
// admit the same quota while this request is still in flight — and this request
// then completes and puts the project over. Keeping the old lease counted does not
// help: the successor never learns of it in time. The only sound options are
// durable transferred reservations or ABORTING the outstanding operation, and this
// is the abort. Refusing here costs a retry and writes nothing.
//
// A zero epoch allows: an admission that reserved no quota (unbounded project,
// delegation inactive, host-only) has no authority to lose, and blocking it would
// fail every create on a quota-less project.
func (l *reservationLease) allowCommit(ctx context.Context) error {
	if l == nil || l.s == nil || l.quotaEpoch == 0 {
		return nil
	}
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, l.s.db, l.quotaProject)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot confirm project-quota authority for %q before committing: %v", l.quotaProject, err)
	}
	if !ok {
		// OUR replica has no authority row at all. At the bootstrap epoch that is
		// the expected state everywhere but the holder: the grant was routed to the
		// derived candidate, which minted on ITS replica, and this fence runs before
		// that mint can possibly have replicated back — failing here would abort
		// every routed first admission of every project. Absence tells us nothing
		// about movement (a fence read is only ever as fresh as this replica, its
		// documented limit), so the bootstrap grant commits. A LATER epoch is
		// different: we read that row locally when admitting, and epoch rows are
		// never deleted, so its disappearance is a state problem — fail closed.
		if l.quotaEpoch == 1 {
			return nil
		}
		return status.Errorf(codes.Unavailable,
			"project-quota authority for %q (granted at epoch %d) is no longer readable in the local replica; "+
				"nothing was committed — retry", l.quotaProject, l.quotaEpoch)
	}
	if cur.Epoch != l.quotaEpoch || cur.Holder != l.quotaHolder {
		return status.Errorf(codes.Aborted,
			"project-quota authority for %q moved past epoch %d while this request was in flight; "+
				"nothing was committed — retry", l.quotaProject, l.quotaEpoch)
	}
	return nil
}

// releaseQuota frees ONLY the delegated project-quota half, leaving the local
// operation row alone. For the one path where the local reservation's op id IS
// the workload operation (resize): the workload op goes terminal via
// CompleteVMOperation (or stays nonterminal for recovery), but the quota lease
// on the holder is a SEPARATE row there that nothing else ever terminates — a
// full release() would wrongly terminate the workload op, and no release at
// all leaves the holder counting a lease forever, permanently shrinking the
// project's usable quota. Idempotent, like release.
func (l *reservationLease) releaseQuota(ctx context.Context) {
	if l == nil || l.s == nil {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	if id := l.quotaLease; id != "" {
		l.quotaLease = ""
		l.s.releaseProjectQuota(rctx, l.quotaHolder, l.quotaProject, id)
	}
}

// release marks the reservation's operation terminal, freeing the capacity.
// Idempotent, and safe on the empty lease returned for a no-op admission.
func (l *reservationLease) release(ctx context.Context) {
	if l == nil || l.s == nil {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()

	if id := l.quotaLease; id != "" {
		l.quotaLease = ""
		l.s.releaseProjectQuota(rctx, l.quotaHolder, l.quotaProject, id)
	}
	if l.id == "" {
		return
	}
	id := l.id
	l.id = ""
	if l.hostHolder != "" && l.hostHolder != l.s.hostName {
		if err := l.s.releaseRemoteHostLease(rctx, l.hostHolder, id); err != nil {
			slog.Error("destination-held capacity reservation was not released; the destination "+
				"holds it until the stale-lease sweep collects it",
				"operation", id, "destination", l.hostHolder, "error", err)
			l.s.noteStateWriteFail(string(corrosion.OpResourceUpdateRunning), err)
		}
		return
	}
	if err := corrosion.AppendOperationStep(rctx, l.s.db, corrosion.OperationStepRecord{
		OperationID: id, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		// A failed release leaks the reservation until the sweep ages it out. Log
		// it as well as counting it: noteStateWriteFail only feeds a metric, and a
		// silent leak shows up later as capacity pressure with no workload behind
		// it — which is miserable to diagnose from scratch. The lab leak above was
		// invisible in the journal for precisely this reason.
		slog.Error("capacity reservation was not released; the host will hold it until the "+
			"stale-lease sweep collects it", "operation", id, "error", err)
		l.s.noteStateWriteFail(string(corrosion.OpResourceUpdateRunning), err)
	}
}

// admitWithReservation reserves cpuDelta/memDelta against host and project, verifies
// the reservation still fits, and returns a lease the caller must release.
//
// resourceID names what is being admitted ("vm:<name>" / "ct:<name>"). It travels with
// a DELEGATED quota lease so the authority holder can tell when the admission it
// granted has actually landed in its replica, instead of guessing from a clock.
//
// A zero/negative delta consumes nothing and takes the cheap path — no operation
// row, no lease — but only AFTER host safety has passed: residency is a safety
// decision even when nothing numeric is requested (see admissionIntent).
func (s *Server) admitWithReservation(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int, intent admissionIntent,
) (*reservationLease, error) {
	return s.admitReserved(ctx, callerPrincipal(ctx), "", method, host, project, resourceID,
		subjectForCreate(resourceID, host, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta}), cpuDelta, memDelta, true, intent)
}

// admitGrowWithReservation is admitWithReservation for a GROW of an existing
// workload, which must carry the absolute target size: the workload's row is
// already visible at its old size, so without the want the released lease would
// settle instantly while usage still counted the smaller spec.
func (s *Server) admitGrowWithReservation(
	ctx context.Context, method, host, project, kind, name string, cpuDelta, memDelta, wantCPU, wantMem int,
) (*reservationLease, error) {
	tag := "vm"
	if kind == corrosion.WorkloadContainer {
		tag = "ct"
	}
	subject := quotaSubject{Kind: kind, Host: host, Name: name, Want: corrosion.QuotaAmount{VCPU: wantCPU, MemMiB: wantMem}}
	return s.admitReserved(ctx, callerPrincipal(ctx), "", method, host, project, tag+":"+name, subject, cpuDelta, memDelta, true, intentResourceGrow)
}

// admitWithReservationID is admitWithReservation with an explicit operation ID.
//
// This exists for paths where the operation identity is already known (for
// example, ResizeVMLive derives a deterministic ID from an idempotency key and
// then needs admission/verification to participate in the same winner election).
func (s *Server) admitWithReservationID(
	ctx context.Context, opID, method, host, project, resourceID string, cpuDelta, memDelta int, intent admissionIntent,
) (*reservationLease, error) {
	return s.admitReserved(ctx, callerPrincipal(ctx), opID, method, host, project, resourceID,
		subjectForCreate(resourceID, host, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta}), cpuDelta, memDelta, true, intent)
}

// admitHostWithReservation is admitWithReservation for paths that must NOT charge
// project quota — the start paths, where the allocation is already counted in
// project usage whether the workload is running or stopped, so charging it again
// would refuse a plain stop/start of any workload over half its quota.
//
// resourceID ("vm:<name>" / "ct:<name>") names the workload for the SAFETY gate
// only. A host-only admission still concerns a specific workload, and the
// ownership-dispute check keys on that identity: with an empty subject a disputed
// workload could be started or migrated onto a host the dispute does not involve,
// quietly adding another holder. The quota figures stay zero regardless — identity
// here never charges anything.
func (s *Server) admitHostWithReservation(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int, intent admissionIntent,
) (*reservationLease, error) {
	return s.admitReserved(ctx, callerPrincipal(ctx), "", method, host, project, resourceID,
		subjectForCreate(resourceID, host, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta}), cpuDelta, memDelta, false, intent)
}

// reserveWithoutCheck publishes a HOST reservation without verifying it fits —
// the --allow-overcommit path, which deliberately bypasses the capacity CHECK but
// must not also bypass the DRAW.
//
// Skipping the check and the reservation together is what made overcommit unsafe
// beyond its own request: the VM's memory stayed invisible to every concurrent
// admission until the workload row committed, so a NORMAL create racing it could
// be admitted against memory already spoken for — and that create never asked to
// overcommit anything. Reserving keeps the operator's decision scoped to the
// request that made it.
//
// Host figures only. Project quota is admitted separately on this path (an
// operator bypassing a physical limit is not bypassing a tenancy one), so
// charging it here would double-count it.
func (s *Server) reserveWithoutCheck(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int,
) (*reservationLease, error) {
	// --allow-overcommit bypasses the numeric headroom CHECK only. Host safety
	// — active ownership conditions, incomplete local inventory — binds the
	// overcommit path exactly as it binds everything else, and binds it BEFORE
	// the zero-delta fast path: residency is a safety decision even when the
	// numeric delta is zero.
	sub := subjectForCreate(resourceID, host, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta})
	if err := s.checkHostSafety(ctx, host, sub.Kind, sub.Name, true, true); err != nil {
		return nil, err
	}
	if cpuDelta <= 0 && memDelta <= 0 {
		return &reservationLease{}, nil
	}
	rv := corrosion.ReservationVector{
		Project:    project,
		TargetHost: host, TargetCPU: cpuDelta, TargetMemMiB: s.capacity.MemChargeFor(memDelta),
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode reservation: %v", err)
	}
	op := corrosion.OperationRecord{
		ID:              newID(),
		Method:          method,
		Principal:       callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:         project,
		ResourceKind:    corrosion.CapacityResourceKind,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		ReservationJSON: resJSON,
	}
	if err := corrosion.InsertOperation(ctx, s.db, op); err != nil {
		return nil, status.Errorf(codes.Internal, "reserve capacity: %v", err)
	}
	lease := &reservationLease{s: s, id: op.ID}
	// Same reason admitReserved stamps: an unattributed reservation is not counted
	// by capacity aggregation once the project has an authority epoch, so the lease
	// would hold nothing and the draw would stay invisible after all.
	if err := s.stampReservationAuthority(ctx, op.ID, project); err != nil {
		lease.release(ctx)
		return nil, err
	}
	return lease, nil
}

// callerPrincipal renders the calling end-user as recorded in operation
// journals. The DELEGATED admission paths (project quota, destination-owned
// host leases) carry this across the peer hop explicitly, so the journal names
// who asked rather than which daemon relayed it.
func callerPrincipal(ctx context.Context) string {
	return callerUsername(ctx) + "@" + callerRealm(ctx)
}

func (s *Server) admitReserved(
	ctx context.Context, principal, opID, method, host, project, resourceID string, subject quotaSubject, cpuDelta, memDelta int, withQuota bool, intent admissionIntent,
) (*reservationLease, error) {
	// Host safety BEFORE the zero-delta fast path AND before any reservation: an
	// active ownership condition on this host or workload, or an incomplete
	// local inventory for a newly-resident workload, refuses outright — no lease
	// to leak, nothing to unwind. A fully uncapped container reaches here with a
	// zero delta and must still be a real safety decision; only after safety
	// passes may a zero delta return the empty no-op lease.
	if err := s.checkHostSafety(ctx, host, subject.Kind, subject.Name, intent.newResidency,
		intent.newResidency || cpuDelta > 0 || memDelta > 0); err != nil {
		return nil, err
	}
	if cpuDelta <= 0 && memDelta <= 0 {
		return &reservationLease{}, nil
	}

	// Host figures carry the per-domain overhead; quota figures never do. The
	// overhead follows the qemu DOMAIN, not residency: a container becomes
	// resident without one.
	hostMemDelta := memDelta
	if intent.vmOverhead {
		hostMemDelta = s.capacity.MemChargeFor(memDelta)
	}

	// When the project-quota decision is DELEGATED, its reservation is published by
	// the authority holder, not here — recording it locally too would charge the
	// project twice for one admission.
	delegated := withQuota && s.projectAuthorityActive(ctx)

	// The vector always NAMES its project — an operation that declares one requires a
	// reservation attributable to it — but a host-only lease leaves the project
	// FIGURES at zero, so it is bound to the project without charging its quota.
	rv := corrosion.ReservationVector{
		Project:    project,
		TargetHost: host, TargetCPU: cpuDelta, TargetMemMiB: hostMemDelta,
	}
	if withQuota && !delegated {
		// Only a quota-charging admission reserves against the PROJECT. A start
		// reserves host capacity alone: its allocation is already in project usage,
		// so publishing a project reservation too would make concurrent starts
		// appear to double-consume a quota neither of them is growing.
		rv.ProjectCPU, rv.ProjectMemMiB = cpuDelta, memDelta
		rv.Workload, rv.WorkloadKind, rv.WorkloadHost = subject.Name, subject.Kind, subject.Host
		rv.WantCPU, rv.WantMemMiB = subject.Want.VCPU, subject.Want.MemMiB
		rv.WantDiskGiB, rv.WantNIC = subject.Want.DiskGiB, subject.Want.NIC
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode reservation: %v", err)
	}

	if opID == "" {
		opID = newID()
	}
	op := corrosion.OperationRecord{
		ID:              opID,
		Method:          method,
		Principal:       principal,
		Project:         project,
		ResourceKind:    corrosion.CapacityResourceKind,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		ReservationJSON: resJSON,
	}
	if err := corrosion.InsertOperation(ctx, s.db, op); err != nil {
		return nil, status.Errorf(codes.Internal, "reserve capacity: %v", err)
	}
	lease := &reservationLease{s: s, id: op.ID}
	// Attribute the reservation to the project's CURRENT authority. Capacity
	// aggregation refuses to count a reservation it cannot attribute once an epoch
	// exists, so skipping this would make the lease consume nothing — the same
	// headroom handed to the next admission while this one is still holding it.
	if err := s.stampReservationAuthority(ctx, op.ID, project); err != nil {
		lease.release(ctx)
		return nil, err
	}

	// Verify against headroom that counts ONLY earlier claimants: not our own
	// provisional reservation (comparing our request against headroom that already
	// subtracted it double-counts) and not later racers (they yield to us).
	if err := s.checkHostCapacityBefore(ctx, host, cpuDelta, hostMemDelta, op.ID); err != nil {
		lease.release(ctx)
		return nil, err
	}
	if withQuota {
		if !delegated {
			if err := s.checkProjectQuotaBefore(ctx, project, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta}, op.ID); err != nil {
				lease.release(ctx)
				return nil, err
			}
			return lease, nil
		}
		// Host capacity is settled first because it is the cheap, local half: an
		// admission that cannot fit the host never needs to bother the holder.
		holder, quotaLease, epoch, qerr := s.admitProjectQuota(ctx, method, project, resourceID, subject, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta})
		if qerr != nil {
			lease.release(ctx)
			return nil, qerr
		}
		lease.quotaHolder, lease.quotaProject, lease.quotaLease = holder, project, quotaLease
		lease.quotaEpoch = epoch
	}
	return lease, nil
}

// checkHostCapacityBefore is checkHostCapacity against headroom that counts only
// reservations from operations sorting before opID — MINUS the host's finite
// runtime-only load. The DB-derived free figure knows recorded workloads and
// reservations; it knows nothing about a bounded rogue the runtime inventory can
// see, so without the subtraction the authoritative host admits against memory
// something it has already observed is using (see runtimeExtras).
func (s *Server) checkHostCapacityBefore(ctx context.Context, host string, cpuDelta, memDelta int, opID string) error {
	freeCPU, freeMem, ok, err := corrosion.HostFreeCapacityBefore(ctx, s.db, host, s.capacity, opID)
	if err != nil {
		return status.Errorf(codes.Internal, "check host capacity: %v", err)
	}
	extraCPU, extraMem := s.runtimeExtras(ctx, host)
	if ok && (cpuDelta > freeCPU-extraCPU || memDelta > freeMem-extraMem) {
		suffix := ""
		if extraCPU > 0 || extraMem > 0 {
			suffix = fmt.Sprintf(", of which %d vCPU/%d MiB is runtime-only load the database does not record", extraCPU, extraMem)
		}
		return status.Errorf(codes.ResourceExhausted,
			"host %s has insufficient free capacity for +%d vCPU/+%d MiB (free: %d vCPU/%d MiB after earlier reservations%s)",
			host, cpuDelta, memDelta, freeCPU-extraCPU, freeMem-extraMem, suffix)
	}
	return nil
}

// checkProjectQuotaBefore is checkProjectQuota counting only reservations from
// operations sorting before opID.
func (s *Server) checkProjectQuotaBefore(ctx context.Context, project string, delta corrosion.QuotaAmount, opID string) error {
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
	r, err := corrosion.ProjectReservedBefore(ctx, s.db, project, opID)
	if err != nil {
		return status.Errorf(codes.Internal, "sum project reservations: %v", err)
	}
	return quotaVerdict(project, q, corrosion.QuotaAmount{
		VCPU: u.VCPUUsed, MemMiB: u.MemMiBUsed, DiskGiB: u.DiskGiBUsed, NIC: u.NICUsed,
	}, r, delta)
}

// quotaVerdict is the one comparison both serialized quota checks make:
// committed usage + the reservations this admission must yield to + what it is
// asking for, against the limit, in EVERY dimension the quota bounds.
//
// Sharing it is the point. Disk and NIC were previously enforced by a separate
// unserialized read that could not see an in-flight claim, so the four
// dimensions were decided under two different rules and only two of them were
// race-free. A zero limit is unbounded, exactly as CheckProjectQuota reads it.
func quotaVerdict(project string, q *corrosion.ProjectQuotaRecord, used, reserved, delta corrosion.QuotaAmount) error {
	for _, d := range []struct {
		name                    string
		limit, used, res, delta int
	}{
		{"vCPU", q.VCPULimit, used.VCPU, reserved.VCPU, delta.VCPU},
		{"memory", q.MemMiBLimit, used.MemMiB, reserved.MemMiB, delta.MemMiB},
		{"disk GiB", q.DiskGiBLimit, used.DiskGiB, reserved.DiskGiB, delta.DiskGiB},
		{"NIC", q.NICLimit, used.NIC, reserved.NIC, delta.NIC},
	} {
		if d.limit > 0 && d.used+d.res+d.delta > d.limit {
			return status.Errorf(codes.ResourceExhausted,
				"project %q %s quota exceeded (used %d + reserved %d + new %d > limit %d)",
				project, d.name, d.used, d.res, d.delta, d.limit)
		}
	}
	return nil
}

// admitQuotaWithReservation admits a grow against PROJECT QUOTA ONLY — no host
// figures. Three callers need exactly this shape:
//
//   - container creates: host capacity charges memory only (cpu_limit is cgroup
//     shares, not a vCPU reservation), but quota charges BOTH — SumProjectUsage
//     counts a container's cpu_limit against the project vCPU budget, so admission
//     must too or the limit is unenforceable;
//   - --allow-overcommit: the operator is bypassing a PHYSICAL judgment, not a
//     tenancy limit, so quota still goes through serialized admission — the
//     unserialized fail-fast cannot see in-flight reservations, and concurrent
//     overcommit requests all observed the same headroom;
//   - a grow of an already-STOPPED VM: its spec counts toward SumProjectUsage but
//     it contributes nothing to host usage until StartVM admits the full size.
//
// delta is what the admission ASKS FOR and want is the ABSOLUTE size the
// workload will contribute once committed (equal for a create, larger than the
// delta for a grow). Both carry all four quota dimensions: disk and NIC are
// tenancy limits with no host analogue, and reserving them here is what makes
// them race-free — an unserialized read of committed usage cannot see a
// concurrent request's claim, so two creates each fitting the remaining disk (or
// NIC) budget both passed and both committed.
//
// The returned lease carries the commit fence like any other quota grant.
func (s *Server) admitQuotaWithReservation(
	ctx context.Context, method, host, project, kind, name string, delta, want corrosion.QuotaAmount, intent admissionIntent,
) (*reservationLease, error) {
	// Safety before the zero-delta fast path, same as admitReserved. The quota
	// figures never carry vmOverhead — it is a host-side cost — so only the
	// residency half of the intent is consulted here.
	if err := s.checkHostSafety(ctx, host, kind, name, intent.newResidency,
		intent.newResidency || !delta.IsZero()); err != nil {
		return nil, err
	}
	if delta.IsZero() {
		return &reservationLease{}, nil
	}
	subject := quotaSubject{Kind: kind, Host: host, Name: name, Want: want}
	tag := "vm"
	if kind == corrosion.WorkloadContainer {
		tag = "ct"
	}
	resourceID := tag + ":" + name

	if s.projectAuthorityActive(ctx) {
		lease := &reservationLease{s: s}
		holder, quotaLease, epoch, qerr := s.admitProjectQuota(ctx, method, project, resourceID, subject, delta)
		if qerr != nil {
			return nil, qerr
		}
		lease.quotaHolder, lease.quotaProject, lease.quotaLease = holder, project, quotaLease
		lease.quotaEpoch = epoch
		return lease, nil
	}

	// Pre-delegation: a local reservation carrying quota figures only, verified
	// reserve-then-verify like every other admission.
	rv := corrosion.ReservationVector{
		Project: project, ProjectCPU: delta.VCPU, ProjectMemMiB: delta.MemMiB,
		ProjectDiskGiB: delta.DiskGiB, ProjectNIC: delta.NIC,
		Workload: name, WorkloadKind: kind, WorkloadHost: host,
		WantCPU: want.VCPU, WantMemMiB: want.MemMiB,
		WantDiskGiB: want.DiskGiB, WantNIC: want.NIC,
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode reservation: %v", err)
	}
	op := corrosion.OperationRecord{
		ID:              newID(),
		Method:          method,
		Principal:       callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:         project,
		ResourceID:      resourceID,
		ResourceKind:    corrosion.CapacityResourceKind,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		ReservationJSON: resJSON,
	}
	if err := corrosion.InsertOperation(ctx, s.db, op); err != nil {
		return nil, status.Errorf(codes.Internal, "reserve project quota: %v", err)
	}
	lease := &reservationLease{s: s, id: op.ID}
	if err := s.stampReservationAuthority(ctx, op.ID, project); err != nil {
		lease.release(ctx)
		return nil, err
	}
	if err := s.checkProjectQuotaBefore(ctx, project, delta, op.ID); err != nil {
		lease.release(ctx)
		return nil, err
	}
	return lease, nil
}
