package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

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

// reservationLease is a provisional capacity reservation held while an admission
// decides. The caller MUST release it exactly once, whatever the outcome: a leaked
// lease permanently consumes capacity no workload is using.
type reservationLease struct {
	s  *Server
	id string
	// The PROJECT-QUOTA half may be held on another node — the project's admission
	// authority holder — so it is tracked separately from the local host reservation
	// and released wherever it actually lives.
	quotaHolder  string
	quotaProject string
	quotaLease   string
}

// release marks the reservation's operation terminal, freeing the capacity.
// Idempotent, and safe on the empty lease returned for a no-op admission.
func (l *reservationLease) release(ctx context.Context) {
	if l == nil || l.s == nil {
		return
	}
	if id := l.quotaLease; id != "" {
		l.quotaLease = ""
		l.s.releaseProjectQuota(ctx, l.quotaHolder, l.quotaProject, id)
	}
	if l.id == "" {
		return
	}
	id := l.id
	l.id = ""
	if err := corrosion.AppendOperationStep(ctx, l.s.db, corrosion.OperationStepRecord{
		OperationID: id, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		// A failed release leaks the reservation until the operation ages out.
		// Surfaced rather than swallowed: it shows up later as capacity pressure
		// with no workload behind it, which is miserable to diagnose from scratch.
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
// row, no lease — so a shrink never queues behind anything.
func (s *Server) admitWithReservation(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int,
) (*reservationLease, error) {
	return s.admitReserved(ctx, method, host, project, resourceID, cpuDelta, memDelta, true)
}

// admitHostWithReservation is admitWithReservation for paths that must NOT charge
// project quota — the start paths, where the allocation is already counted in
// project usage whether the workload is running or stopped, so charging it again
// would refuse a plain stop/start of any workload over half its quota.
func (s *Server) admitHostWithReservation(
	ctx context.Context, method, host, project string, cpuDelta, memDelta int,
) (*reservationLease, error) {
	return s.admitReserved(ctx, method, host, project, "", cpuDelta, memDelta, false)
}

func (s *Server) admitReserved(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int, withQuota bool,
) (*reservationLease, error) {
	if cpuDelta <= 0 && memDelta <= 0 {
		return &reservationLease{}, nil
	}

	// When the project-quota decision is DELEGATED, its reservation is published by
	// the authority holder, not here — recording it locally too would charge the
	// project twice for one admission.
	delegated := withQuota && s.projectAuthorityActive(ctx)

	rv := corrosion.ReservationVector{
		TargetHost: host, TargetCPU: cpuDelta, TargetMemMiB: memDelta,
	}
	if withQuota && !delegated {
		// Only a quota-charging admission reserves against the PROJECT. A start
		// reserves host capacity alone: its allocation is already in project usage,
		// so publishing a project reservation too would make concurrent starts
		// appear to double-consume a quota neither of them is growing.
		rv.Project, rv.ProjectCPU, rv.ProjectMemMiB = project, cpuDelta, memDelta
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

	// Verify against headroom that counts ONLY earlier claimants: not our own
	// provisional reservation (comparing our request against headroom that already
	// subtracted it double-counts) and not later racers (they yield to us).
	if err := s.checkHostCapacityBefore(ctx, host, cpuDelta, memDelta, op.ID); err != nil {
		lease.release(ctx)
		return nil, err
	}
	if withQuota {
		if !delegated {
			if err := s.checkProjectQuotaBefore(ctx, project, cpuDelta, memDelta, op.ID); err != nil {
				lease.release(ctx)
				return nil, err
			}
			return lease, nil
		}
		// Host capacity is settled first because it is the cheap, local half: an
		// admission that cannot fit the host never needs to bother the holder.
		holder, quotaLease, qerr := s.admitProjectQuota(ctx, method, project, resourceID, cpuDelta, memDelta)
		if qerr != nil {
			lease.release(ctx)
			return nil, qerr
		}
		lease.quotaHolder, lease.quotaProject, lease.quotaLease = holder, project, quotaLease
	}
	return lease, nil
}

// checkHostCapacityBefore is checkHostCapacity against headroom that counts only
// reservations from operations sorting before opID.
func (s *Server) checkHostCapacityBefore(ctx context.Context, host string, cpuDelta, memDelta int, opID string) error {
	freeCPU, freeMem, ok, err := corrosion.HostFreeCapacityBefore(ctx, s.db, host, s.capacity, opID)
	if err != nil {
		return status.Errorf(codes.Internal, "check host capacity: %v", err)
	}
	if ok && (cpuDelta > freeCPU || memDelta > freeMem) {
		return status.Errorf(codes.ResourceExhausted,
			"host %s has insufficient free capacity for +%d vCPU/+%d MiB (free: %d vCPU/%d MiB after earlier reservations)",
			host, cpuDelta, memDelta, freeCPU, freeMem)
	}
	return nil
}

// checkProjectQuotaBefore is checkProjectQuota counting only reservations from
// operations sorting before opID.
func (s *Server) checkProjectQuotaBefore(ctx context.Context, project string, cpuDelta, memDelta int, opID string) error {
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
	_, _, rCPU, rMem, err := corrosion.ReservedBefore(ctx, s.db, "", project, opID)
	if err != nil {
		return status.Errorf(codes.Internal, "sum project reservations: %v", err)
	}
	if q.VCPULimit > 0 && u.VCPUUsed+rCPU+cpuDelta > q.VCPULimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q vCPU quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.VCPUUsed, rCPU, cpuDelta, q.VCPULimit)
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+rMem+memDelta > q.MemMiBLimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q memory quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.MemMiBUsed, rMem, memDelta, q.MemMiBLimit)
	}
	return nil
}
