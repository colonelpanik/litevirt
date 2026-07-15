package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// checkResourceAdmission verifies a proposed CPU/memory GROW (positive deltas, MiB)
// fits BOTH the target host's free capacity AND the project's quota, counting
// in-flight reservations from nonterminal operations — not just committed usage — so
// two concurrent grows can't both pass and over-commit (F2). Host capacity is
// serialized by the target-host owner (the caller holds the VM lock on the owning
// host); project quota is checked against committed usage + reserved deltas.
//
// It returns codes.ResourceExhausted when a dimension would be exceeded, and nil for
// a shrink/no-op (deltas ≤ 0 never need capacity). An unbounded project (no quota
// row) skips the quota check; an unknown host skips the host-capacity check.
func (s *Server) checkResourceAdmission(ctx context.Context, host, project string, cpuDelta, memMiBDelta int) error {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return nil
	}

	// Host capacity (owner-serialized). HostFreeCapacity already nets out committed
	// running-VM actuals and in-flight reservations.
	freeCPU, freeMem, ok, err := corrosion.HostFreeCapacity(ctx, s.db, host)
	if err != nil {
		return status.Errorf(codes.Internal, "check host capacity: %v", err)
	}
	if ok && (cpuDelta > freeCPU || memMiBDelta > freeMem) {
		return status.Errorf(codes.ResourceExhausted,
			"host %s has insufficient free capacity for +%d vCPU/+%d MiB (free: %d vCPU/%d MiB)",
			host, cpuDelta, memMiBDelta, freeCPU, freeMem)
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
	if q.VCPULimit > 0 && u.VCPUUsed+rCPU+cpuDelta > q.VCPULimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q vCPU quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.VCPUUsed, rCPU, cpuDelta, q.VCPULimit)
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+rMem+memMiBDelta > q.MemMiBLimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q memory quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.MemMiBUsed, rMem, memMiBDelta, q.MemMiBLimit)
	}
	return nil
}

// ensureProjectAuthority makes sure the project has a D1 admission-authority epoch,
// claiming the initial one (this node) if none exists. Best-effort establishment;
// the returned authority is the current one (for recording in an operation's reserved
// step). A concurrent claim on another node is fine — exactly one wins the guarded
// initial claim, and this node reads the winner back.
func (s *Server) ensureProjectAuthority(ctx context.Context, project string) (corrosion.ProjectAuthority, error) {
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	if ok {
		return cur, nil
	}
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, project, s.hostName); err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	cur, _, err = corrosion.CurrentProjectAuthority(ctx, s.db, project)
	return cur, err
}
