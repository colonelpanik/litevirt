package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// requireOvercommit gates the --allow-overcommit capacity bypass. Skipping the
// host capacity check is an operator-level judgment call, not a routine
// lifecycle action: a binding that grants only lifecycle verbs (vm.start,
// vm.create, …) must not carry it. Wildcard grants (Operator's vm.*) do; in
// the legacy no-bindings model every operator keeps it, unchanged.
func (s *Server) requireOvercommit(ctx context.Context, path string) error {
	return s.RequirePerm(ctx, path, "vm.overcommit", "operator")
}

// checkHostCapacity verifies a proposed CPU/memory GROW (positive deltas, MiB)
// fits the target host's free capacity — quota-free, for start-time paths
// where the allocation is already counted in project usage (see StartVM).
func (s *Server) checkHostCapacity(ctx context.Context, host string, cpuDelta, memMiBDelta int) error {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return nil
	}
	// Host capacity (owner-serialized). HostFreeCapacity already nets out committed
	// running-VM actuals and in-flight reservations.
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
// minting the initial one if none exists. Best-effort establishment; the returned
// authority is the current one (for recording in an operation's reserved step).
//
// The initial holder is DERIVED from the project name over the cluster's hosts, not
// set to this node. Claiming for self is the obvious move and it defeats the purpose:
// every node serves its own creates, so every node would become the holder of its own
// replica, every admission would stay local, and delegation would never fire. It also
// mints conflicting rows — one epoch, two holders. Deriving instead means two nodes
// racing the claim write the SAME row, so the race stops being a conflict.
//
// With no host list to derive from, this node claims for itself: a cluster whose hosts
// cannot be read has bigger problems, and refusing to establish authority at all would
// block admission entirely.
func (s *Server) ensureProjectAuthority(ctx context.Context, project string) (corrosion.ProjectAuthority, error) {
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return corrosion.ProjectAuthority{}, err
	}
	if ok {
		return cur, nil
	}
	holder := s.derivedProjectHolder(ctx, project)
	if holder == "" {
		holder = s.hostName
	}
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, project, holder); err != nil {
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
func (s *Server) derivedProjectHolder(ctx context.Context, project string) string {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil || len(hosts) == 0 {
		return ""
	}
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	return corrosion.DeriveProjectAuthorityHolder(project, names)
}
