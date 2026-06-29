package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// admitNetworkAttach is the attach-time enforcement of project network isolation:
// a workload in wlProject may attach to a network that is GLOBAL (empty project)
// or OWNED by its own project, never another project's. A name with no managed
// network record (a raw bridge that maps to nothing) is unowned, so allowed — it's
// the deliberate legacy/global escape hatch. Fail closed: a lookup error denies.
func (s *Server) admitNetworkAttach(ctx context.Context, wlProject, networkName string) error {
	if networkName == "" {
		return nil
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil {
		return status.Errorf(codes.Internal, "network admission lookup %q: %v", networkName, err)
	}
	if nr == nil {
		return nil // no managed record ⇒ unowned ⇒ not project-isolated
	}
	if !tenancy.AdmitAttach(wlProject, nr.Project) {
		return status.Errorf(codes.PermissionDenied,
			"network %q is owned by project %q; a workload in project %q may not attach",
			networkName, nr.Project, tenancy.NormalizeProject(wlProject))
	}
	return nil
}

// admitPoolAttach is the attach-time enforcement of project storage isolation: a
// workload in wlProject may place a disk on a pool that is GLOBAL or OWNED by its
// own project, never another project's. A name that doesn't resolve to a managed
// pool on host (e.g. a stack volume) carries no pool ownership, so is allowed
// (dedicated volume-project admission is a follow-up). Fail closed on a lookup error.
func (s *Server) admitPoolAttach(ctx context.Context, wlProject, host, poolName string) error {
	if poolName == "" {
		return nil
	}
	pool, ok, err := corrosion.GetStoragePool(ctx, s.db, host, poolName)
	if err != nil {
		return status.Errorf(codes.Internal, "pool admission lookup %q: %v", poolName, err)
	}
	if !ok {
		return nil // not a managed pool on this host ⇒ no pool ownership to enforce
	}
	if !tenancy.AdmitAttach(wlProject, pool.Project) {
		return status.Errorf(codes.PermissionDenied,
			"storage pool %q is owned by project %q; a workload in project %q may not use it",
			poolName, pool.Project, tenancy.NormalizeProject(wlProject))
	}
	return nil
}
