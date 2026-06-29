package grpcapi

// Project isolation model (v37).
//
// The isolation guarantee is enforced at ATTACH TIME, not in the dataplane: a
// workload may bind a NIC / place a disk only on a network/pool that is GLOBAL
// (empty project — the deliberate admin escape hatch) or OWNED by its own project.
// This is the privilege boundary — admitNetworkAttach / admitPoolAttach gate every
// create and day-2 path (move, replicate, import, schedule, runner), and a
// named-project workload may not use a raw/unmanaged bridge at all.
//
// There is intentionally NO dataplane cross-project L2 firewall deny. Admission
// already makes its firing condition unreachable: two DIFFERENT named projects can
// never share a non-global L2 (neither can attach to the other's owned network,
// and a named project can't use a raw bridge), and a GLOBAL network is shared by
// design (two tenants placed there CAN talk unless an SG/default-deny says
// otherwise — the operator's choice, not an isolation failure). A per-NIC
// cross-project nftables synthesis would be redundant defense-in-depth for an
// admission bypass; it's a deliberate non-goal here, a clean follow-up if wanted.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// admitNetworkAttach is the attach-time enforcement of project network isolation:
// a workload in wlProject may attach to a network that is GLOBAL (empty project)
// or OWNED by its own project, never another project's. Fail closed: a lookup
// error denies.
//
// A name with NO managed network record is a raw/unmanaged bridge — outside
// isolation entirely (no project, SGs, IPAM, or firewall bindings). A NAMED-project
// workload may NOT use one (hard tenant isolation requires a managed network); the
// default project / root keeps the legacy raw-bridge escape hatch.
func (s *Server) admitNetworkAttach(ctx context.Context, wlProject, networkName string) error {
	if networkName == "" {
		return nil
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil {
		return status.Errorf(codes.Internal, "network admission lookup %q: %v", networkName, err)
	}
	if nr == nil {
		return s.admitRawBridge(ctx, networkName)
	}
	if !tenancy.AdmitAttach(wlProject, nr.Project) {
		return status.Errorf(codes.PermissionDenied,
			"network %q is owned by project %q; a workload in project %q may not attach",
			networkName, nr.Project, tenancy.NormalizeProject(wlProject))
	}
	return nil
}

// admitRawBridge gates a raw/unmanaged bridge attachment (a name with no managed
// network row). A raw bridge is OUTSIDE isolation (no project / SG / IPAM / firewall
// bindings) and a name can collide with another project's RENDERED bridge, so it's
// the ADMIN escape hatch — gated on the CALLER's cluster-root network authority,
// NOT on the workload's project (_default is a tenant, not root, so a _default
// workload could otherwise reach an owned network's bridge by raw name). A
// cluster/root operator (or a legacy cluster-wide operator via the role fallback)
// passes; a project-scoped caller must use a managed network.
func (s *Server) admitRawBridge(ctx context.Context, ref string) error {
	if err := s.RequirePerm(ctx, "/", "network.create", "operator"); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"attaching to a raw/unmanaged bridge %q requires cluster-root network authority; use a managed network", ref)
	}
	return nil
}

// authorizeResourceRead authorizes VIEWING a project-owned-or-global resource. A
// GLOBAL (empty-project) resource is shared infrastructure, visible to any viewer;
// an OWNED one requires read access to its project path (so a project-scoped caller
// can read its own + global, never another project's). Returned by Get* and used
// as a per-row filter by List* (skip rows where it's non-nil). A legacy cluster
// viewer (no binding) passes via the role fallback → unchanged broad visibility.
func (s *Server) authorizeResourceRead(ctx context.Context, project, rbacPath, verb string) error {
	if project == "" {
		return RequireRole(ctx, "viewer")
	}
	return s.RequirePerm(ctx, rbacPath, verb, "viewer")
}

// admitVMPoolUse is the centralized day-2 storage-pool admission: a VM's project
// may place/move/copy/import onto a target pool only if that pool is global or
// owned by the VM's own project. host is where the target pool lives ("" ⇒ the
// VM's own host). Used by create, move, replicate, import, replication-schedule
// creation, and the replication runner so every path that targets a pool enforces
// the same rule. Fail closed on a lookup error.
func (s *Server) admitVMPoolUse(ctx context.Context, vm *corrosion.VMRecord, host, poolName string) error {
	if host == "" {
		host = vm.HostName
	}
	return s.admitPoolAttach(ctx, vm.Project, host, poolName)
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
