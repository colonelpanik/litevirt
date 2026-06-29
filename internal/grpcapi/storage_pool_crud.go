package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// CreateStoragePool registers a new storage pool. The flow:
//
//  1. Validate (non-empty name, supported driver).
//  2. If the caller targeted a different host, forward there — the
//     pool's Prepare() hook (mount NFS, log into iSCSI, …) MUST run on
//     the actual host that's going to serve disks from it.
//  3. Build the driver via storage.New() so unknown drivers fail fast
//     with a useful "supported drivers" hint.
//  4. Call Prepare(). If it fails, do NOT persist the row — we don't
//     want a half-mounted pool advertised cluster-wide.
//  5. Upsert the row via Corrosion. Replication carries it to peers.
//
// Idempotency: re-registering an existing (host,name) returns OK and
// re-runs Prepare — operators expect `lv pool create` to be safe to
// retry after a transient mount failure.
func (s *Server) CreateStoragePool(ctx context.Context, req *pb.CreateStoragePoolRequest) (*pb.CreateStoragePoolResponse, error) {
	// A pool is GLOBAL (req.Project == "" → admin-managed, RBAC-anchored at root) or
	// OWNED by a project (RBAC at /projects/<p>/...). Empty project is NOT normalized
	// to "_default" — that would make it owned, not global.
	project := req.Project
	if project != "" {
		if _, err := safename.CanonicalProjectName(project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: %v", project, err)
		}
	}
	if err := s.RequirePerm(ctx, poolRBACPathFor(project, req.Name), "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := safename.ValidatePoolName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.Driver == "" {
		return nil, status.Error(codes.InvalidArgument, "driver is required")
	}
	if !slices.Contains(storage.SupportedDrivers, req.Driver) {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown driver %q (supported: %v)", req.Driver, storage.SupportedDrivers)
	}

	host := req.Host
	if host == "" {
		host = s.hostName
	}
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "dial %q: %v", host, err)
		}
		defer conn.Close()
		req.Host = host
		return client.CreateStoragePool(ctx, req)
	}

	driver, err := storage.New(s.dataDir, storage.Config{
		Driver:  req.Driver,
		Source:  req.Source,
		Target:  req.Target,
		Options: req.Options,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build driver: %v", err)
	}
	if err := driver.Prepare(ctx); err != nil {
		// Surface the underlying error verbatim — most "could not
		// mount NFS / could not connect to monitor" diagnostics come
		// from the system itself and operators read them directly.
		return nil, status.Errorf(codes.FailedPrecondition, "prepare: %v", err)
	}

	rec := corrosion.StoragePoolRecord{
		HostName: host,
		Name:     req.Name,
		Driver:   req.Driver,
		Source:   req.Source,
		Target:   req.Target,
		Options:  req.Options,
		Project:  project, // "" = global/shared
		State:    "active",
	}
	// Populate capacity immediately for file-based pools so the UI/inspect and
	// capacity-aware placement don't show 0B until the daemon's next refresh
	// tick. The daemon keeps these current thereafter (refreshDBPoolCapacity).
	if isFileBasedDriver(req.Driver) && req.Target != "" {
		var st syscall.Statfs_t
		if err := syscall.Statfs(req.Target, &st); err == nil {
			rec.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
			rec.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
		}
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "persist: %v", err)
	}
	// Make the pool resolvable for move/replicate/compose on this host right
	// away — the daemon's periodic refresh would otherwise be the only thing
	// that loads runtime-created pools into the in-memory map.
	s.addStoragePoolRef(req.Name, StoragePoolRef{
		Driver:  req.Driver,
		Source:  req.Source,
		Target:  req.Target,
		Options: req.Options,
	})
	slog.Info("storage pool created", "host", host, "name", req.Name, "driver", req.Driver)
	return &pb.CreateStoragePoolResponse{Pool: storagePoolRecordToPB(rec)}, nil
}

// DeleteStoragePool soft-deletes a pool row. The driver is given a chance
// to tear down (unmount NFS, log out of iSCSI) but a teardown failure
// does NOT block the row delete — an operator who hit "rm" likely wants
// the pool gone from the inventory even if cleanup is incomplete, and
// can always re-mount manually. The error is logged so it's not silent.
func (s *Server) DeleteStoragePool(ctx context.Context, req *pb.DeleteStoragePoolRequest) (*pb.DeleteStoragePoolResponse, error) {
	// Operator role floor BEFORE any lookup, so a viewer is rejected without being
	// able to probe pool existence; the project-scoped check follows the fetch.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	// Authorize against the pool's OWNING project (its STORED project, never the
	// request's claim), scoped to the pool's host. storage_pools is replicated, so
	// the entry node can read the record to RBAC-check before forwarding to the
	// owning host. Fail closed on a read error.
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.Name, host)
	}
	if err := s.RequirePerm(ctx, poolRBACPathFor(rec.Project, req.Name), "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	if host != s.hostName {
		// Run the reference guard on THIS (entry) node's replicated view BEFORE
		// forwarding, so a NEW entry node enforces the check even when the pool's
		// host runs an OLD daemon that lacks it (mixed-cluster). The target
		// re-checks against its own authoritative view below — a reference
		// visible to EITHER node blocks (unless --force).
		if err := s.poolReferenceGuard(ctx, host, req.Name, req.Force); err != nil {
			return nil, err
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "dial %q: %v", host, err)
		}
		defer conn.Close()
		req.Host = host
		return client.DeleteStoragePool(ctx, req)
	}

	// Target path: re-run the guard against this host's authoritative view.
	if err := s.poolReferenceGuard(ctx, host, req.Name, req.Force); err != nil {
		return nil, err
	}

	// Driver teardown (unmount NFS / log out of iSCSI) is best-effort about ERRORS
	// — an operator who hit delete wants the pool gone from inventory even if
	// cleanup is incomplete — but its refcount PREDICATES are hard guards (never
	// tear down a mount/session another pool still uses).
	if err := s.driverTeardownIfPossible(ctx, rec); err != nil {
		slog.Warn("storage pool teardown failed (continuing with row delete)",
			"host", host, "name", req.Name, "error", err)
	}
	// Belt-and-suspenders: drop any libvirt pool object. Idempotent — runtime
	// pools usually have no libvirt handle (Create doesn't EnsureStoragePool), so
	// this is a no-op in the common case and never deletes underlying storage.
	if err := s.virt.PoolDestroyIfDefined(req.Name); err != nil {
		slog.Warn("libvirt pool undefine failed (continuing with row delete)",
			"host", host, "name", req.Name, "error", err)
	}

	if err := corrosion.MarkStoragePoolDeleted(ctx, s.db, host, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	s.removeStoragePoolRef(req.Name)
	s.audit(ctx, "storage.pool.delete", req.Name, fmt.Sprintf("force=%t", req.Force), "ok")
	slog.Info("storage pool deleted", "host", host, "name", req.Name)
	return &pb.DeleteStoragePoolResponse{}, nil
}

// GetStoragePool returns one pool's full details. Used by `lv pool inspect`.
// Read is project-scoped: a global pool is visible to any viewer, an owned one
// only to its project (or root) — previously this required root for ALL pools,
// which both over-restricted a project's own pool and under-scoped reads.
func (s *Server) GetStoragePool(ctx context.Context, req *pb.GetStoragePoolRequest) (*pb.GetStoragePoolResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.Name, host)
	}
	if err := s.authorizeResourceRead(ctx, rec.Project, poolRBACPathFor(rec.Project, rec.Name), "storage.pool.read"); err != nil {
		return nil, err
	}
	return &pb.GetStoragePoolResponse{Pool: storagePoolRecordToPB(rec)}, nil
}

// driverTeardownIfPossible builds the pool's driver and, when it implements the
// optional storage.Teardowner capability (NFS umount / iSCSI logout), invokes it
// — but ONLY after a hard refcount guard: a shared NFS export/mount or iSCSI
// session must never be torn down while another live pool row on this host still
// references the same underlying source. Drivers without a Teardown method
// (local, dir, ceph, zfs, btrfs, lvm-thin) are a no-op. The driver-side hook is
// itself idempotent and skips operator-managed mounts (NFS targetOverride).
func (s *Server) driverTeardownIfPossible(ctx context.Context, rec corrosion.StoragePoolRecord) error {
	if rec.Name == "" {
		return errors.New("missing pool name")
	}
	driver, err := storage.New(s.dataDir, storage.Config{
		Driver:  rec.Driver,
		Source:  rec.Source,
		Target:  rec.Target,
		Options: rec.Options,
	})
	if err != nil {
		// An unknown/unbuildable driver has nothing host-level to undo — the row
		// delete should still proceed.
		return fmt.Errorf("build driver for teardown: %w", err)
	}
	td := storage.AsTeardowner(driver)
	if td == nil {
		return nil // local/dir/ceph/zfs/btrfs/lvm-thin — nothing to tear down
	}
	// Refcount: don't tear down a mount/session another pool on this host still
	// uses. The shared resource is driver-specific (NFS derived mountpoint, iSCSI
	// IQN+portal), not merely the same source string.
	shared, err := corrosion.CountPoolsSharingResource(ctx, s.db, rec)
	if err != nil {
		return fmt.Errorf("count pools sharing resource: %w", err)
	}
	if shared > 0 {
		slog.Info("storage pool teardown skipped: resource shared by another pool",
			"host", rec.HostName, "name", rec.Name, "driver", rec.Driver, "source", rec.Source, "sharing", shared)
		return nil
	}
	return td.Teardown(ctx)
}

// poolReferenceGuard refuses (codes.FailedPrecondition) to delete a pool that is
// still referenced by live VM disks or ENABLED backup/replication schedules,
// unless force. Both counts are HOST-scoped (pools are host-local) and read from
// replicated state, so it runs meaningfully on BOTH the entry node (pre-forward)
// and the target host. Fail CLOSED on a count error — a DB read failure must
// never be read as "no references". Audits the refusal as "blocked".
func (s *Server) poolReferenceGuard(ctx context.Context, host, name string, force bool) error {
	disks, err := corrosion.CountDisksUsingPool(ctx, s.db, host, name)
	if err != nil {
		return status.Errorf(codes.Internal, "count disks using pool: %v", err)
	}
	scheds, err := corrosion.CountActiveSchedulesUsingPool(ctx, s.db, host, name)
	if err != nil {
		return status.Errorf(codes.Internal, "count schedules using pool: %v", err)
	}
	if (disks > 0 || scheds > 0) && !force {
		detail := fmt.Sprintf("disks=%d schedules=%d", disks, scheds)
		s.audit(ctx, "storage.pool.delete", name, detail, "blocked")
		return status.Errorf(codes.FailedPrecondition,
			"pool %q on %q is still referenced (%s); use --force to delete anyway",
			name, host, detail)
	}
	return nil
}
