package grpcapi

import (
	"context"
	"errors"
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
	// Cluster-global infra authority (configures a host mount/source); checked
	// at the root path so a project-scoped token can't reach it, with the same
	// operator floor for legacy role-based callers.
	if err := s.RequirePerm(ctx, "/", "storage.pool.write", "operator"); err != nil {
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
	if err := s.RequirePerm(ctx, "/", "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
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
		return client.DeleteStoragePool(ctx, req)
	}

	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.Name, host)
	}

	if err := s.driverTeardownIfPossible(ctx, rec); err != nil {
		slog.Warn("storage pool teardown failed (continuing with row delete)",
			"host", host, "name", req.Name, "error", err)
	}

	if err := corrosion.MarkStoragePoolDeleted(ctx, s.db, host, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	s.removeStoragePoolRef(req.Name)
	slog.Info("storage pool deleted", "host", host, "name", req.Name)
	return &pb.DeleteStoragePoolResponse{}, nil
}

// GetStoragePool returns one pool's full details. Used by `lv pool inspect`.
func (s *Server) GetStoragePool(ctx context.Context, req *pb.GetStoragePoolRequest) (*pb.GetStoragePoolResponse, error) {
	if err := s.RequirePerm(ctx, "/", "storage.pool.read", "viewer"); err != nil {
		return nil, err
	}
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
	return &pb.GetStoragePoolResponse{Pool: storagePoolRecordToPB(rec)}, nil
}

// driverTeardownIfPossible best-effort calls a driver-specific cleanup.
// Most drivers (local, dir, ceph) have nothing to undo at the host level
// because Prepare is a no-op for them. NFS/iSCSI could implement an
// Unmount/Logout hook, but those interfaces don't exist yet
// . For now this is a no-op — operators who want
// strict teardown can pair `lv pool delete` with a manual `umount`.
func (s *Server) driverTeardownIfPossible(_ context.Context, rec corrosion.StoragePoolRecord) error {
	if rec.Name == "" {
		return errors.New("missing pool name")
	}
	return nil
}
