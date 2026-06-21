// federation RPC handlers — thin wrappers around
// internal/region. The actual cross-region migration reuses MigrateVM's
// streaming surface so existing UI code can subscribe unchanged.

package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/region"
)

func (s *Server) ListRegions(ctx context.Context, _ *pb.ListRegionsRequest) (*pb.ListRegionsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	regions, err := region.List(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list regions: %v", err)
	}
	return &pb.ListRegionsResponse{Regions: regions}, nil
}

func (s *Server) RegionStatus(ctx context.Context, req *pb.RegionStatusRequest) (*pb.RegionStatusResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	all, err := region.StatusAll(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "region status: %v", err)
	}
	resp := &pb.RegionStatusResponse{}
	for _, st := range all {
		if req.Region != "" && st.Name != req.Region {
			continue
		}
		entry := &pb.RegionStatus{
			Name:        st.Name,
			HostCount:   int32(st.HostCount),
			ActiveHosts: int32(st.ActiveHosts),
			VmCount:     int32(st.VMCount),
		}
		if !st.LastUpdated.IsZero() {
			entry.LastUpdated = st.LastUpdated.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		resp.Statuses = append(resp.Statuses, entry)
	}
	if req.Region != "" && len(resp.Statuses) == 0 {
		return nil, status.Errorf(codes.NotFound, "region %q not found", req.Region)
	}
	return resp, nil
}

// CrossRegionMigrate validates the source/target hosts are in
// different regions and orchestrates the cross-region handoff:
//
//  1. Validate regions differ + both hosts active.
//  2. If include_disks=true, replicate each disk to target_pool. The
//     target pool must be reachable from the source host (e.g. a
//     multi-region Ceph pool or a shared NFS export); truly-local
//     storage without cross-region replication is intentionally out
//     of scope — operators should use native send/recv
//     to seed the target ahead of time.
//  3. Run MigrateVM(WithStorage=false) — memory + config only,
//     because storage is now present on the target.
//
// The stream surface is MigrateProgress so existing UI/CLI consumers
// don't need to know that a replication ran first; phase=COPY frames
// surface during the replication step.
func (s *Server) CrossRegionMigrate(req *pb.CrossRegionMigrateRequest, stream grpc.ServerStreamingServer[pb.MigrateProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.TargetHost == "" {
		return status.Error(codes.InvalidArgument, "vm_name and target_host required")
	}
	if req.IncludeDisks && req.TargetPool == "" {
		return status.Error(codes.InvalidArgument,
			"target_pool is required when include_disks=true")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
		return err
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q lives on %q; call CrossRegionMigrate on that host (set LV_HOST)",
			req.VmName, vm.HostName)
	}
	if _, _, vErr := region.ValidateCrossRegion(ctx, s.db, vm.HostName, req.TargetHost); vErr != nil {
		return status.Error(codes.FailedPrecondition, vErr.Error())
	}

	if req.IncludeDisks {
		if err := s.replicateDisksForCrossRegion(ctx, req.VmName, req.TargetPool, stream); err != nil {
			return err
		}
	}

	strategy := pb.MigrateStrategy_MIGRATE_COLD
	if req.Live {
		strategy = pb.MigrateStrategy_MIGRATE_LIVE
	}
	mreq := &pb.MigrateVMRequest{
		VmName:      req.VmName,
		TargetHost:  req.TargetHost,
		Strategy:    strategy,
		WithStorage: false, // storage replicated above (or shared)
	}
	return s.MigrateVM(mreq, stream)
}

// replicateDisksForCrossRegion drives one ReplicateVolume per disk on
// the VM, forwarding progress as MigrateProgress phase=COPY frames.
// Returns once all disks land on target_pool. Reuses the existing
// convertQcow2 / native-Replicator path inside ReplicateVolume.
func (s *Server) replicateDisksForCrossRegion(
	ctx context.Context,
	vmName, targetPool string,
	stream grpc.ServerStreamingServer[pb.MigrateProgress],
) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	for _, d := range disks {
		if err := stream.Send(&pb.MigrateProgress{
			Phase:  pb.MigratePhase_MIGRATE_COPYING,
			Status: fmt.Sprintf("replicating disk %q → pool %q", d.DiskName, targetPool),
		}); err != nil {
			return err
		}
		tap := &replicateTap{outer: stream, diskName: d.DiskName}
		repReq := &pb.ReplicateVolumeRequest{
			VmName:     vmName,
			DiskName:   d.DiskName,
			TargetPool: targetPool,
		}
		if err := s.ReplicateVolume(repReq, tap); err != nil {
			return fmt.Errorf("replicate disk %q: %w", d.DiskName, err)
		}
	}
	return nil
}

// replicateTap adapts the ReplicateVolume server-stream onto the
// CrossRegionMigrate stream by translating each ReplicateVolumeProgress
// into a MigrateProgress(phase=COPY) frame. context() / setters/getters
// fall through to the outer stream so deadline + metadata propagate.
type replicateTap struct {
	grpc.ServerStream
	outer    grpc.ServerStreamingServer[pb.MigrateProgress]
	diskName string
}

func (t *replicateTap) Send(p *pb.ReplicateVolumeProgress) error {
	return t.outer.Send(&pb.MigrateProgress{
		Phase:  pb.MigratePhase_MIGRATE_COPYING,
		Status: fmt.Sprintf("disk %q: %s", t.diskName, p.Status),
	})
}

func (t *replicateTap) Context() context.Context { return t.outer.Context() }
