package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateReplicationSchedule adds a replication schedule (a backup_schedules row
// with type='replication'). The destination pool is stored in repo so the
// (vm_name, repo) primary key stays unique per (vm, target).
func (s *Server) CreateReplicationSchedule(ctx context.Context, req *pb.CreateReplicationScheduleRequest) (*pb.ReplicationSchedule, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.RequirePerm(ctx, s.scheduleRBACTarget(ctx, scope, req.VmName, req.PoolName, req.ProjectName), "backup.schedule", "operator"); err != nil {
		return nil, err
	}
	if req.TargetPool == "" || req.Cron == "" {
		return nil, status.Error(codes.InvalidArgument, "target_pool and cron are required")
	}
	if _, err := scheduler.ParseCron(req.Cron); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cron %q: %v", req.Cron, err)
	}
	switch scope {
	case "vm":
		if req.VmName == "" {
			return nil, status.Error(codes.InvalidArgument, "vm_name required for vm-scoped schedule")
		}
		vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
		if err != nil || vm == nil {
			return nil, status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
		}
		// Project isolation: don't let a schedule target another project's pool.
		// (The runner re-checks at run time too — defense in depth.)
		if err := s.admitVMPoolUse(ctx, vm, req.TargetHost, req.TargetPool); err != nil {
			return nil, err
		}
	case "pool":
		if req.PoolName == "" {
			return nil, status.Error(codes.InvalidArgument, "pool_name required for pool-scoped schedule")
		}
	case "project":
		if req.ProjectName == "" {
			return nil, status.Error(codes.InvalidArgument, "project_name required for project-scoped schedule")
		}
	case "cluster":
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown scope %q", scope)
	}

	rec := corrosion.BackupScheduleRecord{
		VMName:       corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName),
		PoolName:     req.PoolName,
		ProjectName:  req.ProjectName,
		Scope:        scope,
		Repo:         req.TargetPool, // destination pool is the row's repo key
		Cron:         req.Cron,
		Enabled:      req.Enabled,
		Type:         "replication",
		TargetPool:   req.TargetPool,
		TargetHost:   req.TargetHost,
		KeepReplicas: int(req.KeepReplicas),
		Incremental:  req.Incremental,
		AutoPromote:  req.AutoPromote,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert replication schedule: %v", err)
	}
	s.audit(ctx, "replication.schedule", req.VmName, "target="+req.TargetPool+" cron="+req.Cron, "ok")
	return replScheduleToPB(rec), nil
}

func (s *Server) ListReplicationSchedules(ctx context.Context, _ *pb.ListReplicationSchedulesRequest) (*pb.ListReplicationSchedulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	resp := &pb.ListReplicationSchedulesResponse{}
	for _, r := range rows {
		if r.Type != "replication" {
			continue
		}
		resp.Schedules = append(resp.Schedules, replScheduleToPB(r))
	}
	return resp, nil
}

func (s *Server) DeleteReplicationSchedule(ctx context.Context, req *pb.DeleteReplicationScheduleRequest) (*emptypb.Empty, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.RequirePerm(ctx, s.scheduleRBACTarget(ctx, scope, req.VmName, req.PoolName, req.ProjectName), "backup.schedule", "operator"); err != nil {
		return nil, err
	}
	if req.TargetPool == "" {
		return nil, status.Error(codes.InvalidArgument, "target_pool required")
	}
	key := corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName)
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, key, req.TargetPool); err != nil {
		return nil, status.Errorf(codes.Internal, "delete replication schedule: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func replScheduleToPB(r corrosion.BackupScheduleRecord) *pb.ReplicationSchedule {
	scope := r.Scope
	if scope == "" {
		scope = "vm"
	}
	return &pb.ReplicationSchedule{
		VmName:       r.VMName,
		Cron:         r.Cron,
		TargetPool:   r.TargetPool,
		TargetHost:   r.TargetHost,
		KeepReplicas: int32(r.KeepReplicas),
		Enabled:      r.Enabled,
		Scope:        scope,
		PoolName:     r.PoolName,
		ProjectName:  r.ProjectName,
		LastRunAt:    r.LastRunAt,
		LastRunErr:   r.LastRunErr,
		Incremental:  r.Incremental,
		AutoPromote:  r.AutoPromote,
	}
}
