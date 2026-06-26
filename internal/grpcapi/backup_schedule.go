// backup-schedule RPC handlers — thin wrappers around the
// `backup_schedules` Corrosion table. The leader-gated minute-tick
// scheduler in `internal/scheduler/snapshots.go` reads the table and
// dispatches actual backups.

package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/scheduler"
)

func (s *Server) CreateBackupSchedule(ctx context.Context, req *pb.CreateBackupScheduleRequest) (*pb.BackupSchedule, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.RequirePerm(ctx, s.scheduleRBACTarget(ctx, scope, req.VmName, req.PoolName, req.ProjectName), "backup.schedule", "operator"); err != nil {
		return nil, err
	}
	if req.Repo == "" || req.Cron == "" {
		return nil, status.Error(codes.InvalidArgument, "repo and cron are required")
	}
	if _, err := scheduler.ParseCron(req.Cron); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cron %q: %v", req.Cron, err)
	}

	// Validate the scope target. Exactly one target field is meaningful per scope.
	switch scope {
	case "vm":
		if req.VmName == "" {
			return nil, status.Error(codes.InvalidArgument, "vm_name required for vm-scoped schedule")
		}
		if vm, err := corrosion.GetVM(ctx, s.db, req.VmName); err != nil || vm == nil {
			return nil, status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
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
		// no target
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown scope %q (want vm|pool|cluster|project)", scope)
	}

	rec := corrosion.BackupScheduleRecord{
		VMName:      corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName),
		PoolName:    req.PoolName,
		ProjectName: req.ProjectName,
		Scope:       scope,
		Repo:        req.Repo,
		Cron:        req.Cron,
		KeepLast:    int(req.KeepLast),
		KeepDaily:   int(req.KeepDaily),
		KeepWeekly:  int(req.KeepWeekly),
		KeepMonthly: int(req.KeepMonthly),
		KeepYearly:  int(req.KeepYearly),
		Enabled:     req.Enabled,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert schedule: %v", err)
	}
	return scheduleToPB(rec), nil
}

// scheduleRBACTarget returns the RBAC path a schedule of the given scope is
// checked against. For the vm scope it resolves the VM's tenancy project
// from corrosion (falling back to the default-project path when the VM
// record can't be found) so per-project RBAC bindings apply correctly.
func (s *Server) scheduleRBACTarget(ctx context.Context, scope, vmName, poolName, projectName string) string {
	switch scope {
	case "pool":
		// A malformed pool name must not map onto another pool's grant; an
		// invalid one yields a sentinel that matches no normal grant.
		if err := safename.ValidatePoolName(poolName); err != nil {
			return "/storage/pools/\x00invalid"
		}
		return "/storage/pools/" + poolName
	case "project":
		return projectRBACBase(projectName)
	case "cluster":
		return "/"
	default:
		if vm, err := corrosion.GetVM(ctx, s.db, vmName); err == nil && vm != nil {
			return vmRBACPath(vm)
		}
		return vmRBACPathFor("", vmName)
	}
}

func (s *Server) ListBackupSchedules(ctx context.Context, _ *pb.ListBackupSchedulesRequest) (*pb.ListBackupSchedulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	resp := &pb.ListBackupSchedulesResponse{}
	for _, r := range rows {
		if r.Type == "replication" {
			continue // listed via ListReplicationSchedules
		}
		resp.Schedules = append(resp.Schedules, scheduleToPB(r))
	}
	return resp, nil
}

func (s *Server) DeleteBackupSchedule(ctx context.Context, req *pb.DeleteBackupScheduleRequest) (*emptypb.Empty, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.RequirePerm(ctx, s.scheduleRBACTarget(ctx, scope, req.VmName, req.PoolName, req.ProjectName), "backup.schedule", "operator"); err != nil {
		return nil, err
	}
	if req.Repo == "" {
		return nil, status.Error(codes.InvalidArgument, "repo required")
	}
	// Resolve the row identity key from the scope target. For vm scope this is
	// the VM name; for others it's the sentinel matching what create stored.
	key := corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName)
	if key == "" {
		return nil, status.Error(codes.InvalidArgument, "schedule target required")
	}
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, key, req.Repo); err != nil {
		return nil, status.Errorf(codes.Internal, "delete schedule: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func scheduleToPB(r corrosion.BackupScheduleRecord) *pb.BackupSchedule {
	scope := r.Scope
	if scope == "" {
		scope = "vm"
	}
	return &pb.BackupSchedule{
		VmName:      r.VMName,
		Repo:        r.Repo,
		Cron:        r.Cron,
		KeepLast:    int32(r.KeepLast),
		KeepDaily:   int32(r.KeepDaily),
		KeepWeekly:  int32(r.KeepWeekly),
		KeepMonthly: int32(r.KeepMonthly),
		KeepYearly:  int32(r.KeepYearly),
		Enabled:     r.Enabled,
		LastRunAt:   r.LastRunAt,
		LastRunErr:  r.LastRunErr,
		Scope:       scope,
		PoolName:    r.PoolName,
		ProjectName: r.ProjectName,
	}
}
