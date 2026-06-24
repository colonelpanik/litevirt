package grpcapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ShutdownHostWorkloads gracefully stops all running VMs on a host in REVERSE
// startup order (highest startup_order first; tie by name), pausing each VM's
// stop_delay_sec after it stops before moving to the next. This is the consumer
// of vms.stop_delay_sec (previously set-but-unused). Honors each VM's
// stop_timeout_sec via the existing StopVM path.
//
// This is an EXPLICIT operator action (`lv host shutdown-workloads`); it is NOT
// invoked on daemon SIGTERM / re-exec / uninstall / normal service restart —
// those keep VMs running (KillMode=process). stop_delay_sec therefore applies
// only to deliberate ordered shutdown, not routine daemon lifecycle.
func (s *Server) ShutdownHostWorkloads(req *pb.ShutdownHostWorkloadsRequest, stream pb.LiteVirt_ShutdownHostWorkloadsServer) error {
	ctx := stream.Context()
	// Host-wide workload shutdown is as destructive as drain → admin, mirroring DrainHost.
	if err := RequireRole(ctx, "admin"); err != nil {
		return err
	}
	if req.Name == "" {
		return status.Error(codes.InvalidArgument, "host name required")
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	vms, err := corrosion.ListVMs(ctx, s.db, "", req.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "list VMs: %v", err)
	}
	type job struct {
		vm    corrosion.VMRecord
		order int
		delay int
	}
	var jobs []job
	for _, vm := range vms {
		if vm.State != "running" {
			continue
		}
		order, delay := 0, 0
		if vm.Spec != "" {
			spec := &pb.VMSpec{}
			if json.Unmarshal([]byte(vm.Spec), spec) == nil {
				order, delay = int(spec.StartupOrder), int(spec.StopDelaySec)
			}
		}
		jobs = append(jobs, job{vm: vm, order: order, delay: delay})
	}
	// Reverse startup order (stop dependents before their dependencies); tie by name.
	sort.SliceStable(jobs, func(i, j int) bool {
		if jobs[i].order != jobs[j].order {
			return jobs[i].order > jobs[j].order
		}
		return jobs[i].vm.Name < jobs[j].vm.Name
	})

	s.audit(ctx, "host.shutdown-workloads", req.Name, fmt.Sprintf("%d running VMs", len(jobs)), "ok")
	slog.Info("shutdown-workloads: stopping VMs in reverse startup order", "host", req.Name, "count", len(jobs))

	for i, jb := range jobs {
		_ = stream.Send(&pb.ShutdownProgress{VmName: jb.vm.Name, Status: "stopping"})
		// StopVM forwards to the VM's owning host and honors its stop_timeout_sec.
		stop := s.StopVM
		if s.stopVMOverride != nil {
			stop = s.stopVMOverride
		}
		if _, err := stop(ctx, &pb.StopVMRequest{Name: jb.vm.Name}); err != nil {
			slog.Warn("shutdown-workloads: stop failed", "vm", jb.vm.Name, "error", err)
			_ = stream.Send(&pb.ShutdownProgress{VmName: jb.vm.Name, Status: "error", Error: err.Error()})
			continue // best-effort: keep shutting down the rest
		}
		_ = stream.Send(&pb.ShutdownProgress{VmName: jb.vm.Name, Status: "stopped"})
		// Pause this VM's stop_delay_sec before the next (not after the last).
		if jb.delay > 0 && i < len(jobs)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(jb.delay) * time.Second):
			}
		}
	}
	return nil
}
