package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/rolling"
)

// serverOps adapts *Server to rolling.Ops so the rolling update engine
// can drive VM lifecycle without knowing about gRPC internals.
type serverOps struct {
	s *Server
}

var _ rolling.Ops = (*serverOps)(nil)

func (o *serverOps) RecreateVM(ctx context.Context, name string, f *compose.File) error {
	// Delete old VM (ignore if already gone).
	_, _ = o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name})

	vmDef, baseName := compose.FindVMDef(f, name)
	if vmDef == nil {
		return fmt.Errorf("VM %q not found in compose file", name)
	}
	spec, err := compose.BuildVMSpec(name, baseName, vmDef, f)
	if err != nil {
		return fmt.Errorf("build spec for %s: %w", name, err)
	}

	_, err = o.s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	return err
}

func (o *serverOps) StopVM(ctx context.Context, name string) error {
	_, err := o.s.StopVM(ctx, &pb.StopVMRequest{Name: name})
	return err
}

func (o *serverOps) StartVM(ctx context.Context, name string) error {
	_, err := o.s.StartVM(ctx, &pb.StartVMRequest{Name: name})
	return err
}

func (o *serverOps) WaitHealthy(ctx context.Context, name string, timeout time.Duration) error {
	return o.s.waitForCondition(ctx, name, fmt.Sprintf("healthy:%s", timeout))
}

func (o *serverOps) HotModifyVM(ctx context.Context, name string, cpu, memMiB int) error {
	_, err := o.s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:      name,
		Cpu:       int32(cpu),
		MemoryMib: int32(memMiB),
	})
	return err
}

func (o *serverOps) CreateNextVM(ctx context.Context, name string, f *compose.File) error {
	nextName := name + "-next"
	// Delete any stale -next VM.
	_, _ = o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: nextName})

	vmDef, baseName := compose.FindVMDef(f, name)
	if vmDef == nil {
		return fmt.Errorf("VM %q not found in compose file", name)
	}
	spec, err := compose.BuildVMSpec(nextName, baseName, vmDef, f)
	if err != nil {
		return fmt.Errorf("build spec for %s: %w", nextName, err)
	}
	_, err = o.s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	return err
}

// useRollingUpdate returns the update strategy if the compose file specifies
// a non-recreate strategy, or "" if inline recreate should be used.
func useRollingUpdate(f *compose.File) string {
	for _, vm := range f.VMs {
		if vm.Update != nil && vm.Update.Strategy != "" && vm.Update.Strategy != "recreate" {
			return vm.Update.Strategy
		}
	}
	return ""
}

// getOldComposeYAML fetches the previously stored compose YAML for rollback.
func (s *Server) getOldComposeYAML(ctx context.Context, stackName string) string {
	st, err := corrosion.GetStack(ctx, s.db, stackName)
	if err != nil || st == nil {
		return ""
	}
	return st.ComposeYAML
}

// executeInlineActions processes all VM actions sequentially using inline
// delete-then-create for updates (the original behavior).
func (s *Server) executeInlineActions(ctx context.Context, f *compose.File, resolved *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	for _, action := range resolved.VMs {
		if action.Kind == planner.OpNoChange {
			continue
		}

		if err := stream.Send(&pb.DeployProgress{
			Phase:  "applying",
			VmName: action.VMName,
			Detail: action.Detail,
		}); err != nil {
			return err
		}

		switch action.Kind {
		case planner.OpCreate:
			if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
				slog.Warn("deploy create failed", "vm", action.VMName, "host", action.TargetHost, "error", vmErr)
				if sendErr := stream.Send(&pb.DeployProgress{
					Phase:  "error",
					VmName: action.VMName,
					Error:  vmErr.Error(),
				}); sendErr != nil {
					return sendErr
				}
				continue
			}

			if action.WaitFor != "" {
				_ = stream.Send(&pb.DeployProgress{
					Phase:  "waiting",
					VmName: action.VMName,
					Detail: fmt.Sprintf("waiting for %s", action.WaitFor),
				})
				if err := s.waitForCondition(ctx, action.VMName, action.WaitFor); err != nil {
					slog.Warn("depends-on wait failed, continuing", "vm", action.VMName, "error", err)
				}
			}

		case planner.OpUpdate:
			if _, delErr := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: action.VMName}); delErr != nil {
				slog.Warn("deploy update delete failed", "vm", action.VMName, "error", delErr)
			}
			if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
				slog.Warn("deploy update recreate failed", "vm", action.VMName, "host", action.TargetHost, "error", vmErr)
				if sendErr := stream.Send(&pb.DeployProgress{
					Phase:  "error",
					VmName: action.VMName,
					Error:  vmErr.Error(),
				}); sendErr != nil {
					return sendErr
				}
				continue
			}

		case planner.OpDelete:
			if _, delErr := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: action.VMName}); delErr != nil {
				slog.Warn("deploy delete failed", "vm", action.VMName, "error", delErr)
			}
		}

		if err := stream.Send(&pb.DeployProgress{
			Phase:       "done",
			VmName:      action.VMName,
			ProgressPct: 100,
		}); err != nil {
			return err
		}
	}
	return nil
}

// executeWithRollingUpdates partitions the plan into creates, updates, and
// deletes. Creates execute first (scale-up), then updates are delegated to
// the rolling update engine, then deletes execute (scale-down).
func (s *Server) executeWithRollingUpdates(ctx context.Context, f *compose.File, resolved *planner.ResolvedPlan, stream grpc.ServerStreamingServer[pb.DeployProgress]) error {
	var creates, updates, deletes []planner.VMAction
	for _, a := range resolved.VMs {
		switch a.Kind {
		case planner.OpCreate:
			creates = append(creates, a)
		case planner.OpUpdate:
			updates = append(updates, a)
		case planner.OpDelete:
			deletes = append(deletes, a)
		}
	}

	// Execute creates (scale-up).
	for _, action := range creates {
		_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})

		if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
			slog.Warn("deploy create failed", "vm", action.VMName, "error", vmErr)
			_ = stream.Send(&pb.DeployProgress{Phase: "error", VmName: action.VMName, Error: vmErr.Error()})
			continue
		}
		if action.WaitFor != "" {
			_ = stream.Send(&pb.DeployProgress{Phase: "waiting", VmName: action.VMName, Detail: fmt.Sprintf("waiting for %s", action.WaitFor)})
			if err := s.waitForCondition(ctx, action.VMName, action.WaitFor); err != nil {
				slog.Warn("depends-on wait failed, continuing", "vm", action.VMName, "error", err)
			}
		}
		_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
	}

	// Rolling updates.
	if len(updates) > 0 {
		strategy := useRollingUpdate(f)
		_ = stream.Send(&pb.DeployProgress{
			Phase:  "rolling-update",
			Detail: fmt.Sprintf("strategy=%s vms=%d", strategy, len(updates)),
		})

		oldYAML := s.getOldComposeYAML(ctx, f.Name)
		ops := &serverOps{s: s}
		ch := rolling.Update(ctx, s.db, ops, f.Name, f, oldYAML)

		for prog := range ch {
			phase := prog.Phase
			detail := prog.Detail
			errStr := ""
			if prog.Err != nil {
				errStr = prog.Err.Error()
			}
			_ = stream.Send(&pb.DeployProgress{
				Phase:  phase,
				VmName: prog.VMName,
				Detail: detail,
				Error:  errStr,
			})
		}
	}

	// Execute deletes (scale-down).
	for _, action := range deletes {
		_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
		if _, delErr := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: action.VMName}); delErr != nil {
			slog.Warn("deploy delete failed", "vm", action.VMName, "error", delErr)
		}
		_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
	}

	return nil
}
