package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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

// recreateAs deletes the VM named `target` (failing on any error other than
// not-found — a delete that couldn't tear down must NOT be followed by a create that
// leaves the old runtime alive) then creates it from a clone of `desired` renamed to
// `target`. It DESTROYS the target's disks, so the rolling engine only reaches it
// under an explicit recreate-class strategy.
func (o *serverOps) recreateAs(ctx context.Context, target string, desired *pb.VMSpec) error {
	if desired == nil {
		return fmt.Errorf("recreate %q: no desired spec", target)
	}
	if _, err := o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: target}); err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("delete %s before recreate: %w", target, err)
	}
	spec := proto.Clone(desired).(*pb.VMSpec)
	spec.Name = target
	_, err := o.s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	return err
}

func (o *serverOps) RecreateVM(ctx context.Context, name string, desired *pb.VMSpec) error {
	return o.recreateAs(ctx, name, desired)
}

func (o *serverOps) CreateNextVM(ctx context.Context, name string, desired *pb.VMSpec) error {
	return o.recreateAs(ctx, name+"-next", desired)
}

func (o *serverOps) ResizeVMLive(ctx context.Context, name string, desired *pb.VMSpec) error {
	return o.s.resizeVMLive(ctx, name, desired, "")
}

func (o *serverOps) ApplyLiveMetadata(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error {
	return o.s.applyLiveMetadata(ctx, name, desired, fields)
}

func (o *serverOps) DeleteVM(ctx context.Context, name string) error {
	if _, err := o.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name}); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
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

// vmUpdateDef returns the effective update strategy for a VM: its own `update:`
// block, else the stack default (first VM with an explicit update block), else
// recreate.
func vmUpdateDef(f *compose.File, name string) compose.UpdateDef {
	if def, _ := compose.FindVMDef(f, name); def != nil && def.Update != nil {
		return *def.Update
	}
	for _, vm := range f.VMs {
		if vm.Update != nil {
			return *vm.Update
		}
	}
	return compose.UpdateDef{Strategy: "recreate"}
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
			// Recreate: delete then re-create. For containers (no in-place
			// reconfigure yet) this is the update strategy; deleteWorkload +
			// deployCreatePlanned route by workload kind.
			if delErr := s.deleteWorkload(ctx, action); delErr != nil {
				slog.Warn("deploy update delete failed", "workload", action.VMName, "error", delErr)
			}
			if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
				slog.Warn("deploy update recreate failed", "workload", action.VMName, "host", action.TargetHost, "error", vmErr)
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
			if delErr := s.deleteWorkload(ctx, action); delErr != nil {
				slog.Warn("deploy delete failed", "workload", action.VMName, "error", delErr)
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
	var creates, updates, ctUpdates, deletes []planner.VMAction
	for _, a := range resolved.VMs {
		switch a.Kind {
		case planner.OpCreate:
			creates = append(creates, a)
		case planner.OpUpdate:
			// The rolling engine is VM-only (it operates on the vms table), so
			// container updates are recreated inline below; only VM updates go
			// through it.
			if a.IsContainer {
				ctUpdates = append(ctUpdates, a)
			} else {
				updates = append(updates, a)
			}
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

	// Container updates: inline recreate (the rolling engine doesn't handle
	// containers). delete-then-create on the resolved host.
	for _, action := range ctUpdates {
		_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
		if delErr := s.deleteWorkload(ctx, action); delErr != nil {
			slog.Warn("rolling update: container delete failed", "workload", action.VMName, "error", delErr)
		}
		if vmErr := s.deployCreatePlanned(ctx, action, f); vmErr != nil {
			slog.Warn("rolling update: container recreate failed", "workload", action.VMName, "error", vmErr)
			_ = stream.Send(&pb.DeployProgress{Phase: "error", VmName: action.VMName, Error: vmErr.Error()})
			continue
		}
		_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
	}

	// Rolling updates (VMs only). Fail-fast: a rolling error returns BEFORE the
	// scale-down deletes below, so a failed update never deletes a VM the update
	// didn't intend to, and the Deploy handler skips UpsertStack on the returned
	// error — leaving the prior stack record/hash untouched.
	if len(updates) > 0 {
		strategy := useRollingUpdate(f)
		_ = stream.Send(&pb.DeployProgress{
			Phase:  "rolling-update",
			Detail: fmt.Sprintf("strategy=%s vms=%d", strategy, len(updates)),
		})

		// Skip VMs on draining/fenced hosts — drain handles those separately (#19).
		drainingHosts := map[string]bool{}
		if hosts, herr := corrosion.ListHosts(ctx, s.db); herr == nil {
			for _, h := range hosts {
				if h.State == "draining" || h.State == "fenced" {
					drainingHosts[h.Name] = true
				}
			}
		}

		actions := make([]rolling.VMAction, 0, len(updates))
		for _, a := range updates {
			if drainingHosts[a.TargetHost] {
				_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: a.VMName, Detail: "skipped — host is draining/fenced"})
				continue
			}
			actions = append(actions, rolling.VMAction{
				Name:     a.VMName,
				Strategy: vmUpdateDef(f, a.VMName),
				Plan:     a.Plan,
				Desired:  a.Spec,
			})
		}

		if len(actions) > 0 {
			ops := &serverOps{s: s}
			rerr := rolling.Run(ctx, ops, f.Name, actions, func(p rolling.Progress) {
				errStr := ""
				if p.Err != nil {
					errStr = p.Err.Error()
				}
				_ = stream.Send(&pb.DeployProgress{Phase: p.Phase, VmName: p.VMName, Detail: p.Detail, Error: errStr})
			})
			if rerr != nil {
				s.audit(ctx, "stack.rolling_update", f.Name, rerr.Error(), "error")
				return rerr
			}
		}
	}

	// Execute deletes (scale-down).
	for _, action := range deletes {
		_ = stream.Send(&pb.DeployProgress{Phase: "applying", VmName: action.VMName, Detail: action.Detail})
		if delErr := s.deleteWorkload(ctx, action); delErr != nil {
			slog.Warn("deploy delete failed", "workload", action.VMName, "error", delErr)
		}
		_ = stream.Send(&pb.DeployProgress{Phase: "done", VmName: action.VMName, ProgressPct: 100})
	}

	return nil
}
