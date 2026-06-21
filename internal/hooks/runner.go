// Package hooks executes lifecycle hook commands for VM events.
package hooks

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

const defaultTimeout = 30 * time.Second

// Event names passed as LV_EVENT env var.
const (
	PreStart    = "pre_start"
	PostStart   = "post_start"
	PreStop     = "pre_stop"
	PostStop    = "post_stop"
	PreMigrate  = "pre_migrate"
	PostMigrate = "post_migrate"
)

// Run executes the hook for the given event. It is a no-op if the spec is nil
// or the hook command for that event is empty. Errors are logged but not
// propagated — hooks should never block VM lifecycle operations.
func Run(ctx context.Context, event string, vm *pb.VM, spec *pb.HooksSpec) {
	if spec == nil {
		return
	}
	cmd := hookCmd(spec, event)
	if cmd == "" {
		return
	}

	env := buildEnv(event, vm)
	slog.Info("running lifecycle hook", "event", event, "vm", vm.Name, "cmd", cmd)

	tctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	c := exec.CommandContext(tctx, "/bin/sh", "-c", cmd)
	c.Env = env
	out, err := c.CombinedOutput()
	if err != nil {
		slog.Warn("lifecycle hook failed", "event", event, "vm", vm.Name, "error", err, "output", strings.TrimSpace(string(out)))
		return
	}
	if len(out) > 0 {
		slog.Info("lifecycle hook output", "event", event, "vm", vm.Name, "output", strings.TrimSpace(string(out)))
	}
}

func hookCmd(spec *pb.HooksSpec, event string) string {
	switch event {
	case PreStart:
		return spec.PreStart
	case PostStart:
		return spec.PostStart
	case PreStop:
		return spec.PreStop
	case PostStop:
		return spec.PostStop
	case PreMigrate:
		return spec.PreMigrate
	case PostMigrate:
		return spec.PostMigrate
	default:
		return ""
	}
}

func buildEnv(event string, vm *pb.VM) []string {
	env := []string{
		"LV_EVENT=" + event,
		"LV_VM_NAME=" + vm.Name,
		"LV_VM_HOST=" + vm.HostName,
		"LV_VM_STATE=" + vmStateString(vm.State),
	}
	if vm.StackName != "" {
		env = append(env, "LV_VM_STACK="+vm.StackName)
	}
	// First discovered IP across all interfaces.
	for _, iface := range vm.Interfaces {
		if iface.Ip != "" {
			env = append(env, "LV_VM_IP="+iface.Ip)
			break
		}
	}
	return env
}

func vmStateString(s pb.VMState) string {
	switch s {
	case pb.VMState_VM_RUNNING:
		return "running"
	case pb.VMState_VM_STOPPED:
		return "stopped"
	case pb.VMState_VM_STARTING:
		return "starting"
	case pb.VMState_VM_STOPPING:
		return "stopping"
	case pb.VMState_VM_MIGRATING:
		return "migrating"
	case pb.VMState_VM_ERROR:
		return "error"
	default:
		return "unknown"
	}
}
