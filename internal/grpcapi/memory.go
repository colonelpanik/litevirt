package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SetVMMemory adjusts the running balloon target (#4). The target must lie
// within the VM's [min, max] memory band; for a running VM the virtio balloon
// is driven live (and the value is persisted to libvirt config). Memory
// ballooning lets the host overcommit and reclaim guest RAM at runtime.
func (s *Server) SetVMMemory(ctx context.Context, req *pb.SetVMMemoryRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		return nil, err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.SetVMMemory(ctx, req)
	}

	if req.TargetMib <= 0 {
		return nil, status.Error(codes.InvalidArgument, "target_mib must be positive")
	}

	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		return nil, status.Errorf(codes.Internal, "parse VM spec: %v", err)
	}
	ceiling := spec.MaxMemoryMib
	if ceiling == 0 {
		ceiling = spec.MemoryMib
	}
	if req.TargetMib > ceiling {
		return nil, status.Errorf(codes.InvalidArgument,
			"target %d MiB exceeds the VM's maximum %d MiB", req.TargetMib, ceiling)
	}
	if spec.MinMemoryMib > 0 && req.TargetMib < spec.MinMemoryMib {
		return nil, status.Errorf(codes.InvalidArgument,
			"target %d MiB is below the VM's minimum %d MiB", req.TargetMib, spec.MinMemoryMib)
	}

	if err := s.virt.SetMemory(req.Name, int(req.TargetMib)); err != nil {
		return nil, status.Errorf(codes.Internal, "set memory: %v", err)
	}

	slog.Info("vm memory ballooned", "vm", req.Name, "target_mib", req.TargetMib)
	s.recordVMEvent(ctx, req.Name, "vm.memory", "ok", fmt.Sprintf("balloon target %d MiB", req.TargetMib))
	return s.vmToProto(ctx, req.Name)
}
