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
	// Forward to the owner BEFORE taking the local lock.
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

	// Post-latch: route the balloon through the SAME atomic F1 path as a live resize
	// (BeginVMOperation commits the desired memory_mib + claims the barrier), so a
	// balloon and a coordinated resize can't race and the change is crash-recoverable.
	// The coordinator owns the VM lock, re-reads under it, and enforces the band.
	if s.operationProtocolActive(ctx) {
		if err := s.resizeVMLive(ctx, req.Name, &pb.VMSpec{MemoryMib: req.TargetMib}, req.IdempotencyKey); err != nil {
			return nil, err
		}
		return s.vmToProto(ctx, req.Name)
	}

	// Pre-latch: the direct balloon + mem_actual path.
	unlock := s.lockVM(req.Name)
	defer unlock()
	vm, err = corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", req.Name, vm.HostName)
	}
	// Mutation barrier: don't balloon a VM while a resource operation holds it.
	if vm.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot set memory for %q: an operation is in progress", req.Name)
	}
	// Ballooning drives the LIVE virtio balloon — it only applies to a running VM.
	// Change a stopped VM's boot allocation with `lv update --memory` instead.
	if vm.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q must be running to balloon memory (current: %s); use `lv update --memory` to set boot memory on a stopped VM", req.Name, vm.State)
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

	if err := s.virt.SetMemory(vm.Name, int(req.TargetMib)); err != nil {
		return nil, status.Errorf(codes.Internal, "set memory: %v", err)
	}

	// Persist the new live balloon target as the observed actual so accounting and
	// placement (which sum mem_actual) reflect reclaimed/added guest RAM. The balloon
	// has already been driven; a lost write is healed on the next observe, so log
	// loudly rather than fail an applied resize.
	if _, err := corrosion.UpdateObservedActuals(ctx, s.db, vm.Name, vm.CPUActual, int(req.TargetMib), vm.OwnerEpoch, -1); err != nil {
		slog.Error("SetVMMemory: persisting mem_actual failed — accounting will lag until reconciled", "vm", vm.Name, "error", err)
	}

	slog.Info("vm memory ballooned", "vm", vm.Name, "target_mib", req.TargetMib)
	s.recordVMEvent(ctx, vm.Name, "vm.memory", "ok", fmt.Sprintf("balloon target %d MiB", req.TargetMib))
	return s.vmToProto(ctx, vm.Name)
}
