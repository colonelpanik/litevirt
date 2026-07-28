package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetVMOperation returns the operation currently holding a VM's mutation barrier
// (F1 admin recovery inspect). has_active=false when the VM has no in-flight
// operation. Admin-only.
func (s *Server) GetVMOperation(ctx context.Context, req *pb.GetVMOperationRequest) (*pb.GetVMOperationResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	view, found, err := corrosion.GetVMActiveOperation(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get active operation: %v", err)
	}
	resp := &pb.GetVMOperationResponse{}
	if !found {
		return resp, nil // has_active = false
	}
	resp.HasActive = true
	resp.OperationId = view.ActiveOperationID
	resp.CurrentState = view.State
	resp.Faulted = view.Faulted
	resp.VmOwnerEpoch = view.OwnerEpoch
	resp.SpecGeneration = view.SpecGeneration
	if view.Operation != nil {
		resp.OperationKind = view.Operation.OperationKind
	} else {
		resp.HeaderMissing = true
	}
	for _, st := range view.Steps {
		resp.Steps = append(resp.Steps, &pb.OperationStepInfo{
			StepName: st.StepName, OwnerEpoch: st.OwnerEpoch, CreatedAt: st.CreatedAt,
		})
	}
	return resp, nil
}

// AbortVMOperation force-clears a wedged operation's mutation barrier so the VM
// is mutable again. Deliberate admin recovery: requires force, and clears the
// barrier only via the exact owner/generation CAS (a superseded op can't clear a
// newer one). Admin-only.
func (s *Server) AbortVMOperation(ctx context.Context, req *pb.AbortVMOperationRequest) (*pb.AbortVMOperationResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	if !req.Force {
		return nil, status.Error(codes.FailedPrecondition, "aborting an operation requires force")
	}
	view, found, err := corrosion.GetVMActiveOperation(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get active operation: %v", err)
	}
	if !found {
		return &pb.AbortVMOperationResponse{Aborted: false, Detail: "no active operation"}, nil
	}
	applied, err := s.db.AbortVMOperation(ctx, req.VmName, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "abort operation: %v", err)
	}
	if !applied {
		return &pb.AbortVMOperationResponse{
			Aborted: false, PreviousOperationId: view.ActiveOperationID,
			Detail: "operation state changed concurrently; re-inspect before retrying",
		}, nil
	}
	slog.Warn("operation force-aborted by admin", "vm", req.VmName, "op", view.ActiveOperationID,
		"epoch", view.OwnerEpoch, "generation", view.SpecGeneration)
	s.audit(ctx, "operation.abort", req.VmName,
		fmt.Sprintf("op=%s epoch=%d gen=%d", view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration), "ok")
	return &pb.AbortVMOperationResponse{Aborted: true, PreviousOperationId: view.ActiveOperationID}, nil
}
