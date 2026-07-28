package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestGetAndAbortVMOperation(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// No active operation → has_active false.
	got, err := s.GetVMOperation(adminCtx(), &pb.GetVMOperationRequest{VmName: "vm1"})
	if err != nil || got.HasActive {
		t.Fatalf("expected no active op: has_active=%v err=%v", got.GetHasActive(), err)
	}

	// Wedge an operation on the VM.
	op := corrosion.OperationRecord{ID: "wedged", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
	if _, err := s.db.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil {
		t.Fatalf("BeginVMOperation: %v", err)
	}

	got, err = s.GetVMOperation(adminCtx(), &pb.GetVMOperationRequest{VmName: "vm1"})
	if err != nil || !got.HasActive || got.OperationId != "wedged" || got.CurrentState != corrosion.OpStepPlanned {
		t.Fatalf("inspect: %+v err=%v", got, err)
	}
	if len(got.Steps) == 0 {
		t.Fatal("expected at least the planned step")
	}

	// Abort without force → rejected.
	if _, err := s.AbortVMOperation(adminCtx(), &pb.AbortVMOperationRequest{VmName: "vm1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("abort without force must be FailedPrecondition, got %v", err)
	}
	// Non-admin → denied.
	if _, err := s.AbortVMOperation(userCtx("bob", "operator"), &pb.AbortVMOperationRequest{VmName: "vm1", Force: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin abort must be denied, got %v", err)
	}
	// Abort with force → cleared.
	ab, err := s.AbortVMOperation(adminCtx(), &pb.AbortVMOperationRequest{VmName: "vm1", Force: true})
	if err != nil || !ab.Aborted || ab.PreviousOperationId != "wedged" {
		t.Fatalf("abort: %+v err=%v", ab, err)
	}
	// Barrier cleared.
	if got, _ := s.GetVMOperation(adminCtx(), &pb.GetVMOperationRequest{VmName: "vm1"}); got.HasActive {
		t.Fatal("barrier should be cleared after abort")
	}
}
