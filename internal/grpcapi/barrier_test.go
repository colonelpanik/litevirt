package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestMutationBarrier_DefersRuntimeOps: while an operation holds a VM's mutation
// barrier, delete / attach / detach all defer with FailedPrecondition (even the
// delete, which --force must not bypass).
func TestMutationBarrier_DefersRuntimeOps(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "held", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "held", Cpu: 2, MemoryMib: 2048}))

	op := corrosion.OperationRecord{ID: "op-held", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "held",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := s.db.BeginVMOperation(ctx, op, seedSpecJSON(t, &pb.VMSpec{Name: "held", Cpu: 4, MemoryMib: 2048}), 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: ok=%v err=%v", ok, err)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "held"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("DeleteVM should defer on the barrier, got %v", err)
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "held", Disk: &pb.DiskSpec{Name: "d1", Size: "1G"}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("AttachDevice should defer on the barrier, got %v", err)
	}
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "held", DiskName: "d1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("DetachDevice should defer on the barrier, got %v", err)
	}
}
