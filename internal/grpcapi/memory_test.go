package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func memBandSpec(t *testing.T, name string) string {
	return seedSpecJSON(t, &pb.VMSpec{Name: name, Cpu: 2, MemoryMib: 4096, MinMemoryMib: 1024, MaxMemoryMib: 8192})
}

// TestSetVMMemory_PersistsActual: a live balloon within the band drives libvirt AND
// persists the new mem_actual (the old handler changed libvirt but never wrote it).
func TestSetVMMemory_PersistsActual(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "bal", "test-host", "running", memBandSpec(t, "bal"))

	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "bal", TargetMib: 2048}); err != nil {
		t.Fatalf("SetVMMemory: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "bal")
	if vm.MemActual != 2048 {
		t.Errorf("mem_actual not persisted: got %d, want 2048", vm.MemActual)
	}
}

// TestSetVMMemory_Validation covers the band + running + barrier guards.
func TestSetVMMemory_Validation(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()

	insertTestVMWithSpec(t, ctx, s.db, "run", "test-host", "running", memBandSpec(t, "run"))
	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "run", TargetMib: 99999}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("above ceiling: want InvalidArgument, got %v", err)
	}
	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "run", TargetMib: 512}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("below floor: want InvalidArgument, got %v", err)
	}

	insertTestVMWithSpec(t, ctx, s.db, "stop", "test-host", "stopped", memBandSpec(t, "stop"))
	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "stop", TargetMib: 2048}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("stopped VM: want FailedPrecondition, got %v", err)
	}

	// Barrier held by an operation → deferred.
	insertTestVMWithSpec(t, ctx, s.db, "busy", "test-host", "running", memBandSpec(t, "busy"))
	op := corrosion.OperationRecord{ID: "op-x", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "busy",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := s.db.BeginVMOperation(ctx, op, memBandSpec(t, "busy"), 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: ok=%v err=%v", ok, err)
	}
	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "busy", TargetMib: 2048}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("operation active: want FailedPrecondition, got %v", err)
	}
}
