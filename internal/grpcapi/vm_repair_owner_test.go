package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func TestRepairVMOwner(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()

	// A VM whose DB row wrongly says host-b, but which actually runs on host-a.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-b", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Not running locally yet → refused, owner untouched (can't claim a VM we
	// don't actually run).
	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("not-running: want FailedPrecondition, got %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.HostName != "host-b" {
		t.Fatalf("owner must be unchanged when not running locally, got %+v", vm)
	}

	// Now it's confirmed running locally → re-assert ownership to host-a.
	fake.SetState("vm1", libvirtfake.StateRunning)
	resp, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"})
	if err != nil {
		t.Fatalf("RepairVMOwner: %v", err)
	}
	if resp.GetHost() != "host-a" || resp.GetPreviousHost() != "host-b" {
		t.Fatalf("resp = %+v, want host-a (was host-b)", resp)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.HostName != "host-a" || vm.State != "running" {
		t.Fatalf("owner must be re-stamped to host-a/running, got %+v", vm)
	}
	// Audited.
	if n := auditRows(t, s, "vm.repair-owner", "ok"); n != 1 {
		t.Fatalf("want 1 vm.repair-owner audit row, got %d", n)
	}

	// Admin only.
	if _, err := s.RepairVMOwner(viewerCtx(), &pb.RepairVMOwnerRequest{Name: "vm1", Host: "host-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer: want PermissionDenied, got %v", err)
	}
	// Unknown VM.
	if _, err := s.RepairVMOwner(adminCtx(), &pb.RepairVMOwnerRequest{Name: "ghost", Host: "host-a"}); status.Code(err) != codes.NotFound {
		t.Fatalf("ghost: want NotFound, got %v", err)
	}
}
