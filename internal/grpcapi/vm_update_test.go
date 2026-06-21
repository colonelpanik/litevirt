package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestUpdateVM_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestUpdateVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestUpdateVM_RunningRejects(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "running-vm", "test-host", "running")

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "running-vm", Cpu: 4})
	if err == nil {
		t.Fatal("expected error for running VM")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
	if s := status.Convert(err).Message(); s == "" {
		t.Error("expected error message about needing to be stopped")
	}
}

func TestUpdateVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	// UpdateVM now forwards to the remote host via peerClient.
	// In test, the peer is unreachable so we get Unavailable.
	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "remote-vm", Cpu: 4})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}
