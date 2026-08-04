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

// --allow-overcommit bypasses the host capacity check, an operator-level
// judgment call. A principal whose binding grants only the lifecycle verbs
// (VMOperator: vm.start, vm.stop, …) must NOT be able to invoke the bypass —
// it needs vm.overcommit, which only wildcard grants (Operator's vm.*) carry.
func TestStartVM_AllowOvercommitRequiresOvercommitVerb(t *testing.T) {
	s := serverWithEngine(t)
	s.virt = libvirtfake.New()
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", HostName: "test-host", State: "stopped",
		Project: "/acme", CPUActual: 1, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "VMOperator",
		Principal: "user:bob@local", Propagate: true,
	}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	bob := userCtx("bob", "viewer")

	// bob holds vm.start, so the flag-free path passes authz (whatever happens
	// later, it must not be PermissionDenied).
	if _, err := s.StartVM(bob, &pb.StartVMRequest{Name: "web-1"}); status.Code(err) == codes.PermissionDenied {
		t.Fatalf("plain StartVM should pass authz for a VMOperator, got %v", err)
	}

	// With --allow-overcommit the same principal must be refused: lifecycle
	// verbs do not include the capacity-bypass judgment call.
	_, err := s.StartVM(bob, &pb.StartVMRequest{Name: "web-1", AllowOvercommit: true})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("StartVM --allow-overcommit by a VMOperator: want PermissionDenied, got %v", err)
	}

	// An Operator (vm.*) keeps the bypass.
	if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Operator",
		Principal: "user:carol@local", Propagate: true,
	}); err != nil {
		t.Fatalf("GrantRole carol: %v", err)
	}
	carol := userCtx("carol", "viewer")
	if _, err := s.StartVM(carol, &pb.StartVMRequest{Name: "web-1", AllowOvercommit: true}); status.Code(err) == codes.PermissionDenied {
		t.Fatalf("StartVM --allow-overcommit by an Operator (vm.*) must pass authz, got %v", err)
	}
}
