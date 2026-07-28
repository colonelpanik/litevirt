package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// serverWithEngine returns a testServer with the RBAC engine wired and the
// built-in roles seeded — the state a real daemon runs in, so grant/revoke
// go through the same in-memory engine that RequirePerm consults.
func serverWithEngine(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	if err := auth.SeedBuiltinRoles(context.Background(), s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	e := auth.NewEngine(s.db)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(e)
	return s
}

// TestGrantRole_EnforcedWithoutReload is the P1 reproduction (grant half): a
// grant must take effect immediately, without a daemon restart or a manual
// engine reload. bob's legacy role is only viewer, so the Operator grant is
// the only thing that can authorize vm.start — proving the engine picked up
// the new binding.
func TestGrantRole_EnforcedWithoutReload(t *testing.T) {
	s := serverWithEngine(t)
	if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Operator",
		Principal: "user:bob@local", Propagate: true,
	}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	bob := userCtx("bob", "viewer")
	if err := s.RequirePerm(bob, "/projects/acme/vms/web-1", "vm.start", "operator"); err != nil {
		t.Fatalf("grant not enforced without reload: %v", err)
	}
}

// TestRevokeRole_DeniedWithoutReload is the P1 reproduction (revoke half): a
// revoke must take effect immediately, without a restart.
func TestRevokeRole_DeniedWithoutReload(t *testing.T) {
	s := serverWithEngine(t)
	grant, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Operator",
		Principal: "user:bob@local", Propagate: true,
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	bob := userCtx("bob", "viewer")
	if err := s.RequirePerm(bob, "/projects/acme/vms/web-1", "vm.start", "operator"); err != nil {
		t.Fatalf("precondition: grant should be enforced: %v", err)
	}
	if _, err := s.RevokeRole(adminCtx(), &pb.RevokeRoleRequest{Id: grant.Binding.Id}); err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	if err := s.RequirePerm(bob, "/projects/acme/vms/web-1", "vm.start", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoke not enforced without reload: want PermissionDenied, got %v", err)
	}
}

// TestRevokeRole_RetainsOtherBinding verifies that revoking one binding leaves
// the principal's other bindings intact (recompute, don't blanket-drop).
func TestRevokeRole_RetainsOtherBinding(t *testing.T) {
	s := serverWithEngine(t)
	// Two independent grants for bob.
	g1, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Operator",
		Principal: "user:bob@local", Propagate: true,
	})
	if err != nil {
		t.Fatalf("GrantRole 1: %v", err)
	}
	if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/beta", Role: "Operator",
		Principal: "user:bob@local", Propagate: true,
	}); err != nil {
		t.Fatalf("GrantRole 2: %v", err)
	}
	bob := userCtx("bob", "viewer")
	// Revoke only the /projects/acme binding.
	if _, err := s.RevokeRole(adminCtx(), &pb.RevokeRoleRequest{Id: g1.Binding.Id}); err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	if err := s.RequirePerm(bob, "/projects/acme/vms/web-1", "vm.start", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked binding still grants: %v", err)
	}
	if err := s.RequirePerm(bob, "/projects/beta/vms/web-1", "vm.start", "operator"); err != nil {
		t.Fatalf("surviving binding was dropped: %v", err)
	}
}

// TestDeleteUser_TombstonesBindings verifies DeleteUser removes the user's
// role bindings (canonical AND bare forms) from both the DB and the live
// engine, so a deleted user can't retain access via a lingering binding.
func TestDeleteUser_TombstonesBindings(t *testing.T) {
	s := serverWithEngine(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "carol", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	// Canonical + legacy-bare bindings for the same user.
	for _, p := range []string{"user:carol@local", "user:carol"} {
		if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
			Path: "/projects/acme", Role: "Operator", Principal: p, Propagate: true,
		}); err != nil {
			t.Fatalf("GrantRole %s: %v", p, err)
		}
	}
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "carol"}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	// DB: no active bindings remain for either principal form.
	for _, p := range []string{"user:carol@local", "user:carol"} {
		rows, err := corrosion.ListBindingsForPrincipal(ctx, s.db, p)
		if err != nil {
			t.Fatalf("ListBindingsForPrincipal(%s): %v", p, err)
		}
		if len(rows) != 0 {
			t.Fatalf("DeleteUser left %d binding(s) for %s", len(rows), p)
		}
	}
	// Engine: carol is no longer authorized (immediately, no reload).
	carol := userCtx("carol", "viewer")
	if err := s.RequirePerm(carol, "/projects/acme/vms/web-1", "vm.start", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("deleted user still authorized: %v", err)
	}
}
