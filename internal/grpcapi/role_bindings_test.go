package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// userCtx mints an authenticated context for a non-admin caller —
// the RBAC tests need to verify scoping behaviour against callers
// who aren't the implicit admin used elsewhere.
func userCtx(username, role string) context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, username)
	return context.WithValue(ctx, ctxKeyRole, role)
}

// viewerCtx is sugar for a non-admin caller named "viewer".
func viewerCtx() context.Context { return userCtx("viewer", "viewer") }

func TestGrantRole_AdminCanGrant(t *testing.T) {
	s := testServer(t)
	resp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Operator", Principal: "user:alice", Propagate: true,
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if resp.Binding.Id == "" || resp.Binding.Principal != "user:alice" {
		t.Fatalf("unexpected binding: %+v", resp.Binding)
	}

	rows, err := corrosion.ListRoleBindings(context.Background(), s.db)
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(rows) != 1 || rows[0].Path != "/projects/acme" {
		t.Fatalf("DB rows = %+v, want one row at /projects/acme", rows)
	}
}

func TestGrantRole_NonAdminDenied(t *testing.T) {
	s := testServer(t)
	_, err := s.GrantRole(viewerCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Admin", Principal: "user:attacker",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestGrantRole_RejectsBadInputs(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		name string
		req  *pb.GrantRoleRequest
	}{
		{"bad path", &pb.GrantRoleRequest{Path: "no-slash", Role: "Viewer", Principal: "user:alice"}},
		{"empty role", &pb.GrantRoleRequest{Path: "/", Role: "", Principal: "user:alice"}},
		{"bad principal", &pb.GrantRoleRequest{Path: "/", Role: "Viewer", Principal: "alice"}},
		{"empty group realm", &pb.GrantRoleRequest{Path: "/", Role: "Viewer", Principal: "group:foo@"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.GrantRole(adminCtx(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("want InvalidArgument, got %v", err)
			}
		})
	}
}

func TestRevokeRole_RoundTrip(t *testing.T) {
	s := testServer(t)
	grantResp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:alice",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := s.RevokeRole(adminCtx(), &pb.RevokeRoleRequest{Id: grantResp.Binding.Id}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	rows, err := corrosion.ListRoleBindings(context.Background(), s.db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected zero active bindings after revoke, got %d", len(rows))
	}
}

func TestListRoleBindings_NonAdminScopedToSelf(t *testing.T) {
	s := testServer(t)
	// Seed two bindings: one for alice, one for bob.
	for _, p := range []string{"user:alice", "user:bob"} {
		if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
			Path: "/", Role: "Viewer", Principal: p,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// alice as non-admin only sees herself.
	resp, err := s.ListRoleBindings(userCtx("alice", "viewer"), &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(resp.Bindings) != 1 || resp.Bindings[0].Principal != "user:alice" {
		t.Fatalf("scoped list = %+v, want only alice", resp.Bindings)
	}

	// Admin sees both.
	adminResp, err := s.ListRoleBindings(adminCtx(), &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatalf("admin ListRoleBindings: %v", err)
	}
	if len(adminResp.Bindings) != 2 {
		t.Fatalf("admin list = %d, want 2", len(adminResp.Bindings))
	}
}
