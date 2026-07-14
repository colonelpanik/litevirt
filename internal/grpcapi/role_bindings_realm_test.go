package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// realmServer wires the engine, sets the auth.rbac_realm flag, and injects a
// gate whose RBACRealmV1 latch is `latched`.
func realmServer(t *testing.T, on, latched bool) *Server {
	t.Helper()
	s := serverWithEngine(t)
	s.SetRBACRealm(on)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.RBACRealmV1: latched}})
	return s
}

func TestClassifyUserPrincipal(t *testing.T) {
	cases := []struct {
		body      string
		name      string
		realm     string
		qualified bool
	}{
		{"alice@local", "alice", "local", true},
		{"alice@oidc:corp", "alice", "oidc:corp", true},
		{"alice@ldap:dc1", "alice", "ldap:dc1", true},
		{"alice@example.com", "alice@example.com", "", false}, // email, not a realm
		{"alice", "alice", "", false},                         // bare
		{"alice@", "alice@", "", false},                       // trailing @ is not a realm
	}
	for _, c := range cases {
		name, realm, qualified := classifyUserPrincipal(c.body)
		if name != c.name || realm != c.realm || qualified != c.qualified {
			t.Errorf("classifyUserPrincipal(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.body, name, realm, qualified, c.name, c.realm, c.qualified)
		}
	}
}

// TestGrantRole_RBACRealmOff_AcceptsBare: with the flag off (default), a bare
// grant is stored verbatim — legacy behavior, mixed-version-safe.
func TestGrantRole_RBACRealmOff_AcceptsBare(t *testing.T) {
	s := realmServer(t, false, false)
	resp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:bob",
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if resp.Binding.Principal != "user:bob" {
		t.Fatalf("principal = %q, want user:bob (stored verbatim)", resp.Binding.Principal)
	}
}

// TestGrantRole_RBACRealmOn_NotLatched_RejectsBare: flag on but not latched
// fleet-wide → a bare grant is refused (require an explicit realm) so this node
// never mints a new inert bare binding while peers might still make them.
func TestGrantRole_RBACRealmOn_NotLatched_RejectsBare(t *testing.T) {
	s := realmServer(t, true, false)
	_, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:bob",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for bare grant pre-latch, got %v", err)
	}
}

// TestGrantRole_RBACRealmOn_AcceptsQualified: a realm-qualified grant passes
// through regardless of latch state.
func TestGrantRole_RBACRealmOn_AcceptsQualified(t *testing.T) {
	s := realmServer(t, true, false)
	resp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:bob@local",
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if resp.Binding.Principal != "user:bob@local" {
		t.Fatalf("principal = %q, want user:bob@local", resp.Binding.Principal)
	}
}

// TestGrantRole_RBACRealmOn_Latched_ResolvesBare: once latched, a bare grant for
// a known local user is resolved to canonical form and stored.
func TestGrantRole_RBACRealmOn_Latched_ResolvesBare(t *testing.T) {
	s := realmServer(t, true, true)
	if err := corrosion.InsertUser(context.Background(), s.db, "bob", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	resp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:bob",
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if resp.Binding.Principal != "user:bob@local" {
		t.Fatalf("principal = %q, want canonicalized user:bob@local", resp.Binding.Principal)
	}
}

// TestGrantRole_RBACRealmOn_Latched_RejectsUnresolvable: a bare grant that names
// no known local user cannot be resolved and is refused.
func TestGrantRole_RBACRealmOn_Latched_RejectsUnresolvable(t *testing.T) {
	s := realmServer(t, true, true)
	_, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:ghost",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for unresolvable bare grant, got %v", err)
	}
}

// TestNormalizeRoleBindings rewrites resolvable bare bindings to canonical form,
// leaves unresolvable ones in place, and is idempotent on re-run.
func TestNormalizeRoleBindings(t *testing.T) {
	s := realmServer(t, true, true)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "carol", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	// Legacy bare bindings inserted directly (GrantRole would now reject a bare grant).
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "bare-carol", Path: "/projects/x", Role: "Operator", Principal: "user:carol", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding carol: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "bare-ghost", Path: "/", Role: "Viewer", Principal: "user:ghost", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding ghost: %v", err)
	}

	resp, err := s.NormalizeRoleBindings(adminCtx(), &pb.NormalizeRoleBindingsRequest{})
	if err != nil {
		t.Fatalf("NormalizeRoleBindings: %v", err)
	}
	if resp.Normalized != 1 || resp.Skipped != 1 {
		t.Fatalf("normalized=%d skipped=%d, want 1 and 1", resp.Normalized, resp.Skipped)
	}
	if rows, _ := corrosion.ListBindingsForPrincipal(ctx, s.db, "user:carol"); len(rows) != 0 {
		t.Fatalf("bare user:carol not tombstoned: %d rows", len(rows))
	}
	if rows, _ := corrosion.ListBindingsForPrincipal(ctx, s.db, "user:carol@local"); len(rows) != 1 {
		t.Fatalf("canonical user:carol@local missing: %d rows", len(rows))
	}
	if rows, _ := corrosion.ListBindingsForPrincipal(ctx, s.db, "user:ghost"); len(rows) != 1 {
		t.Fatalf("unresolvable bare binding should be left in place: %d rows", len(rows))
	}
	// Idempotent: re-run normalizes nothing more.
	resp2, err := s.NormalizeRoleBindings(adminCtx(), &pb.NormalizeRoleBindingsRequest{})
	if err != nil {
		t.Fatalf("NormalizeRoleBindings re-run: %v", err)
	}
	if resp2.Normalized != 0 {
		t.Fatalf("re-run normalized=%d, want 0 (idempotent)", resp2.Normalized)
	}
}

func TestNormalizeRoleBindings_RequiresLatch(t *testing.T) {
	s := realmServer(t, true, false) // flag on but capability not latched
	_, err := s.NormalizeRoleBindings(adminCtx(), &pb.NormalizeRoleBindingsRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition when not latched, got %v", err)
	}
}

func TestNormalizeRoleBindings_DryRun(t *testing.T) {
	s := realmServer(t, true, true)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "carol", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "bare-carol", Path: "/projects/x", Role: "Operator", Principal: "user:carol", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	resp, err := s.NormalizeRoleBindings(adminCtx(), &pb.NormalizeRoleBindingsRequest{DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if resp.Normalized != 1 {
		t.Fatalf("dry-run normalized=%d, want 1", resp.Normalized)
	}
	if rows, _ := corrosion.ListBindingsForPrincipal(ctx, s.db, "user:carol"); len(rows) != 1 {
		t.Fatalf("dry-run must not modify DB: bare rows=%d", len(rows))
	}
}

func TestPrincipalsForCaller_RealmAware(t *testing.T) {
	got := principalsForCaller("alice", "operator", "oidc:corp")
	want := []string{"user:alice@oidc:corp", "group:operator@oidc:corp"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("principalsForCaller realm-aware = %v, want %v", got, want)
	}
	// Empty realm defaults to local (backward compatible).
	if got := principalsForCaller("alice", "", ""); len(got) != 1 || got[0] != "user:alice@local" {
		t.Fatalf("principalsForCaller default realm = %v, want [user:alice@local]", got)
	}
}
