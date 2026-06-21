package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// scopedRequirePermSetup constructs a server whose auth engine recognises
// admin-everywhere bindings, so RequirePerm decisions hinge purely on the
// scope-paths gate (not legacy fallback or missing bindings).
func scopedRequirePermSetup(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	if err := corrosion.InsertUser(context.Background(), s.db, "alice", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(context.Background(), s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(context.Background(), s.db, corrosion.RoleBindingRecord{
		Path: "/", Role: "Admin", Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	return s
}

func aliceCtxWithScopes(scopes []string) context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	if len(scopes) > 0 {
		ctx = context.WithValue(ctx, ctxKeyScopePaths, scopes)
	}
	return ctx
}

// TestRequirePerm_UnscopedTokenAllowed — without scopes, the engine
// decision wins and admin-everywhere allows everything.
func TestRequirePerm_UnscopedTokenAllowed(t *testing.T) {
	s := scopedRequirePermSetup(t)
	if err := s.RequirePerm(aliceCtxWithScopes(nil), "/projects/acme/vms/web", "vm.start", "operator"); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

// TestRequirePerm_ScopeMatch — request inside the scope subtree is allowed.
func TestRequirePerm_ScopeMatch(t *testing.T) {
	s := scopedRequirePermSetup(t)
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})
	if err := s.RequirePerm(ctx, "/projects/acme/vms/web", "vm.start", "operator"); err != nil {
		t.Fatalf("expected allow inside scope, got %v", err)
	}
}

// TestRequirePerm_ScopeMiss — request outside the scope subtree is denied
// even though the user (admin) would otherwise be allowed.
func TestRequirePerm_ScopeMiss(t *testing.T) {
	s := scopedRequirePermSetup(t)
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})
	err := s.RequirePerm(ctx, "/projects/other/vms/db", "vm.start", "operator")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for out-of-scope path, got %v", err)
	}
}

// TestRequirePerm_RootScope — "/" is a scope wildcard.
func TestRequirePerm_RootScope(t *testing.T) {
	s := scopedRequirePermSetup(t)
	ctx := aliceCtxWithScopes([]string{"/"})
	if err := s.RequirePerm(ctx, "/anything/at/all", "vm.start", "operator"); err != nil {
		t.Fatalf("root scope should allow everything, got %v", err)
	}
}

// TestRequirePerm_ScopeBoundaryIsNotPrefixMatch — "/foo" must not match
// "/foobar" (proper prefix only on a "/" boundary).
func TestRequirePerm_ScopeBoundaryIsNotPrefixMatch(t *testing.T) {
	s := scopedRequirePermSetup(t)
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})
	err := s.RequirePerm(ctx, "/projects/acme-staging/vms/web", "vm.start", "operator")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for /projects/acme-staging vs /projects/acme scope, got %v", err)
	}
}

// TestRequirePerm_MultipleScopes — any one match is enough.
func TestRequirePerm_MultipleScopes(t *testing.T) {
	s := scopedRequirePermSetup(t)
	ctx := aliceCtxWithScopes([]string{"/projects/foo", "/projects/bar"})
	if err := s.RequirePerm(ctx, "/projects/bar/vms/x", "vm.start", "operator"); err != nil {
		t.Fatalf("expected match on second scope, got %v", err)
	}
	if err := s.RequirePerm(ctx, "/projects/baz/vms/x", "vm.start", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected deny outside both scopes, got %v", err)
	}
}

// TestPathHasPrefix_BoundaryMatching covers the unit-level matcher
// directly to lock the "/foo" vs "/foobar" boundary rule.
func TestPathHasPrefix_BoundaryMatching(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/", "/anything", true},
		{"/projects/acme", "/projects/acme", true},
		{"/projects/acme", "/projects/acme/vms/x", true},
		{"/projects/acme", "/projects/acme-staging", false},
		{"/projects/acme/", "/projects/acme/vms/x", true}, // trailing slash tolerant
		{"projects/acme", "/projects/acme/vms/x", true},   // leading slash tolerant
	}
	for _, tc := range cases {
		if got := pathHasPrefix(tc.prefix, tc.path); got != tc.want {
			t.Errorf("pathHasPrefix(%q, %q) = %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
}
