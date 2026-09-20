package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// docs/auth.md promises: "Even if the bound user is Admin, a token scoped to
// /projects/acme cannot touch /projects/other."
//
// Scope was consulted in exactly one place — RequirePerm. RequireRole never
// looked at it, and RequireRole guards over a hundred handlers including
// CreateToken, GrantRole, PublishCRL, RemoveHost, FenceHost and DeleteUser.
//
// So the holder of a scoped token could call CreateToken with no scopes and
// receive an unscoped admin token, or skip that and fence a host directly. The
// restriction was decorative across the entire admin surface, and
// tokenscope_test.go did not catch it because it only ever exercised
// RequirePerm.
//
// A role gate has no path, so there is nothing to intersect a scope against.
// The only sound answer is to refuse: a credential that carries a restriction
// this code path cannot evaluate must not pass it.
func TestRequireRole_RefusesAScopedToken(t *testing.T) {
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})

	err := RequireRole(ctx, "admin")
	if err == nil {
		t.Fatal("a token scoped to /projects/acme satisfied a bare admin role gate; " +
			"it can mint itself an unscoped admin token via CreateToken")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// An unscoped credential is unchanged — this is the ordinary path and must not
// regress.
func TestRequireRole_UnscopedCallerUnaffected(t *testing.T) {
	if err := RequireRole(aliceCtxWithScopes(nil), "admin"); err != nil {
		t.Errorf("unscoped admin was refused: %v", err)
	}
}

// A token scoped to the ROOT carries no restriction to violate, so it keeps
// working. Without this, "/" would be the one scope that behaved worse than no
// scope at all.
func TestRequireRole_RootScopeIsNotARestriction(t *testing.T) {
	if err := RequireRole(aliceCtxWithScopes([]string{"/"}), "admin"); err != nil {
		t.Errorf("root-scoped admin was refused: %v", err)
	}
}

// Role level still decides for a scoped-out caller: a viewer must fail the gate
// for the ordinary reason too.
func TestRequireRole_StillChecksTheRoleItself(t *testing.T) {
	ctx := viewerCtx()
	if err := RequireRole(ctx, "admin"); err == nil {
		t.Error("a viewer satisfied an admin gate")
	}
}

// RequirePerm must NOT inherit the new refusal. It already checks the scope
// against the REAL path, and on a cluster with no role-bindings it falls back
// to the role check — so a scoped token acting inside its own scope has to keep
// working, or the fix would deny every scoped token everywhere.
func TestRequirePerm_ScopedTokenStillWorksInsideItsScopeOnTheFallbackPath(t *testing.T) {
	var s *Server // nil engine → fallback to the role check
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})

	if err := s.RequirePerm(ctx, "/projects/acme/vms/web", "vm.start", "operator"); err != nil {
		t.Errorf("a scoped token was refused inside its own scope: %v", err)
	}
	if err := s.RequirePerm(ctx, "/projects/other/vms/web", "vm.start", "operator"); err == nil {
		t.Error("a scoped token reached outside its scope")
	}
}

// The issue's own diagnosis: "tokenscope_test.go covers the matcher and
// RequirePerm in isolation. Nothing covers a RequireRole handler, which is why
// this holds despite the tests."
//
// So this drives a real handler. CreateToken is the sharpest one — it is the
// privilege-escalation route, because a scoped token that reaches it can mint
// an UNSCOPED admin token and drop its own restriction entirely.
func TestCreateToken_RefusesAScopedToken(t *testing.T) {
	s := testServerR2(t)
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})

	_, err := s.CreateToken(ctx, &pb.CreateTokenRequest{Username: "alice"})
	if err == nil {
		t.Fatal("a token scoped to /projects/acme minted a new token; it can issue " +
			"itself an unscoped admin credential and escape its own scope")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// Same shape, a different verb, to show this is the whole RequireRole surface
// and not one patched handler: FenceHost powers off a machine.
func TestFenceHost_RefusesAScopedToken(t *testing.T) {
	s := testServerR2(t)
	ctx := aliceCtxWithScopes([]string{"/projects/acme"})

	_, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "some-host"})
	if err == nil {
		t.Fatal("a scoped token fenced a host")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}
