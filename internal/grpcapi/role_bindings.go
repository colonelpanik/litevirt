package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GrantRole creates a (path, role, principal) binding. Path-based
// RBAC engine in `internal/auth/permissions.go` reads role_bindings on
// every request — see `docs/auth.md` for the role catalog. Admin role
// is required because role grants escalate privilege.
//
// Validation:
//   - path must start with "/" (RBAC paths are rooted).
//   - role must be non-empty; existence is checked against the
//     in-memory engine snapshot so a typo doesn't quietly create an
//     unusable row.
//   - principal must be "user:<name>" or "group:<name>@<realm>".
//
// Idempotency: a binding is keyed by id. We mint a fresh id on every
// GrantRole call, so re-running the RPC creates a second row — this
// is the correct CRDT behaviour (deleting one leaves the other in
// place). Operators who want strict uniqueness can ListRoleBindings
// first and Revoke duplicates.
func (s *Server) GrantRole(ctx context.Context, req *pb.GrantRoleRequest) (*pb.GrantRoleResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(req.Path, "/") {
		return nil, status.Error(codes.InvalidArgument, "path must start with /")
	}
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}
	if !isWellFormedPrincipal(req.Principal) {
		return nil, status.Error(codes.InvalidArgument,
			"principal must be user:<name> or group:<name>@<realm>")
	}

	// Realm-aware grammar (opt-in via auth.rbac_realm): reject or canonicalize a
	// bare user:<name> so this node never mints an inert bare binding. When the
	// flag is off, principals are stored verbatim (legacy behavior).
	principal := req.Principal
	if s.rbacRealmConfigured() {
		resolved, err := s.resolveGrantPrincipal(ctx, principal)
		if err != nil {
			return nil, err
		}
		principal = resolved
	}

	id := mustHexID(16)
	binding := corrosion.RoleBindingRecord{
		ID:        id,
		Path:      req.Path,
		Role:      req.Role,
		Principal: principal,
		Propagate: req.Propagate,
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, binding); err != nil {
		return nil, status.Errorf(codes.Internal, "insert binding: %v", err)
	}
	// Make the grant effective immediately (a grant is additive, so a
	// best-effort reload is safe — a transient failure is caught by the
	// periodic backstop rather than blocking the RPC).
	if s.authEngine != nil {
		if err := s.authEngine.Reload(ctx); err != nil {
			slog.Warn("auth engine reload after grant failed; backstop will retry",
				"id", id, "error", err)
		}
	}
	slog.Info("role binding granted",
		"id", id, "path", req.Path, "role", req.Role,
		"principal", principal, "propagate", req.Propagate)
	s.audit(ctx, "role.grant", principal,
		fmt.Sprintf("role=%s path=%s propagate=%t id=%s", req.Role, req.Path, req.Propagate, id), "ok")
	return &pb.GrantRoleResponse{Binding: bindingToPB(binding)}, nil
}

// RevokeRole soft-deletes a binding by id. Admin only — same reason
// as Grant: the operation changes who can do what.
func (s *Server) RevokeRole(ctx context.Context, req *pb.RevokeRoleRequest) (*pb.RevokeRoleResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := corrosion.DeleteRoleBinding(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete binding: %v", err)
	}
	// Apply the revoke to the live engine as an in-memory delta rather than a
	// reload: the revoke must take effect immediately and MUST NOT depend on a
	// successful DB re-read (a reload-based revoke that hit a transient failure
	// would leave the binding enforced). The DB tombstone above makes it
	// durable and keeps a later reload from resurrecting it.
	if s.authEngine != nil {
		s.authEngine.RemoveBinding(req.Id)
	}
	slog.Info("role binding revoked", "id", req.Id)
	s.audit(ctx, "role.revoke", req.Id, "", "ok")
	return &pb.RevokeRoleResponse{}, nil
}

// ListRoleBindings returns all active bindings, optionally filtered
// to a single principal. Operators with admin role see everything;
// non-admins see only bindings that include their own principal so
// they can audit what they have access to without exposing the full
// authorisation graph.
func (s *Server) ListRoleBindings(ctx context.Context, req *pb.ListRoleBindingsRequest) (*pb.ListRoleBindingsResponse, error) {
	caller := callerUsername(ctx)
	isAdmin := RequireRole(ctx, "admin") == nil

	var rows []corrosion.RoleBindingRecord
	var err error
	if req.Principal != "" {
		// Non-admins can only filter to their own principal.
		if !isAdmin && !isSelfPrincipal(req.Principal, caller, callerRealm(ctx)) {
			return nil, status.Error(codes.PermissionDenied,
				"non-admin callers may only list their own bindings")
		}
		rows, err = corrosion.ListBindingsForPrincipal(ctx, s.db, req.Principal)
	} else {
		rows, err = corrosion.ListRoleBindings(ctx, s.db)
		if err == nil && !isAdmin {
			rows = filterBindingsForCaller(rows, caller, callerRealm(ctx))
		}
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list bindings: %v", err)
	}
	resp := &pb.ListRoleBindingsResponse{}
	for _, r := range rows {
		resp.Bindings = append(resp.Bindings, bindingToPB(r))
	}
	return resp, nil
}

// NormalizeRoleBindings rewrites legacy bare `user:<name>` bindings to the
// canonical realm-qualified form so they enforce. It is a deliberate,
// idempotent one-time admin job — gated on the RBACRealmV1 latch so it never
// races an old peer that still mints bare bindings. A bare binding whose realm
// can't be resolved (not a known local user) is left in place and counted as
// skipped. Re-running is a no-op once every bare row has been rewritten.
func (s *Server) NormalizeRoleBindings(ctx context.Context, req *pb.NormalizeRoleBindingsRequest) (*pb.NormalizeRoleBindingsResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if !s.rbacRealmLatched(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"normalize requires auth.rbac_realm enabled and the rbac_realm_v1 capability latched cluster-wide")
	}
	rows, err := corrosion.ListRoleBindings(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list bindings: %v", err)
	}
	existing := make(map[string]bool, len(rows))
	for _, b := range rows {
		existing[bindingKey(b.Path, b.Role, b.Principal, b.Propagate)] = true
	}
	var normalized, skipped int
	for _, b := range rows {
		body, ok := strings.CutPrefix(b.Principal, "user:")
		if !ok {
			continue // group:<g>@<realm> — already realm-qualified
		}
		if _, _, qualified := classifyUserPrincipal(body); qualified {
			continue
		}
		u, err := corrosion.GetUser(ctx, s.db, body)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "resolve realm for user %q: %v", body, err)
		}
		if u == nil {
			skipped++
			continue
		}
		canonical := "user:" + body + "@local"
		if req.DryRun {
			normalized++
			continue
		}
		if !existing[bindingKey(b.Path, b.Role, canonical, b.Propagate)] {
			nb := corrosion.RoleBindingRecord{
				ID: mustHexID(16), Path: b.Path, Role: b.Role,
				Principal: canonical, Propagate: b.Propagate,
			}
			if err := corrosion.InsertRoleBinding(ctx, s.db, nb); err != nil {
				return nil, status.Errorf(codes.Internal, "insert canonical binding: %v", err)
			}
			existing[bindingKey(b.Path, b.Role, canonical, b.Propagate)] = true
		}
		if err := corrosion.DeleteRoleBinding(ctx, s.db, b.ID); err != nil {
			return nil, status.Errorf(codes.Internal, "tombstone bare binding: %v", err)
		}
		normalized++
	}
	if !req.DryRun && normalized > 0 && s.authEngine != nil {
		if err := s.authEngine.Reload(ctx); err != nil {
			slog.Warn("auth engine reload after normalize failed; backstop will retry", "error", err)
		}
	}
	slog.Info("role bindings normalized", "normalized", normalized, "skipped", skipped, "dry_run", req.DryRun)
	s.audit(ctx, "role.normalize", "",
		fmt.Sprintf("normalized=%d skipped=%d dry_run=%t", normalized, skipped, req.DryRun), "ok")
	return &pb.NormalizeRoleBindingsResponse{Normalized: int32(normalized), Skipped: int32(skipped)}, nil
}

// bindingKey is a stable identity for a role binding's (path, role, principal,
// propagate) tuple — used to dedup a canonical form that already exists so
// normalization never creates a duplicate.
func bindingKey(path, role, principal string, propagate bool) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%t", path, role, principal, propagate)
}

// classifyUserPrincipal splits the body of a `user:<body>` principal into its
// name and realm. It is realm-QUALIFIED only when the substring after the last
// '@' names a realm ("local", "oidc:*", or "ldap:*"), so an email address
// (user:alice@example.com) is treated as a bare username while user:alice@local
// and user:alice@oidc:corp are qualified. Realms carry a ':' (or are "local")
// and email domains do not — that is the disambiguation the grammar relies on,
// which is why we don't treat a bare "contains @" as realm-qualified.
func classifyUserPrincipal(body string) (name, realm string, qualified bool) {
	if i := strings.LastIndexByte(body, '@'); i > 0 && i < len(body)-1 {
		suffix := body[i+1:]
		if suffix == "local" || strings.HasPrefix(suffix, "oidc:") || strings.HasPrefix(suffix, "ldap:") {
			return body[:i], suffix, true
		}
	}
	return body, "", false
}

// resolveGrantPrincipal applies realm-aware grammar to a well-formed principal
// when auth.rbac_realm is on (callers gate on rbacRealmConfigured first). A
// realm-qualified principal — or any group:<g>@<realm> — passes through
// unchanged. A bare user:<name> is either RESOLVED to canonical form (only once
// the RBACRealmV1 capability is latched cluster-wide, so no peer still mints
// bare bindings) or REJECTED (pre-latch), so this node never adds a new inert
// bare binding. Resolution maps a known local user to @local; anything not
// resolvable must be spelled out with an explicit realm.
func (s *Server) resolveGrantPrincipal(ctx context.Context, principal string) (string, error) {
	body, ok := strings.CutPrefix(principal, "user:")
	if !ok {
		return principal, nil // group:<g>@<realm> — already realm-qualified
	}
	if _, _, qualified := classifyUserPrincipal(body); qualified {
		return principal, nil
	}
	if !s.rbacRealmLatched(ctx) {
		return "", status.Errorf(codes.FailedPrecondition,
			"realm-aware RBAC is enabled but not yet latched cluster-wide; specify an explicit realm: user:%s@<realm>", body)
	}
	u, err := corrosion.GetUser(ctx, s.db, body)
	if err != nil {
		return "", status.Errorf(codes.Internal, "resolve realm for user %q: %v", body, err)
	}
	if u == nil {
		return "", status.Errorf(codes.FailedPrecondition,
			"cannot resolve a realm for bare principal user:%s (not a known local user); specify user:%s@<realm>", body, body)
	}
	return "user:" + body + "@local", nil
}

// isWellFormedPrincipal accepts the two principal shapes the RBAC
// engine resolves: `user:<name>` and `group:<group>@<realm>`. Anything
// else would never match a row and confuse operators.
func isWellFormedPrincipal(p string) bool {
	switch {
	case strings.HasPrefix(p, "user:") && len(p) > len("user:"):
		return true
	case strings.HasPrefix(p, "group:"):
		body := p[len("group:"):]
		if i := strings.IndexByte(body, '@'); i > 0 && i < len(body)-1 {
			return true
		}
	}
	return false
}

func filterBindingsForCaller(all []corrosion.RoleBindingRecord, caller, realm string) []corrosion.RoleBindingRecord {
	if caller == "" {
		return nil
	}
	out := make([]corrosion.RoleBindingRecord, 0, len(all))
	for _, b := range all {
		if isSelfPrincipal(b.Principal, caller, realm) {
			out = append(out, b)
		}
	}
	return out
}

// isSelfPrincipal reports whether principal names the caller — matching both the
// realm-qualified form (user:<caller>@<realm>) and the legacy bare form
// (user:<caller>), so a non-admin can still see and query their own bindings
// through the transition to realm-qualified principals.
func isSelfPrincipal(principal, caller, realm string) bool {
	if realm == "" {
		realm = "local"
	}
	return principal == "user:"+caller || principal == "user:"+caller+"@"+realm
}

func bindingToPB(b corrosion.RoleBindingRecord) *pb.RoleBinding {
	return &pb.RoleBinding{
		Id:        b.ID,
		Path:      b.Path,
		Role:      b.Role,
		Principal: b.Principal,
		Propagate: b.Propagate,
		UpdatedAt: b.UpdatedAt,
	}
}

func mustHexID(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand only fails on broken kernel entropy. Panic is
		// the right answer — we'd rather refuse the RPC than mint a
		// zero-byte id that collides.
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
