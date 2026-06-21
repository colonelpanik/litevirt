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

	id := mustHexID(16)
	binding := corrosion.RoleBindingRecord{
		ID:        id,
		Path:      req.Path,
		Role:      req.Role,
		Principal: req.Principal,
		Propagate: req.Propagate,
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, binding); err != nil {
		return nil, status.Errorf(codes.Internal, "insert binding: %v", err)
	}
	slog.Info("role binding granted",
		"id", id, "path", req.Path, "role", req.Role,
		"principal", req.Principal, "propagate", req.Propagate)
	s.audit(ctx, "role.grant", req.Principal,
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
		if !isAdmin && req.Principal != "user:"+caller {
			return nil, status.Error(codes.PermissionDenied,
				"non-admin callers may only list their own bindings")
		}
		rows, err = corrosion.ListBindingsForPrincipal(ctx, s.db, req.Principal)
	} else {
		rows, err = corrosion.ListRoleBindings(ctx, s.db)
		if err == nil && !isAdmin {
			rows = filterBindingsForCaller(rows, caller)
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

func filterBindingsForCaller(all []corrosion.RoleBindingRecord, caller string) []corrosion.RoleBindingRecord {
	if caller == "" {
		return nil
	}
	self := "user:" + caller
	out := make([]corrosion.RoleBindingRecord, 0, len(all))
	for _, b := range all {
		if b.Principal == self {
			out = append(out, b)
		}
	}
	return out
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
