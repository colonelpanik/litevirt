package grpcapi

import (
	"context"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Whoami returns the authenticated caller's identity. It is NOT in skipAuth, so
// reaching this handler means the interceptor already validated the bearer (or
// mTLS) — a stale/expired/revoked session bearer fails earlier with
// Unauthenticated. The web UI calls this to validate the session cookie and
// redirect to /login when it's no longer good.
func (s *Server) Whoami(ctx context.Context, _ *emptypb.Empty) (*pb.WhoamiResponse, error) {
	resp := &pb.WhoamiResponse{
		Username: callerUsername(ctx),
		Role:     callerRole(ctx),
		Realm:    callerRealm(ctx),
	}
	// Best-effort: surface the session's hard-expiry so the UI can show it.
	if sid := callerSessionID(ctx); sid != "" {
		if sess, err := corrosion.GetSession(ctx, s.db, sid); err == nil && sess != nil {
			resp.ExpiresAt = sess.ExpiresAt
		}
	}
	return resp, nil
}

// ChangePassword updates a local-realm user's password. A user may change their
// own password after presenting the correct old one; changing another user's
// password requires admin (a reset — no old password needed). External-realm
// users (OIDC/LDAP, no local password hash) are rejected.
func (s *Server) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*emptypb.Empty, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	selfChange := target == caller
	if !selfChange {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	user, err := corrosion.GetUser(ctx, s.db, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup user: %v", err)
	}
	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", target)
	}
	if user.PasswordHash == "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"user %q has no local password (managed by an external realm)", target)
	}
	// Verify the old password for self-service changes. Admin resets skip it.
	if selfChange {
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)) != nil {
			s.audit(ctx, "user.password-change", target, "self", "denied: bad old password")
			return nil, status.Error(codes.PermissionDenied, "old password is incorrect")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), auth.BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash password: %v", err)
	}
	if err := corrosion.UpdateUserPassword(ctx, s.db, target, string(hash)); err != nil {
		return nil, status.Errorf(codes.Internal, "update password: %v", err)
	}
	detail := "by=" + caller
	if !selfChange {
		detail = "admin reset by=" + caller
	}
	s.audit(ctx, "user.password-change", target, detail, "ok")
	return &emptypb.Empty{}, nil
}
