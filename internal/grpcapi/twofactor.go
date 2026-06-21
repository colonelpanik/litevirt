package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListTwoFactors returns the second factors enrolled for the given user
// (or the caller if username is empty). Listing other users' factors
// requires admin.
func (s *Server) ListTwoFactors(ctx context.Context, req *pb.ListTwoFactorsRequest) (*pb.ListTwoFactorsResponse, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	rows, err := corrosion.ListUser2FA(ctx, s.db, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list 2fa: %v", err)
	}
	resp := &pb.ListTwoFactorsResponse{}
	for _, r := range rows {
		resp.Factors = append(resp.Factors, &pb.TwoFactor{
			Method:     r.Method,
			Label:      r.Label,
			EnrolledAt: r.EnrolledAt,
			LastUsedAt: r.LastUsedAt,
		})
	}
	return resp, nil
}

// EnrollTOTP generates a fresh TOTP secret + recovery codes for the
// requested user. A user can always enroll for themselves; admins can
// enroll for others (used by recovery flows).
//
// The plaintext secret and recovery codes are returned exactly once.
func (s *Server) EnrollTOTP(ctx context.Context, req *pb.EnrollTOTPRequest) (*pb.EnrollTOTPResponse, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	user, err := corrosion.GetUser(ctx, s.db, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup user: %v", err)
	}
	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", target)
	}

	res, err := auth.EnrollTOTP(ctx, s.db, target, req.Label)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "enroll totp: %v", err)
	}
	slog.Info("totp enrolled", "username", target, "label", req.Label, "by", caller)
	s.audit(ctx, "2fa.enroll", target, "method=totp label="+req.Label, "ok")
	return &pb.EnrollTOTPResponse{
		OtpauthUrl:    res.OtpAuthURL,
		SecretBase32:  res.SecretBase32,
		RecoveryCodes: res.RecoveryCodes,
	}, nil
}

// DisableTwoFactor un-enrolls a single 2FA method+label tuple. A user can
// disable their own factors; admins can disable any user's. When the last
// factor is removed, login proceeds without a second-factor challenge —
// callers should guard against accidentally deleting the only factor.
func (s *Server) DisableTwoFactor(ctx context.Context, req *pb.DisableTwoFactorRequest) (*emptypb.Empty, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	if req.Method == "" {
		return nil, status.Error(codes.InvalidArgument, "method required")
	}
	if err := corrosion.DeleteUser2FA(ctx, s.db, target, req.Method, req.Label); err != nil {
		return nil, status.Errorf(codes.Internal, "delete 2fa: %v", err)
	}
	slog.Info("2fa disabled", "username", target, "method", req.Method, "label", req.Label, "by", caller)
	s.audit(ctx, "2fa.disable", target, "method="+req.Method+" label="+req.Label, "ok")
	return &emptypb.Empty{}, nil
}
