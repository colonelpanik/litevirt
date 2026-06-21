package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestLogin_With2FA_RequiresSecondFactor verifies that an enrolled user
// receives a Requires_2Fa response on first call, and a real session bearer
// only after presenting a valid TOTP code.
func TestLogin_With2FA_RequiresSecondFactor(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "operator", "hunter2")

	// Enroll TOTP for alice (admin path; caller is admin).
	enroll, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if enroll.OtpauthUrl == "" || enroll.SecretBase32 == "" {
		t.Fatal("expected provisioning URL + secret")
	}

	// First Login with no totp_code: must return Requires_2Fa with empty token.
	resp, err := s.Login(context.Background(), &pb.LoginRequest{
		Username: "alice", Password: "hunter2",
	})
	if err != nil {
		t.Fatalf("Login (stage 1): %v", err)
	}
	if !resp.Requires_2Fa {
		t.Fatal("expected Requires_2Fa=true on first stage")
	}
	if resp.Token != "" {
		t.Fatalf("expected empty token on first stage, got %q", resp.Token)
	}

	// Second Login with TOTP code: should mint a session.
	code, err := totp.GenerateCodeCustom(enroll.SecretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	resp, err = s.Login(context.Background(), &pb.LoginRequest{
		Username: "alice", Password: "hunter2", TotpCode: code,
	})
	if err != nil {
		t.Fatalf("Login (stage 2): %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected session token after 2FA")
	}
	if resp.Requires_2Fa {
		t.Error("expected Requires_2Fa=false after success")
	}
}

// TestLogin_With2FA_BadCodeRejected ensures invalid TOTP codes are
// Unauthenticated, not Internal.
func TestLogin_With2FA_BadCodeRejected(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	if _, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "alice"}); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}

	_, err := s.Login(context.Background(), &pb.LoginRequest{
		Username: "alice", Password: "hunter2", TotpCode: "000000",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// TestEnrollTOTP_NonAdmin_OwnUserOnly verifies that a non-admin can enroll
// for themselves (req.Username empty) but not for someone else.
func TestEnrollTOTP_NonAdmin_OwnUserOnly(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "x")
	seedUser(t, s, "bob", "viewer", "x")

	aliceCtx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	aliceCtx = context.WithValue(aliceCtx, ctxKeyRole, "viewer")

	// Self-enroll allowed.
	if _, err := s.EnrollTOTP(aliceCtx, &pb.EnrollTOTPRequest{}); err != nil {
		t.Fatalf("self-enroll should succeed: %v", err)
	}
	// Enrolling Bob requires admin.
	if _, err := s.EnrollTOTP(aliceCtx, &pb.EnrollTOTPRequest{Username: "bob"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for cross-user enroll, got %v", err)
	}
}

// TestDisableTwoFactor_Self verifies a user can clear their own 2FA.
func TestDisableTwoFactor_Self(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "x")
	aliceCtx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	aliceCtx = context.WithValue(aliceCtx, ctxKeyRole, "viewer")
	if _, err := s.EnrollTOTP(aliceCtx, &pb.EnrollTOTPRequest{Label: "phone"}); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	resp, err := s.ListTwoFactors(aliceCtx, &pb.ListTwoFactorsRequest{})
	if err != nil || len(resp.Factors) != 1 {
		t.Fatalf("expected 1 factor, got %v err=%v", resp, err)
	}
	if _, err := s.DisableTwoFactor(aliceCtx, &pb.DisableTwoFactorRequest{Method: "totp", Label: "phone"}); err != nil {
		t.Fatalf("DisableTwoFactor: %v", err)
	}
	resp, _ = s.ListTwoFactors(aliceCtx, &pb.ListTwoFactorsRequest{})
	if len(resp.Factors) != 0 {
		t.Fatalf("expected 0 factors after disable, got %d", len(resp.Factors))
	}
}
