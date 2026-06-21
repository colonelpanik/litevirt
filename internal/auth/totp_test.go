package auth

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func newAuthTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// TestEnrollTOTP_StoresSecretAndRecoveryCodes verifies enrolment writes a
// 2fa row plus the configured number of recovery hashes.
func TestEnrollTOTP_StoresSecretAndRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	res, err := EnrollTOTP(ctx, db, "alice", "phone")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if res.SecretBase32 == "" {
		t.Error("expected base32 secret")
	}
	if len(res.RecoveryCodes) != totpRecoveryCodeCount {
		t.Errorf("expected %d recovery codes, got %d", totpRecoveryCodeCount, len(res.RecoveryCodes))
	}

	factors, err := corrosion.ListUser2FA(ctx, db, "alice")
	if err != nil {
		t.Fatalf("ListUser2FA: %v", err)
	}
	if len(factors) != 1 || factors[0].Method != "totp" || factors[0].Label != "phone" {
		t.Errorf("unexpected factors: %+v", factors)
	}
	hashes, err := corrosion.ListUnusedRecoveryCodes(ctx, db, "alice")
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(hashes) != totpRecoveryCodeCount {
		t.Errorf("expected %d hashes stored, got %d", totpRecoveryCodeCount, len(hashes))
	}
}

// TestVerifyTOTP_ValidCodeAccepted enrolls a user, recomputes the current
// TOTP from the returned secret, and verifies VerifyTOTP accepts it.
func TestVerifyTOTP_ValidCodeAccepted(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	res, err := EnrollTOTP(ctx, db, "alice", "")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	code, err := totp.GenerateCodeCustom(res.SecretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	ok, err := VerifyTOTP(ctx, db, "alice", code)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if !ok {
		t.Fatal("expected valid code to verify")
	}
}

// TestVerifyTOTP_ReplayRejected verifies a valid code can be used exactly
// once: a second submission of the SAME code (same time-step) is rejected as
// a replay, even though it would otherwise still be within its ±30s validity.
func TestVerifyTOTP_ReplayRejected(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	res, err := EnrollTOTP(ctx, db, "alice", "")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	code, err := totp.GenerateCodeCustom(res.SecretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	ok, err := VerifyTOTP(ctx, db, "alice", code)
	if err != nil || !ok {
		t.Fatalf("first use of code should verify: ok=%v err=%v", ok, err)
	}

	// last_step must have ratcheted forward.
	factors, err := corrosion.ListUser2FA(ctx, db, "alice")
	if err != nil {
		t.Fatalf("ListUser2FA: %v", err)
	}
	if factors[0].LastStep == 0 {
		t.Fatal("expected last_step to ratchet forward after a successful verify")
	}

	// Same code, still inside its window — must be rejected as a replay.
	ok, err = VerifyTOTP(ctx, db, "alice", code)
	if err != nil {
		t.Fatalf("VerifyTOTP (replay): %v", err)
	}
	if ok {
		t.Fatal("a TOTP code was accepted twice — replay guard failed")
	}
}

// TestVerifyTOTP_BadCodeRejected ensures we don't accept arbitrary input.
func TestVerifyTOTP_BadCodeRejected(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if _, err := EnrollTOTP(ctx, db, "alice", ""); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	ok, err := VerifyTOTP(ctx, db, "alice", "000000")
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if ok {
		t.Fatal("expected zero code to be rejected")
	}
}

// TestVerifyTOTP_RecoveryCodeOneShot verifies recovery codes work once and
// are then marked used.
func TestVerifyTOTP_RecoveryCodeOneShot(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	res, err := EnrollTOTP(ctx, db, "alice", "")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	code := res.RecoveryCodes[0]

	ok, err := VerifyTOTP(ctx, db, "alice", code)
	if err != nil || !ok {
		t.Fatalf("expected first use of recovery code to succeed: ok=%v err=%v", ok, err)
	}
	// Second use must fail.
	ok, err = VerifyTOTP(ctx, db, "alice", code)
	if err != nil {
		t.Fatalf("VerifyTOTP (replay): %v", err)
	}
	if ok {
		t.Fatal("recovery code accepted twice — must be one-shot")
	}
}

// TestVerifyTOTP_NoFactorsEnrolled returns false (not error) so callers
// can treat "no 2FA" as a clean negative.
func TestVerifyTOTP_NoFactorsEnrolled(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	ok, err := VerifyTOTP(ctx, db, "alice", "123456")
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if ok {
		t.Fatal("expected false when user has no factors")
	}
}

// TestNormalizeRecoveryCode handles dashes, spaces, and casing.
func TestNormalizeRecoveryCode(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"ABCD-EFGH", "abcdefgh"},
		{"abcd efgh", "abcdefgh"},
		{"  ABCD-EFGH  ", "abcdefgh"},
		{"abcdefgh", "abcdefgh"},
	} {
		if got := normalizeRecoveryCode(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
