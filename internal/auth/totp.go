package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// totpIssuer is what authenticator apps display next to the account.
// Cluster operators may want to override per-cluster (e.g. "litevirt-prod"),
// but a stable default keeps the QR provisioning URL deterministic.
const totpIssuer = "litevirt"

// totpRecoveryCodeCount is how many one-shot recovery codes we mint when
// a user enrols TOTP. Industry default is 10 (GitHub, Google).
const totpRecoveryCodeCount = 10

// TOTP validation parameters, shared by enrollment and verification.
const (
	totpPeriod = uint(30) // RFC 6238 default; one code per 30s window
	totpSkew   = uint(1)  // accept ±1 step (±30s drift), mirrors GitHub/Okta
)

// matchTOTPStep returns the time-step that `code` validates against (within
// ±skew of now), or ok=false if none. Unlike totp.ValidateCustom — which only
// returns a boolean — this exposes the matched step so the caller can enforce
// monotonic single-use (replay protection). Comparison is constant-time.
func matchTOTPStep(code, secret string, now time.Time, period, skew uint) (int64, bool) {
	t0 := now.Unix() / int64(period)
	// Probe t0 first, then alternate outward (t0+1, t0-1, …) like the
	// upstream validator does, so a matching code is found regardless of
	// drift direction.
	for d := int64(0); d <= int64(skew); d++ {
		for _, step := range stepsAtDistance(t0, d) {
			candidate, err := totp.GenerateCodeCustom(secret, time.Unix(step*int64(period), 0), totp.ValidateOpts{
				Period:    period,
				Skew:      0,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if err != nil {
				return 0, false
			}
			if constantTimeEqual(candidate, code) {
				return step, true
			}
		}
	}
	return 0, false
}

func stepsAtDistance(t0, d int64) []int64 {
	if d == 0 {
		return []int64{t0}
	}
	return []int64{t0 + d, t0 - d}
}

// EnrollTOTPResult is what an enrollment handler returns to the user. The
// secret is shown once (rendered as a QR code by the UI); recovery codes
// are shown once and never again.
type EnrollTOTPResult struct {
	// OtpAuthURL is the otpauth:// URI that authenticator apps consume
	// when scanning a QR code. Format:
	//   otpauth://totp/litevirt:<user>?secret=<base32>&issuer=litevirt
	OtpAuthURL string

	// SecretBase32 is the raw shared secret in base32 — useful for users
	// who can't scan a QR (hardware tokens, SSH-only ops).
	SecretBase32 string

	// RecoveryCodes are plaintext one-shot codes (formatted as 4-4 hex
	// groups). The DB only stores their bcrypt hashes.
	RecoveryCodes []string
}

// EnrollTOTP generates a fresh TOTP secret + recovery codes for the user
// and persists them. If the user already has a TOTP factor with the same
// label it is replaced — re-enrolling rotates the secret.
//
// The label is user-supplied (e.g. "phone", "yubikey-hw1") and lets a user
// register multiple authenticators of the same kind.
func EnrollTOTP(ctx context.Context, db *corrosion.Client, username, label string) (*EnrollTOTPResult, error) {
	if username == "" {
		return nil, fmt.Errorf("username required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // RFC 6238 default; widest authenticator support
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}

	if err := corrosion.InsertUser2FA(ctx, db, corrosion.User2FARecord{
		Username: username,
		Method:   "totp",
		Secret:   key.Secret(), // base32, raw secret — required for verification
		Label:    label,
	}); err != nil {
		return nil, fmt.Errorf("persist 2fa: %w", err)
	}

	codes, hashes, err := generateRecoveryCodes(totpRecoveryCodeCount)
	if err != nil {
		return nil, fmt.Errorf("generate recovery codes: %w", err)
	}
	if err := corrosion.InsertRecoveryCodes(ctx, db, username, hashes); err != nil {
		return nil, fmt.Errorf("persist recovery codes: %w", err)
	}

	return &EnrollTOTPResult{
		OtpAuthURL:    key.URL(),
		SecretBase32:  key.Secret(),
		RecoveryCodes: codes,
	}, nil
}

// VerifyTOTP checks `code` against any of the user's enrolled TOTP factors.
// Returns true on success, also touching last_used_at on the matched factor.
//
// Falls back to recovery-code verification if no factor matches: a recovery
// code consumed here is marked used and cannot be reused, matching how
// industry-standard 2FA flows work.
func VerifyTOTP(ctx context.Context, db *corrosion.Client, username, code string) (bool, error) {
	if code == "" {
		return false, nil
	}
	factors, err := corrosion.ListUser2FA(ctx, db, username)
	if err != nil {
		return false, fmt.Errorf("list factors: %w", err)
	}
	now := time.Now().UTC()
	for _, f := range factors {
		if f.Method != "totp" {
			continue
		}
		step, ok := matchTOTPStep(code, f.Secret, now, totpPeriod, totpSkew)
		if !ok {
			continue
		}
		// Replay guard: each TOTP time-step may be consumed at most once.
		// A code at or below the highest already-consumed step is a replay
		// (or a stale code) — reject it, and do NOT fall through to recovery
		// codes (a replayed TOTP is not a recovery code).
		if step <= f.LastStep {
			return false, nil
		}
		if err := corrosion.RecordTOTPStep(ctx, db, username, f.Method, f.Label, step); err != nil {
			return false, fmt.Errorf("record totp step: %w", err)
		}
		return true, nil
	}

	if matched, rcErr := verifyRecoveryCode(ctx, db, username, code); rcErr != nil {
		return false, rcErr
	} else if matched {
		return true, nil
	}
	return false, nil
}

// verifyRecoveryCode validates a presented code against unused recovery
// hashes. On match the hash is marked used.
func verifyRecoveryCode(ctx context.Context, db *corrosion.Client, username, code string) (bool, error) {
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return false, nil
	}
	hashes, err := corrosion.ListUnusedRecoveryCodes(ctx, db, username)
	if err != nil {
		return false, err
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(normalized)) == nil {
			if err := corrosion.MarkRecoveryCodeUsed(ctx, db, username, h); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// generateRecoveryCodes mints N codes formatted as "xxxx-xxxx" (8 hex chars,
// dash-separated for readability) along with their bcrypt hashes for storage.
func generateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	codes = make([]string, n)
	hashes = make([]string, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 5) // 40 bits → 8 base32 chars
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, err
		}
		s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
		// Format as xxxx-xxxx (one dash for readability).
		codes[i] = s[:4] + "-" + s[4:8]
		h, herr := bcrypt.GenerateFromPassword([]byte(normalizeRecoveryCode(codes[i])), BcryptCost)
		if herr != nil {
			return nil, nil, herr
		}
		hashes[i] = string(h)
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode strips whitespace and dashes and lowercases,
// so users typing "ABCD efgh" or "abcd-efgh" both resolve identically.
func normalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// constantTimeEqual exists so call sites that compare 2FA codes can be
// audited without grep'ing for `==` on user input.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
