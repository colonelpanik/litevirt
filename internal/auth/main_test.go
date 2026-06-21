package auth

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain knocks bcrypt cost down to MinCost for the auth-package
// test suite. bcrypt.DefaultCost is intentionally CPU-expensive
// (~80 ms/hash) and the TOTP enroll path generates eight recovery-code
// hashes per call — the cumulative cost dominates `go test -race`.
func TestMain(m *testing.M) {
	BcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
