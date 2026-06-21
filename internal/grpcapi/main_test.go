package grpcapi

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/auth"
)

// TestMain knocks bcrypt cost down to MinCost for the grpcapi suite.
// The package has 880+ tests and many touch CreateUser / Login /
// CreateToken / EnrollTOTP, all of which hash at auth.BcryptCost.
// bcrypt.DefaultCost (10) ≈ 80 ms/hash on modern hardware; under
// `-race` instrumentation it climbs into the hundreds of ms — driving
// total `go test -race` runtime past 4 minutes for this package alone.
// MinCost (4) drops that to ~1 ms/hash with no loss of test coverage,
// because the production cost constant lives in internal/auth/cost.go
// and is exercised separately in production builds.
func TestMain(m *testing.M) {
	auth.BcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
