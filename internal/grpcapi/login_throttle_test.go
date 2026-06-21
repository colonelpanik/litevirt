package grpcapi

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestLoginThrottle_LocksAfterMaxFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }
	key := "bob|10.0.0.1"

	for i := 0; i < defaultLoginMaxFailures-1; i++ {
		if d := th.fail(key); d != 0 {
			t.Fatalf("fail %d unexpectedly tripped lockout", i)
		}
		if w := th.retryAfter(key); w != 0 {
			t.Fatalf("locked out too early after %d failures", i+1)
		}
	}
	// The threshold-th failure trips the lockout.
	if d := th.fail(key); d != defaultLoginLockout {
		t.Fatalf("expected lockout duration %s, got %s", defaultLoginLockout, d)
	}
	if w := th.retryAfter(key); w <= 0 {
		t.Fatal("expected key to be locked out after threshold failures")
	}

	// A different key is unaffected.
	if w := th.retryAfter("alice|10.0.0.1"); w != 0 {
		t.Fatal("unrelated key should not be locked")
	}

	// Lockout expires.
	now = now.Add(defaultLoginLockout + time.Second)
	if w := th.retryAfter(key); w != 0 {
		t.Fatal("lockout should have expired")
	}
}

func TestLoginThrottle_SuccessClears(t *testing.T) {
	th := newLoginThrottle()
	key := "bob|10.0.0.1"
	for i := 0; i < defaultLoginMaxFailures-1; i++ {
		th.fail(key)
	}
	th.success(key)
	// Should be able to fail maxFailures-1 more times without locking.
	for i := 0; i < defaultLoginMaxFailures-1; i++ {
		if d := th.fail(key); d != 0 {
			t.Fatalf("lockout tripped despite prior success reset (i=%d)", i)
		}
	}
}

func TestLoginThrottle_NilIsNoop(t *testing.T) {
	var th *loginThrottle // nil
	if w := th.retryAfter("x"); w != 0 {
		t.Fatal("nil throttle should never lock out")
	}
	th.fail("x")    // must not panic
	th.success("x") // must not panic
}

// TestLogin_LocksOutAfterRepeatedFailures drives the real Login RPC: after
// the threshold of wrong-password attempts, even a would-be-valid attempt is
// refused with ResourceExhausted until the lockout clears.
func TestLogin_LocksOutAfterRepeatedFailures(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), auth.BcryptCost)
	if err := corrosion.InsertUser(ctx, s.db, "bob", "viewer", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	for i := 0; i < defaultLoginMaxFailures; i++ {
		_, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "wrong"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("attempt %d: expected Unauthenticated, got %v", i, err)
		}
	}

	// Now locked: even the correct password is refused with ResourceExhausted.
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "correct-horse"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted while locked out, got %v", err)
	}
}

// TestLogin_SuccessResetsThrottle confirms a successful login clears the
// failure counter so a few earlier typos don't bring a user closer to lockout.
func TestLogin_SuccessResetsThrottle(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), auth.BcryptCost)
	if err := corrosion.InsertUser(ctx, s.db, "bob", "viewer", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	// A couple of typos, then a success.
	for i := 0; i < defaultLoginMaxFailures-1; i++ {
		if _, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "wrong"}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("attempt %d: expected Unauthenticated, got %v", i, err)
		}
	}
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "correct-horse"}); err != nil {
		t.Fatalf("valid login should succeed and reset throttle: %v", err)
	}
	// Counter reset — another full run of failures should not be pre-locked.
	if w := s.loginThrottle.retryAfter(loginThrottleKey("bob", "")); w != 0 {
		t.Fatal("throttle should have been cleared by the successful login")
	}
}
