package auth

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestNewWebAuthnService_HappyPath ensures the constructor accepts a
// reasonable config and returns a usable engine. This is the smallest
// proof that the dependency wiring works; full registration/login
// flows require a browser-resident authenticator.
func TestNewWebAuthnService_HappyPath(t *testing.T) {
	db := newAuthTestDB(t)
	svc, err := NewWebAuthnService(db, WebAuthnConfig{
		RPDisplayName: "litevirt",
		RPID:          "litevirt.test",
		RPOrigins:     []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	if svc.engine == nil {
		t.Error("engine not constructed")
	}
}

// TestNewWebAuthnService_MissingRPID surfaces the most common config
// mistake — no RPID — as a clear error.
func TestNewWebAuthnService_MissingRPID(t *testing.T) {
	db := newAuthTestDB(t)
	_, err := NewWebAuthnService(db, WebAuthnConfig{})
	if err == nil {
		t.Error("expected error for missing RPID")
	}
}

// TestBeginRegistration_RequiresUser surfaces a stale-config case
// (config refers to a non-existent user).
func TestBeginRegistration_RequiresUser(t *testing.T) {
	db := newAuthTestDB(t)
	svc, err := NewWebAuthnService(db, WebAuthnConfig{
		RPID: "litevirt.test", RPOrigins: []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	_, err = svc.BeginRegistration(context.Background(), "ghost")
	if err == nil {
		t.Error("expected error for unknown user")
	}
}

// TestBeginRegistration_KnownUserReturnsCreationOptions verifies the
// happy path: the Begin call returns a non-empty JSON challenge that
// the browser would normally pass to navigator.credentials.create.
func TestBeginRegistration_KnownUserReturnsCreationOptions(t *testing.T) {
	db := newAuthTestDB(t)
	if err := corrosion.InsertUser(context.Background(), db, "alice", "viewer", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	svc, err := NewWebAuthnService(db, WebAuthnConfig{
		RPID: "litevirt.test", RPOrigins: []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	out, err := svc.BeginRegistration(context.Background(), "alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected non-empty creation options")
	}
	// Session is now in flight; verify takeSession returns it.
	if sess := svc.takeSession("alice"); sess == nil {
		t.Error("expected session stored after BeginRegistration")
	}
}

// TestCredLabel_StableEncoding locks the byte→label mapping so a
// round-tripped credential is matched against the same row.
func TestCredLabel_StableEncoding(t *testing.T) {
	id := []byte{0x01, 0xff, 0xab}
	a := credLabel(id)
	b := credLabel(append([]byte(nil), id...))
	if a != b {
		t.Errorf("credLabel non-deterministic: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("credLabel returned empty string")
	}
}
