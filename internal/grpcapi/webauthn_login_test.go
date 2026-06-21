package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestMintSession covers the session-minting shared by password Login and the
// WebAuthn login flow (WS4c): a valid user gets a real bearer + a future hard
// expiry, and the session is persisted and resolvable.
func TestMintSession(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "wakey", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	token, expiresAt, role, err := s.mintSession(ctx, "wakey", "local", "10.0.0.9", "webauthn")
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	if !strings.HasPrefix(token, SessionTokenPrefix) {
		t.Errorf("token %q lacks session prefix", token)
	}
	if role != "operator" {
		t.Errorf("role = %q, want operator", role)
	}
	exp, perr := time.Parse(time.RFC3339, expiresAt)
	if perr != nil || !exp.After(time.Now()) {
		t.Errorf("expiresAt %q not a future RFC3339 time (err=%v)", expiresAt, perr)
	}

	// The session must be persisted and resolve back to the user.
	sid := strings.TrimPrefix(token, SessionTokenPrefix)
	sess, err := corrosion.GetSession(ctx, s.db, sid)
	if err != nil || sess == nil {
		t.Fatalf("session not persisted: err=%v", err)
	}
	if sess.Username != "wakey" || sess.Realm != "local" {
		t.Errorf("session = %+v", sess)
	}
}

// TestFinishWebAuthnLogin_Unimplemented confirms the RPC is a clean no-op when
// WebAuthn isn't configured (rather than panicking on a nil service).
func TestFinishWebAuthnLogin_Unimplemented(t *testing.T) {
	s := testServer(t) // no webauthn service wired
	_, err := s.FinishWebAuthnLogin(context.Background(), &pb.FinishWebAuthnLoginRequest{
		Username: "x", AssertionJson: []byte("{}"),
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v", err)
	}
}

// TestWebAuthnLoginInSkipAuth guards that the login RPCs bypass the auth
// interceptor (pre-session) but registration does NOT.
func TestWebAuthnLoginInSkipAuth(t *testing.T) {
	for _, m := range []string{
		"/litevirt.v1.LiteVirt/BeginWebAuthnLogin",
		"/litevirt.v1.LiteVirt/FinishWebAuthnLogin",
	} {
		if !skipAuth[m] {
			t.Errorf("%s should be in skipAuth (pre-session login)", m)
		}
	}
	for _, m := range []string{
		"/litevirt.v1.LiteVirt/BeginWebAuthnRegistration",
		"/litevirt.v1.LiteVirt/FinishWebAuthnRegistration",
	} {
		if skipAuth[m] {
			t.Errorf("%s must NOT be in skipAuth (registration requires a session)", m)
		}
	}
}
