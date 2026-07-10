package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"golang.org/x/crypto/bcrypt"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{
		hostName: "test-host",
		pkiDir:   "/etc/litevirt/pki",
		db:       db,
		events:   events.NewBus(),
	}
}

// adminCtx returns a context with admin role, for use in tests that call
// handlers directly (bypassing the gRPC auth interceptor).
func adminCtx() context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// peerCtxFor inserts cn as a live cluster host in s.db and returns an mTLS peer
// context for it, so a call passes requirePeerCert (and classifies as `peer`).
// Used by tests of peer-only RPCs that call handlers directly.
func peerCtxFor(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: cn, Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost(%s): %v", cn, err)
	}
	return mtlsCtx(cn)
}

func TestCallerUsername_Default(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	if got := callerUsername(ctx); got != "alice" {
		t.Errorf("expected alice, got %q", got)
	}
}

func TestCallerRole_Default(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "operator")
	if got := callerRole(ctx); got != "operator" {
		t.Errorf("expected operator, got %q", got)
	}
}

func TestCallerUsername_Missing(t *testing.T) {
	if got := callerUsername(context.Background()); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestRoleLevel(t *testing.T) {
	if roleLevel("admin") <= roleLevel("operator") {
		t.Error("admin should outrank operator")
	}
	if roleLevel("operator") <= roleLevel("viewer") {
		t.Error("operator should outrank viewer")
	}
	if roleLevel("viewer") <= roleLevel("unknown") {
		t.Error("viewer should outrank unknown")
	}
}

func TestRequireRole_Sufficient(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "admin")
	if err := RequireRole(ctx, "operator"); err != nil {
		t.Errorf("admin should satisfy operator requirement: %v", err)
	}
}

func TestRequireRole_Insufficient(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "viewer")
	if err := RequireRole(ctx, "operator"); err == nil {
		t.Error("viewer should NOT satisfy operator requirement")
	}
}

func TestAuthenticate_NoMetadata_Admin(t *testing.T) {
	s := testServer(t)
	ctx, err := s.authenticate(context.Background())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if callerRole(ctx) != "admin" {
		t.Errorf("expected admin role for mTLS caller, got %q", callerRole(ctx))
	}
}

func TestAuthenticate_ValidToken(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// Create user and token.
	hash, _ := bcrypt.GenerateFromPassword([]byte("supersecret"), bcrypt.MinCost)
	if err := corrosion.InsertUser(ctx, s.db, "bob", "operator", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	// Real API tokens are 64 hex chars; ValidateToken fast-rejects other shapes.
	const apiToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokenHash, _ := bcrypt.GenerateFromPassword([]byte(apiToken), bcrypt.MinCost)
	if err := corrosion.InsertToken(ctx, s.db, corrosion.TokenRecord{
		ID:        "tok1",
		Username:  "bob",
		Name:      "ci-token",
		TokenHash: string(tokenHash),
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	// Directly test ValidateToken since we can't easily inject gRPC metadata in unit tests.
	user, err := corrosion.ValidateToken(ctx, s.db, apiToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "bob" || user.Role != "operator" {
		t.Errorf("unexpected user: %+v", user)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	user, err := corrosion.ValidateToken(ctx, s.db, "notavalidtoken")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil for invalid token, got %+v", user)
	}
}
