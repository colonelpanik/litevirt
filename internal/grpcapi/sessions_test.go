package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"golang.org/x/crypto/bcrypt"
)

func seedUser(t *testing.T, s *Server, username, role, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := corrosion.InsertUser(context.Background(), s.db, username, role, string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
}

// TestLogin_HappyPath_IssuesSessionBearer verifies Login returns a bearer
// prefixed with "lvs_" and that the session row is persisted.
func TestLogin_HappyPath_IssuesSessionBearer(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "operator", "hunter2")

	resp, err := s.Login(context.Background(), &pb.LoginRequest{
		Username: "alice",
		Password: "hunter2",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !strings.HasPrefix(resp.Token, SessionTokenPrefix) {
		t.Fatalf("expected token to be a session bearer (prefix %q), got %q", SessionTokenPrefix, resp.Token)
	}
	if resp.Role != "operator" {
		t.Errorf("expected role operator, got %q", resp.Role)
	}
	if resp.ExpiresAt == "" {
		t.Error("expected ExpiresAt to be populated")
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)
	sess, err := corrosion.GetSession(context.Background(), s.db, id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess == nil || sess.Username != "alice" || sess.Realm != "local" {
		t.Errorf("session not stored as expected: %+v", sess)
	}
}

// TestLogin_BadPassword_Unauthenticated verifies wrong password is rejected
// without distinguishing from "no such user" (no enumeration).
func TestLogin_BadPassword_Unauthenticated(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")

	_, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "wrong"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "ghost", Password: "x"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for unknown user, got %v", err)
	}
}

// TestAuthenticate_SessionBearer_HappyPath verifies the auth interceptor
// resolves a "lvs_..." bearer to the session's user and bumps last_used_at.
func TestAuthenticate_SessionBearer_HappyPath(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "operator", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)

	// Force last_used_at to a known earlier time, then authenticate and
	// confirm Touch advances it.
	earlier := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := s.db.Execute(context.Background(),
		`UPDATE sessions SET last_used_at = ? WHERE id = ?`, earlier, id); err != nil {
		t.Fatalf("seed last_used: %v", err)
	}

	md := metadata.New(map[string]string{"authorization": "Bearer " + resp.Token})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	authedCtx, err := s.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u := callerUsername(authedCtx); u != "alice" {
		t.Errorf("expected alice, got %q", u)
	}
	if r := callerRole(authedCtx); r != "operator" {
		t.Errorf("expected operator, got %q", r)
	}
	if sid := callerSessionID(authedCtx); sid != id {
		t.Errorf("expected sid %q in ctx, got %q", id, sid)
	}

	sess, _ := corrosion.GetSession(context.Background(), s.db, id)
	if sess.LastUsedAt == earlier {
		t.Error("expected last_used_at to be updated by authenticate()")
	}
}

// TestAuthenticate_SessionBearer_RevokedRejected ensures revoked sessions
// cannot continue making calls.
func TestAuthenticate_SessionBearer_RevokedRejected(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)
	if err := corrosion.RevokeSession(context.Background(), s.db, id); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	md := metadata.New(map[string]string{"authorization": "Bearer " + resp.Token})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := s.authenticate(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for revoked session, got %v", err)
	}
}

// TestAuthenticate_SessionBearer_IdleTimeout ensures stale sessions are
// rejected even before hard expiry.
func TestAuthenticate_SessionBearer_IdleTimeout(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)

	stale := time.Now().UTC().Add(-(SessionIdleTimeout + time.Minute)).Format(time.RFC3339)
	if err := s.db.Execute(context.Background(),
		`UPDATE sessions SET last_used_at = ? WHERE id = ?`, stale, id); err != nil {
		t.Fatalf("seed: %v", err)
	}

	md := metadata.New(map[string]string{"authorization": "Bearer " + resp.Token})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := s.authenticate(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for idle session, got %v", err)
	}
	// Idle-timeout path should also revoke the session so reuse fails fast.
	sess, _ := corrosion.GetSession(context.Background(), s.db, id)
	if sess.RevokedAt == "" {
		t.Error("expected idle-timeout to mark session revoked")
	}
}

// TestLogout_RevokesCurrentSession verifies Logout terminates the active session.
func TestLogout_RevokesCurrentSession(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)

	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	ctx = context.WithValue(ctx, ctxKeySessionID, id)
	if _, err := s.Logout(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	sess, _ := corrosion.GetSession(context.Background(), s.db, id)
	if sess.RevokedAt == "" {
		t.Error("expected session revoked after Logout")
	}
}

// TestRevokeSession_OwnerCanRevokeOwn verifies non-admin can revoke their
// own session (e.g. lost laptop) without admin help.
func TestRevokeSession_OwnerCanRevokeOwn(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)

	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	if _, err := s.RevokeSession(ctx, &pb.RevokeSessionRequest{Id: id}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	sess, _ := corrosion.GetSession(context.Background(), s.db, id)
	if sess.RevokedAt == "" {
		t.Error("expected session revoked")
	}
}

// TestRevokeSession_NonAdminCannotRevokeOthers ensures non-admins can't
// kick others out.
func TestRevokeSession_NonAdminCannotRevokeOthers(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	seedUser(t, s, "bob", "viewer", "hunter2")
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	id := strings.TrimPrefix(resp.Token, SessionTokenPrefix)

	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	if _, err := s.RevokeSession(ctx, &pb.RevokeSessionRequest{Id: id}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestListSessions_OwnSessions returns the caller's own sessions when no
// username is supplied (no admin needed).
func TestListSessions_OwnSessions(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	if _, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "hunter2"}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	resp, err := s.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0].Username != "alice" {
		t.Errorf("unexpected sessions: %+v", resp.Sessions)
	}
}
