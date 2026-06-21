package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Login validates credentials via the configured realm and mints a
// session-bearer ("lvs_<id>") on success. If the user has 2FA enrolled and
// no totp_code was supplied, returns RequiresTwoFA=true with an empty token
// so the client can re-call Login with the second factor (wires
// TOTP verification; until then enrolled-but-not-verified is rejected).
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	realmName := req.Realm
	if realmName == "" {
		realmName = "local"
	}

	// At least one credential family must be supplied. OIDC code-flow
	// uses oidc_code + oidc_state; password realms use username +
	// password. Mixed inputs are tolerated — the realm picks what it
	// needs from Credentials.
	hasPassword := req.Username != "" && req.Password != ""
	hasOIDCCode := req.OidcCode != "" && req.OidcState != ""
	if !hasPassword && !hasOIDCCode {
		return nil, status.Error(codes.InvalidArgument,
			"login requires either username+password or oidc_code+oidc_state")
	}

	clientIP := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		clientIP = p.Addr.String()
	}

	// Brute-force lockout: refuse early if this (username, IP) is currently
	// locked out from too many recent failures. Keyed on the attempted
	// username so a correct password can't be ground out, and on IP so one
	// attacker can't lock a victim's account from afar.
	throttleKey := loginThrottleKey(req.Username, clientIP)
	if wait := s.loginThrottle.retryAfter(throttleKey); wait > 0 {
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" locked out ip="+clientIP, "denied")
		return nil, status.Errorf(codes.ResourceExhausted,
			"too many failed login attempts; retry in %s", wait.Round(time.Second))
	}

	// Realm dispatch: if a registry is wired, route by
	// name. Otherwise fall back to a hard-coded LocalRealm so tests
	// that don't construct a registry keep working.
	var realm auth.Realm
	if s.realmRegistry != nil {
		realm = s.realmRegistry.Get(realmName)
		if realm == nil {
			return nil, status.Errorf(codes.Unimplemented, "realm %q not configured", realmName)
		}
	} else if realmName == "local" {
		realm = auth.NewLocalRealm(s.db)
	} else {
		return nil, status.Errorf(codes.Unimplemented, "realm %q not configured (no registry)", realmName)
	}

	creds := auth.Credentials{
		Username:        req.Username,
		Password:        req.Password,
		OIDCCode:        req.OidcCode,
		OIDCState:       req.OidcState,
		OIDCRedirectURI: req.OidcRedirectUri,
	}
	principal, err := realm.Authenticate(ctx, creds)
	if err != nil {
		// Login is in skipAuth, so callerUsername(ctx) is empty here — record
		// the attempted username from the request as the audit target.
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" invalid credentials", "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, auth.ErrRealmUnavailable) {
			s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" unavailable", "denied")
			return nil, status.Errorf(codes.Unavailable, "realm unavailable: %v", err)
		}
		s.audit(ctx, "auth.login", req.Username, "realm="+realmName+" error", "denied")
		return nil, status.Errorf(codes.Internal, "authenticate: %v", err)
	}

	// External realms (OIDC/LDAP) may surface users not yet in the
	// local users table. Auto-shadow them so sessions / RBAC have a
	// stable subject. Default role is viewer; admins promote via
	// `lv user promote`.
	if realmName != "local" {
		if err := auth.EnsureUserShadow(ctx, s.db, principal, "viewer"); err != nil {
			return nil, status.Errorf(codes.Internal, "shadow user: %v", err)
		}
	}

	if principal.Requires2FA && req.TotpCode == "" {
		return &pb.LoginResponse{Requires_2Fa: true}, nil
	}
	if principal.Requires2FA {
		ok, err := s.verifyTOTP(ctx, principal.Subject, req.TotpCode)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "verify 2FA: %v", err)
		}
		if !ok {
			s.loginThrottle.fail(throttleKey)
			s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" invalid second factor", "denied")
			return nil, status.Error(codes.Unauthenticated, "invalid second factor")
		}
	}

	// Successful credential + (if required) second-factor verification —
	// clear any accumulated failure state for this key.
	s.loginThrottle.success(throttleKey)

	token, expiresAt, role, err := s.mintSession(ctx, principal.Subject, realmName, clientIP, req.UserAgent)
	if err != nil {
		return nil, err
	}

	slog.Info("user logged in", "username", principal.Subject, "realm", realmName)
	s.audit(ctx, "auth.login", principal.Subject, "realm="+realmName+" ip="+clientIP, "ok")
	return &pb.LoginResponse{
		Token:     token,
		Username:  principal.Subject,
		Role:      role,
		ExpiresAt: expiresAt,
	}, nil
}

// mintSession creates a session row for an already-authenticated user and
// returns the bearer token, hard-expiry (RFC3339), and the user's role. Shared
// by password Login and the WebAuthn login flow so both produce identical
// session semantics.
func (s *Server) mintSession(ctx context.Context, username, realm, clientIP, userAgent string) (token, expiresAt, role string, err error) {
	user, gerr := corrosion.GetUser(ctx, s.db, username)
	if gerr != nil || user == nil {
		return "", "", "", status.Errorf(codes.Internal, "post-auth user lookup: %v", gerr)
	}
	id, ierr := newSessionID()
	if ierr != nil {
		return "", "", "", status.Errorf(codes.Internal, "generate session id: %v", ierr)
	}
	now := time.Now().UTC()
	exp := now.Add(s.hardExpiry())
	if serr := corrosion.InsertSession(ctx, s.db, corrosion.SessionRecord{
		ID:         id,
		Username:   username,
		Realm:      realm,
		IP:         clientIP,
		UserAgent:  userAgent,
		CreatedAt:  now.Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339),
		ExpiresAt:  exp.Format(time.RFC3339),
	}); serr != nil {
		return "", "", "", status.Errorf(codes.Internal, "store session: %v", serr)
	}
	return SessionTokenPrefix + id, exp.Format(time.RFC3339), user.Role, nil
}

// ListRealms enumerates the authentication realms the daemon accepts
// Login against. The "local" realm is always present; OIDC/LDAP names
// come from auth.realms in the config. Bypasses auth so the login UI
// can populate the realm dropdown before any user is signed in.
func (s *Server) ListRealms(_ context.Context, _ *emptypb.Empty) (*pb.ListRealmsResponse, error) {
	resp := &pb.ListRealmsResponse{}
	if s.realmRegistry != nil {
		resp.Realms = s.realmRegistry.Names()
	} else {
		// Legacy / test path: no registry → only local works.
		resp.Realms = []string{"local"}
	}
	return resp, nil
}

// Logout revokes the current session (if the caller authenticated with one).
// Tokens (legacy API tokens) are not affected — use RevokeToken instead.
func (s *Server) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	sid := callerSessionID(ctx)
	if sid == "" {
		return &emptypb.Empty{}, nil
	}
	if err := corrosion.RevokeSession(ctx, s.db, sid); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke session: %v", err)
	}
	slog.Info("user logged out", "username", callerUsername(ctx))
	s.audit(ctx, "auth.logout", callerUsername(ctx), "session="+sid, "ok")
	return &emptypb.Empty{}, nil
}

// ListSessions returns active sessions for the requested user, or for the
// caller if username is empty. Listing other users' sessions requires admin.
func (s *Server) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	caller := callerUsername(ctx)
	target := req.Username
	if target == "" {
		target = caller
	}
	if target != caller {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	rows, err := corrosion.ListSessionsForUser(ctx, s.db, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	resp := &pb.ListSessionsResponse{}
	for _, r := range rows {
		resp.Sessions = append(resp.Sessions, &pb.Session{
			Id:         r.ID,
			Username:   r.Username,
			Realm:      r.Realm,
			Ip:         r.IP,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
			ExpiresAt:  r.ExpiresAt,
		})
	}
	return resp, nil
}

// RevokeSession terminates a session by id. The owning user can revoke
// their own; admins can revoke anyone's.
func (s *Server) RevokeSession(ctx context.Context, req *pb.RevokeSessionRequest) (*emptypb.Empty, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "session id required")
	}
	sess, err := corrosion.GetSession(ctx, s.db, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup session: %v", err)
	}
	if sess == nil {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if sess.Username != callerUsername(ctx) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	if err := corrosion.RevokeSession(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke session: %v", err)
	}
	slog.Info("session revoked", "id", req.Id, "username", sess.Username, "by", callerUsername(ctx))
	s.audit(ctx, "session.revoke", sess.Username, "session="+req.Id, "ok")
	return &emptypb.Empty{}, nil
}

// verifyTOTP delegates to the auth package's TOTP verifier. A successful
// recovery-code submission also returns true; the code is marked used.
func (s *Server) verifyTOTP(ctx context.Context, username, code string) (bool, error) {
	return auth.VerifyTOTP(ctx, s.db, username, code)
}

// loginThrottleKey identifies a brute-force bucket. An empty username (OIDC
// code-flow, which carries no username) falls back to IP-only so the bucket
// is still meaningful.
func loginThrottleKey(username, ip string) string {
	if username == "" {
		username = "_anon"
	}
	return username + "|" + ip
}

// newSessionID returns a 256-bit random hex string suitable as a session id.
func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}
	role := req.Role
	if role == "" {
		role = "viewer"
	}

	existing, _ := corrosion.GetUser(ctx, s.db, req.Username)
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "user %q already exists", req.Username)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), auth.BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash password: %v", err)
	}

	if err := corrosion.InsertUser(ctx, s.db, req.Username, role, string(hash)); err != nil {
		return nil, status.Errorf(codes.Internal, "create user: %v", err)
	}

	slog.Info("user created", "username", req.Username, "role", role)
	s.publish("user.created", req.Username, "role="+role)
	s.audit(ctx, "user.create", req.Username, "role="+role, "ok")

	return &pb.User{Username: req.Username, Role: role}, nil
}

func (s *Server) ListUsers(ctx context.Context, _ *emptypb.Empty) (*pb.ListUsersResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	users, err := corrosion.ListUsers(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list users: %v", err)
	}

	resp := &pb.ListUsersResponse{}
	for _, u := range users {
		pbUser := &pb.User{Username: u.Username, Role: u.Role}
		if u.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, u.CreatedAt); err == nil {
				pbUser.CreatedAt = timestamppb.New(t)
			}
		}
		resp.Users = append(resp.Users, pbUser)
	}
	return resp, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteUser(ctx, s.db, req.Username); err != nil {
		return nil, status.Errorf(codes.Internal, "delete user: %v", err)
	}
	slog.Info("user deleted", "username", req.Username)
	s.publish("user.deleted", req.Username, "")
	s.audit(ctx, "user.delete", req.Username, "", "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.Token, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "token name required")
	}

	// Verify user exists
	user, err := corrosion.GetUser(ctx, s.db, req.Username)
	if err != nil || user == nil {
		return nil, status.Errorf(codes.NotFound, "user %q not found", req.Username)
	}

	// Generate a random 32-byte token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Errorf(codes.Internal, "generate token: %v", err)
	}
	tokenStr := hex.EncodeToString(raw)

	hash, err := bcrypt.GenerateFromPassword([]byte(tokenStr), auth.BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash token: %v", err)
	}

	id := generateID()
	var expiresAt string
	if req.Expires != "" {
		expiresAt = req.Expires
	}

	if err := corrosion.InsertToken(ctx, s.db, corrosion.TokenRecord{
		ID:         id,
		Username:   req.Username,
		Name:       req.Name,
		TokenHash:  string(hash),
		ExpiresAt:  expiresAt,
		ScopePaths: req.ScopePaths,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store token: %v", err)
	}

	slog.Info("token created", "username", req.Username, "name", req.Name, "id", id, "scopes", req.ScopePaths)
	s.audit(ctx, "token.create", id, "user="+req.Username+" name="+req.Name, "ok")
	// Return the plaintext token — only shown once.
	return &pb.Token{
		Id:       id,
		Username: req.Username,
		Name:     req.Name,
		Token:    tokenStr,
	}, nil
}

func (s *Server) RevokeToken(ctx context.Context, req *pb.RevokeTokenRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := corrosion.RevokeToken(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke token: %v", err)
	}
	slog.Info("token revoked", "id", req.Id)
	s.audit(ctx, "token.revoke", req.Id, "", "ok")
	return &emptypb.Empty{}, nil
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
