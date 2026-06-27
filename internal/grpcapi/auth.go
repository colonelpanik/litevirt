package grpcapi

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type ctxKey int

const (
	ctxKeyUsername ctxKey = iota
	ctxKeyRole
	ctxKeyRealm
	ctxKeySessionID
	ctxKeyScopePaths
	ctxKeyAuthMethod
	ctxKeyMTLSCommonName
)

const (
	authMethodSession = "session"
	authMethodToken   = "token"
	authMethodMTLS    = "mtls"
)

// SessionTokenPrefix marks bearer strings that resolve via the sessions
// table (as opposed to the legacy tokens table). Format: "lvs_<hex-id>".
const SessionTokenPrefix = "lvs_"

// SessionIdleTimeout — DEFAULT idle window: a session is rejected if
// last_used_at is older than this. Each authenticated RPC bumps last_used_at.
// Overridable per-daemon via config (auth.session_idle_timeout).
const SessionIdleTimeout = 8 * time.Hour

// SessionHardExpiry — DEFAULT absolute lifetime of a session regardless of
// activity. Overridable via config (auth.session_hard_expiry). The value is
// stored on the session row (ExpiresAt) at login, so the hard cap stays
// consistent cluster-wide even if nodes carry different configs.
const SessionHardExpiry = 7 * 24 * time.Hour

// idleTimeout / hardExpiry return the configured session lifetimes, falling
// back to the package defaults when unset (0) — so struct-literal test servers
// and unconfigured daemons get the defaults.
func (s *Server) idleTimeout() time.Duration {
	if s.sessionIdleTimeout > 0 {
		return s.sessionIdleTimeout
	}
	return SessionIdleTimeout
}

func (s *Server) hardExpiry() time.Duration {
	if s.sessionHardExpiry > 0 {
		return s.sessionHardExpiry
	}
	return SessionHardExpiry
}

// SetSessionTimeouts overrides the session idle/hard lifetimes from daemon
// config. A non-positive value leaves the corresponding default in place.
func (s *Server) SetSessionTimeouts(idle, hard time.Duration) {
	if idle > 0 {
		s.sessionIdleTimeout = idle
	}
	if hard > 0 {
		s.sessionHardExpiry = hard
	}
}

// skipAuth lists RPC methods that bypass authentication.
var skipAuth = map[string]bool{
	"/litevirt.v1.LiteVirt/Ping":       true,
	"/litevirt.v1.LiteVirt/Login":      true,
	"/litevirt.v1.LiteVirt/ListRealms": true,
	// WebAuthn login is pre-session (passwordless): the caller has no bearer
	// yet and supplies its own username. The assertion IS the credential, so
	// these bypass the interceptor like Login does. Registration RPCs are NOT
	// here — those require an authenticated session (you enrol a key while
	// logged in).
	"/litevirt.v1.LiteVirt/BeginWebAuthnLogin":  true,
	"/litevirt.v1.LiteVirt/FinishWebAuthnLogin": true,
}

// UnaryAuthInterceptor validates tokens/mTLS on every unary RPC.
func (s *Server) UnaryAuthInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if skipAuth[info.FullMethod] {
		return handler(ctx, req)
	}
	ctx, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// StreamAuthInterceptor validates tokens/mTLS on every streaming RPC.
func (s *Server) StreamAuthInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if skipAuth[info.FullMethod] {
		return handler(srv, ss)
	}
	ctx, err := s.authenticate(ss.Context())
	if err != nil {
		return err
	}
	return handler(srv, &wrappedStream{ss, ctx})
}

// authenticate extracts and validates the caller identity.
//
//	Bearer "lvs_<id>" → sessions table lookup, idle/hard-expiry enforced
//	Bearer "<hex>"    → legacy API token bcrypt match
//	No bearer        → mTLS client cert (CLI/daemon) → treat as admin
func (s *Server) authenticate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if auth := md.Get("authorization"); len(auth) > 0 {
			val := auth[0]
			if !strings.HasPrefix(val, "Bearer ") {
				return nil, status.Error(codes.Unauthenticated, "authorization header must use Bearer scheme")
			}
			rawToken := strings.TrimPrefix(val, "Bearer ")

			if strings.HasPrefix(rawToken, SessionTokenPrefix) {
				return s.authenticateSession(ctx, strings.TrimPrefix(rawToken, SessionTokenPrefix))
			}

			user, err := corrosion.ValidateToken(ctx, s.db, rawToken)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "token validation: %v", err)
			}
			if user == nil {
				return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
			}
			ctx = context.WithValue(ctx, ctxKeyUsername, user.Username)
			ctx = context.WithValue(ctx, ctxKeyRole, user.Role)
			ctx = context.WithValue(ctx, ctxKeyRealm, "local")
			ctx = context.WithValue(ctx, ctxKeyAuthMethod, authMethodToken)
			if len(user.ScopePaths) > 0 {
				ctx = context.WithValue(ctx, ctxKeyScopePaths, user.ScopePaths)
			}
			return ctx, nil
		}
	}
	// No bearer token — authenticated via mTLS client cert (CLI / daemon-to-daemon).
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	ctx = context.WithValue(ctx, ctxKeyRealm, "local")
	ctx = context.WithValue(ctx, ctxKeyAuthMethod, authMethodMTLS)
	if cn := peerCommonName(ctx); cn != "" {
		ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, cn)
	}
	return ctx, nil
}

// authenticateSession validates a "lvs_<id>"-prefixed bearer against the
// sessions table. Enforces revoke, hard expiry, and idle timeout, and
// touches last_used_at on success.
func (s *Server) authenticateSession(ctx context.Context, sid string) (context.Context, error) {
	if sid == "" {
		return nil, status.Error(codes.Unauthenticated, "empty session id")
	}
	sess, err := corrosion.GetSession(ctx, s.db, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session lookup: %v", err)
	}
	if sess == nil {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	if sess.RevokedAt != "" {
		return nil, status.Error(codes.Unauthenticated, "session revoked")
	}
	now := time.Now().UTC()
	// Fail CLOSED: a malformed/empty timestamp rejects the session rather than
	// skipping the check (the old code failed open on a parse error).
	exp, perr := time.Parse(time.RFC3339, sess.ExpiresAt)
	if perr != nil || now.After(exp) {
		return nil, status.Error(codes.Unauthenticated, "session expired")
	}
	last, perr := time.Parse(time.RFC3339, sess.LastUsedAt)
	if perr != nil || now.Sub(last) > s.idleTimeout() {
		_ = corrosion.RevokeSession(ctx, s.db, sid)
		return nil, status.Error(codes.Unauthenticated, "session idle-timeout exceeded")
	}
	user, err := corrosion.GetUser(ctx, s.db, sess.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session user lookup: %v", err)
	}
	if user == nil {
		_ = corrosion.RevokeSession(ctx, s.db, sid)
		return nil, status.Error(codes.Unauthenticated, "session user not found")
	}
	_ = corrosion.TouchSession(ctx, s.db, sid)
	ctx = context.WithValue(ctx, ctxKeyUsername, user.Username)
	ctx = context.WithValue(ctx, ctxKeyRole, user.Role)
	ctx = context.WithValue(ctx, ctxKeyRealm, sess.Realm)
	ctx = context.WithValue(ctx, ctxKeySessionID, sid)
	ctx = context.WithValue(ctx, ctxKeyAuthMethod, authMethodSession)
	return ctx, nil
}

// callerSessionID returns the active session id when the caller authenticated
// via a session bearer; empty if the request used a legacy token or mTLS.
func callerSessionID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeySessionID).(string); ok {
		return v
	}
	return ""
}

// callerRealm returns the realm name the caller authenticated through.
func callerRealm(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRealm).(string); ok && v != "" {
		return v
	}
	return "local"
}

func callerAuthMethod(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyAuthMethod).(string); ok {
		return v
	}
	return ""
}

func callerMTLSCommonName(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyMTLSCommonName).(string); ok {
		return v
	}
	return ""
}

func peerCommonName(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return ""
	}
	return tlsInfo.State.PeerCertificates[0].Subject.CommonName
}

// RequireRole returns an error if the caller's role is insufficient.
// Roles: admin > operator > viewer.
//
// Deprecated for new code: prefer RequirePerm(ctx, path, verb) which
// consults the path-based RBAC engine. This function is the legacy
// fallback used by handlers we haven't migrated yet, and as the bridge
// fallback when no role-bindings exist in the cluster.
func RequireRole(ctx context.Context, minRole string) error {
	role := callerRole(ctx)
	if roleLevel(role) < roleLevel(minRole) {
		return status.Errorf(codes.PermissionDenied, "role %q required, caller has %q", minRole, role)
	}
	return nil
}

// RequirePerm checks whether the caller may perform `verb` at `path` in
// the path-based RBAC model. transitional contract:
//
//  1. Token-scope guard: if the caller authenticated with a scoped API
//     token, `path` must be under one of the token's scope_paths regardless
//     of the user's role. This is the same intersection rule that GitHub
//     fine-grained PATs and AWS IAM session tokens use.
//  2. If the auth engine is wired AND has any binding for the caller's
//     principal-set, the engine's decision is authoritative.
//  3. Otherwise (no engine, or caller has no bindings at all), fall back
//     to the legacy RequireRole(minRole) semantics. The caller passes a
//     fallbackRole as a safety net for mixed-state clusters.
//
// Once every cluster has migrated to role-bindings, the fallback path
// can be deleted and RequirePerm becomes the only authz primitive.
func (s *Server) RequirePerm(ctx context.Context, path, verb, fallbackRole string) error {
	user := callerUsername(ctx)
	role := callerRole(ctx)
	if user == "" {
		return status.Error(codes.Unauthenticated, "no authenticated principal")
	}

	if scopes := callerScopePaths(ctx); len(scopes) > 0 && !pathAllowedByScopes(path, scopes) {
		return status.Errorf(codes.PermissionDenied,
			"token scope does not cover %q", path)
	}

	if s != nil && s.authEngine != nil {
		principalIDs := principalsForCaller(user, role)
		if s.authEngine.HasAnyBinding(principalIDs) {
			if s.authEngine.Allowed(principalIDs, verb, path) {
				return nil
			}
			return status.Errorf(codes.PermissionDenied,
				"caller %q lacks %q on %q", user, verb, path)
		}
	}

	// No bindings → legacy fallback.
	return RequireRole(ctx, fallbackRole)
}

// requirePermPrecheck is a path-independent gate used by handlers that must
// resolve the target object (and its tenancy project) before they can build
// the real RBAC path for RequirePerm. It denies callers who could never be
// authorized for ANY path of this verb — i.e. callers with no RBAC bindings
// whose legacy role is below fallbackRole — without first leaking whether
// the target object exists. Callers who DO hold bindings are let through so
// the subsequent per-path RequirePerm (after the object is fetched) makes
// the authoritative decision.
//
// Contract: a pass here is NOT an authorization grant. The handler MUST still
// call RequirePerm with the resolved path. This only short-circuits the
// obvious no-binding/insufficient-role denial early.
func (s *Server) requirePermPrecheck(ctx context.Context, fallbackRole string) error {
	user := callerUsername(ctx)
	if user == "" {
		return status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	if s != nil && s.authEngine != nil {
		principalIDs := principalsForCaller(user, callerRole(ctx))
		if s.authEngine.HasAnyBinding(principalIDs) {
			// Binding-holder: defer to the per-path check after fetch.
			return nil
		}
	}
	return RequireRole(ctx, fallbackRole)
}

// callerScopePaths returns the token-scope path prefixes attached to the
// caller's bearer credential (or nil for unscoped sessions / mTLS).
func callerScopePaths(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxKeyScopePaths).([]string); ok {
		return v
	}
	return nil
}

// pathAllowedByScopes reports whether the request path is covered by any
// scope. A scope is a path prefix; "/" is the root and matches everything.
// We reuse auth.PathPrefixOf semantics inline to avoid a circular import:
// "/foo/bar" covers "/foo/bar" and "/foo/bar/baz" but not "/foo/barred".
func pathAllowedByScopes(path string, scopes []string) bool {
	for _, s := range scopes {
		if pathHasPrefix(s, path) {
			return true
		}
	}
	return false
}

// pathHasPrefix mirrors internal/auth.pathPrefixOf so we don't introduce
// a dependency cycle. Both must agree to keep scope checks consistent
// with the engine's propagation rules.
func pathHasPrefix(prefix, path string) bool {
	prefix = canonicalScopePath(prefix)
	path = canonicalScopePath(path)
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

func canonicalScopePath(p string) string {
	if p == "" {
		return "/"
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return p
}

// principalsForCaller is the canonical mapping from (user, legacy-role)
// to the principal IDs the auth engine evaluates against. Always emits
// `user:<u>@local` (since today's only realm is local), and a synthetic
// `group:<role>@local` so legacy roles can be granted via role-bindings:
//
//	# Grant Admin to all admins:
//	lv role grant Admin group:admin@local --path /
//
// When OIDC/LDAP land, this helper learns to accept the realm-aware
// Principal struct in context and emit `user:<sub>@<realm>` plus
// `group:<g>@<realm>` for each remote group.
func principalsForCaller(user, role string) []string {
	out := []string{"user:" + user + "@local"}
	if role != "" {
		out = append(out, "group:"+role+"@local")
	}
	return out
}

func roleLevel(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

// callerUsername extracts the authenticated username from context.
func callerUsername(ctx context.Context) string {
	if u, ok := ctx.Value(ctxKeyUsername).(string); ok {
		return u
	}
	return ""
}

// callerRole extracts the authenticated role from context.
func callerRole(ctx context.Context) string {
	if r, ok := ctx.Value(ctxKeyRole).(string); ok {
		return r
	}
	return ""
}

// wrappedStream attaches a new context to a grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// metadataFromStream extracts incoming metadata from any grpc.ServerStream.
func metadataFromStream(stream grpc.ServerStream) (metadata.MD, bool) {
	return metadata.FromIncomingContext(stream.Context())
}
