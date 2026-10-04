package ui

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// withBearerToken attaches the UI's session cookie to outgoing gRPC
// metadata so the daemon-side auth interceptor can identify the user
// for revoke / logout / per-user RPCs.
func withBearerToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

const sessionCookieName = "lv_session"

// requireAuth wraps an http.Handler and redirects to /login unless the session
// cookie is present AND still valid (see sessionValid).
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionValid(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthFunc is the same as requireAuth but for HandlerFunc.
func (s *Server) requireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionValid(w, r) {
			return
		}
		next(w, r)
	}
}

// sessionValid gates an authenticated page: the cookie must be present AND the
// daemon must still accept it (validated via Whoami, which runs through the
// auth interceptor). A missing/expired/revoked session clears the cookie and
// redirects to /login, returning false — so an expired session bounces to the
// login screen instead of surfacing a raw "rpc error: session expired" on the
// page. A non-Unauthenticated error (e.g. the daemon is briefly unreachable)
// does NOT lock the user out: we let the handler run and surface its own error,
// which also avoids a redirect loop.
func (s *Server) sessionValid(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}

	// A mutating request is held to the same bar as the equivalent RPC. The UI's
	// write handlers reach the replicated DB in-process rather than through
	// gRPC, so they never passed the operator check the RPC applies
	// (firewall_rules.go) — and this gate, the only one in front of them, looked
	// at the cookie and never at the role. A VIEWER could flip the cluster
	// default firewall policy, delete security-group rules for every VM, and
	// repoint cluster notifications.
	mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions

	who, err := s.grpc.Whoami(s.uiBearerCtx(r), &emptypb.Empty{})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return false
		}
		// Fail OPEN for a read and CLOSED for a write. Letting a read through a
		// brief daemon blip avoids locking an operator out of the dashboard, and
		// that trade is deliberate. Letting a WRITE through means the one
		// component that knows the caller's role is unreachable and the write
		// lands anyway, which is not a trade — it is the check being optional.
		if mutating {
			slog.Warn("ui: refusing a mutation because the caller's role could not be verified",
				"method", r.Method, "path", r.URL.Path, "error", err)
			http.Error(w, "cannot verify your permissions right now; try again shortly",
				http.StatusServiceUnavailable)
			return false
		}
		slog.Warn("ui: session validation hit a transient error; allowing the READ through", "error", err)
		return true
	}

	// A mutation is authorized by the DAEMON, not here. The write handlers now
	// call their gRPC twins, whose RequirePerm consults the token's scope paths
	// and the caller's RBAC bindings — neither of which is visible in the
	// coarse role string this layer can see.
	//
	// What remains here is a cheap early refusal for the one case the coarse
	// role settles on its own: a session with no role at all. It must not be
	// the only check, and it deliberately does NOT refuse a low role, because
	// an external-realm user is shadowed as "viewer" while their real
	// authority comes from a binding the daemon holds.
	if mutating && !selfServiceMutation(r.URL.Path) && who.GetRole() == "" {
		slog.Warn("ui: refusing a mutation from a session with no role",
			"user", who.GetUsername(), "method", r.Method, "path", r.URL.Path)
		http.Error(w, "your credentials do not permit this change", http.StatusForbidden)
		return false
	}
	return true
}

// selfServiceMutation reports whether path is a user acting on their OWN
// credentials.
//
// These carry no authority beyond the session that already authenticated, and
// the handlers behind them scope themselves to the caller. Holding them to the
// cluster-write bar would stop a Viewer changing their own password or
// enrolling a security key -- which is the thing to break, not the thing to
// secure.
//
// path.Clean first: "/account/../ui/firewall/cluster-rules" must not be
// laundered into the exempt set by a prefix match.
func selfServiceMutation(p string) bool {
	switch cleaned := path.Clean(p); {
	case cleaned == "/account/password":
		return true
	case cleaned == "/account/2fa" || strings.HasPrefix(cleaned, "/account/2fa/"):
		return true
	}
	return false
}

// httpStatusFor maps a gRPC error to the HTTP status the page should return.
//
// It exists because the write handlers now call their gRPC twins, so the
// daemon's PermissionDenied has to arrive at the browser as 403 rather than
// being flattened into 500 with the rest. A refusal that reads as a server
// fault sends the operator to the logs instead of to their permissions.
func httpStatusFor(err error) int {
	switch status.Code(err) {
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.InvalidArgument, codes.FailedPrecondition, codes.AlreadyExists:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// uiRoleLevels mirrors the daemon's admin > operator > viewer ordering. It is a
// local copy because internal/grpcapi does not export one; the two must agree,
// and the UI is deliberately the more permissive of the pair only in that it
// never grants more than the RPC behind it would.
var uiRoleLevels = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

// uiRoleAtLeast reports whether role meets minRole. An unknown or empty role
// scores 0, so it never satisfies anything.
func uiRoleAtLeast(role, minRole string) bool {
	return uiRoleLevels[role] >= uiRoleLevels[minRole] && uiRoleLevels[role] > 0
}

// clearSessionCookie expires the session cookie in the browser.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderLoginPage(w, loginPageData{})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	realm := r.FormValue("realm")
	totp := r.FormValue("totp_code")

	resp, err := s.grpc.Login(r.Context(), &pb.LoginRequest{
		Username: username,
		Password: password,
		Realm:    realm,
		TotpCode: totp,
	})
	if err != nil {
		slog.Warn("UI login failed", "username", username, "realm", realm, "error", err)
		s.renderLoginPage(w, loginPageData{
			Username: username, Realm: realm,
			Realms: s.availableRealms(),
			Error:  "Invalid username or password",
		})
		return
	}

	// Two-stage 2FA: server returned no token + Requires_2Fa. Re-render
	// the form with the second-factor input.
	if resp.Requires_2Fa {
		s.renderLoginPage(w, loginPageData{
			Username: username, Realm: realm,
			Realms:      s.availableRealms(),
			Requires2FA: true,
		})
		return
	}

	// MaxAge bounds the browser-side cookie to the session's hard expiry, so a
	// dead session doesn't linger as a usable-looking cookie. Secure is set when
	// the request arrived over TLS (directly or via a terminating proxy) so the
	// bearer isn't sent in cleartext; left off for plain-HTTP/loopback dev so we
	// don't lock those out.
	maxAge := 0
	if exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt); perr == nil {
		if secs := int(time.Until(exp).Seconds()); secs > 0 {
			maxAge = secs
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// requestIsHTTPS reports whether the request reached us over TLS, either
// directly or through a TLS-terminating reverse proxy (X-Forwarded-Proto).
func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Best-effort server-side revoke: forward the bearer cookie via
	// authorization metadata so the daemon can identify the session.
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		ctx := withBearerToken(r.Context(), c.Value)
		_, _ = s.grpc.Logout(ctx, &emptypb.Empty{})
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// loginPageData is rendered into login.html. Only non-empty fields are
// used by the template — we keep the struct stable so adding a new
// challenge type (WebAuthn, push) is one extra field.
type loginPageData struct {
	Username    string
	Realm       string
	Realms      []string
	Error       string
	Requires2FA bool
}

// availableRealms returns the realm names the daemon advertises via
// ListRealms. Hidden when the cluster has only "local" — the dropdown
// would be a single-option no-op. Errors degrade silently to nil so a
// transient daemon hiccup doesn't strand users at the login page.
func (s *Server) availableRealms() []string {
	resp, err := s.grpc.ListRealms(context.Background(), &emptypb.Empty{})
	if err != nil || resp == nil {
		return nil
	}
	if len(resp.Realms) <= 1 {
		return nil
	}
	return resp.Realms
}

func (s *Server) renderLoginPage(w http.ResponseWriter, data loginPageData) {
	t, err := template.New("").ParseFS(templateFS, "templates/login.html")
	if err != nil {
		slog.Error("parse login template", "error", err)
		http.Error(w, "render error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.ExecuteTemplate(w, "login.html", data)
}
