package ui

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
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
	if _, err := s.grpc.Whoami(s.uiBearerCtx(r), &emptypb.Empty{}); err != nil {
		if status.Code(err) == codes.Unauthenticated {
			clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return false
		}
		slog.Warn("ui: session validation hit a transient error; allowing through", "error", err)
	}
	return true
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
