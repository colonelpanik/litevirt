package ui

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// UI handlers — /account/2fa shows the caller's enrolled
// second factors and offers a "Register security key" button that
// drives navigator.credentials.create against the daemon.
//
// The page itself only renders the list; the registration dance is
// pure JS calling the two POST endpoints (begin → finish) below. We
// keep the JSON shape opaque-bytes through the browser so the daemon
// stays the only place that parses go-webauthn's structures.

func (s *Server) handleAccount2FA(w http.ResponseWriter, r *http.Request) {
	s.renderAccountPage(w, r, nil)
}

// renderAccountPage loads the account page (enrolled factors) and merges any
// extra fields (e.g. a password-change flash) before rendering. Shared by the
// 2FA view and the change-password POST handler.
func (s *Server) renderAccountPage(w http.ResponseWriter, r *http.Request, extra map[string]any) {
	ctx := s.uiBearerCtx(r)
	data := s.pageData("Account · 2FA", "account")
	if resp, err := s.grpc.ListTwoFactors(ctx, &pb.ListTwoFactorsRequest{}); err != nil {
		data["Error"] = err.Error()
	} else {
		data["Factors"] = resp.Factors
	}
	// Only local-realm accounts have a password to change here; OIDC/LDAP
	// users are managed at their identity provider, so hide the form for them.
	// Default false (form hidden) if we can't determine the realm — fail closed.
	if who, err := s.grpc.Whoami(ctx, &emptypb.Empty{}); err == nil {
		data["Realm"] = who.Realm
		data["CanChangePassword"] = who.Realm == "local"
	}
	for k, v := range extra {
		data[k] = v
	}
	s.renderPage(w, "account_2fa.html", data)
}

// handleAccountPassword lets the logged-in user change their own local-realm
// password from the web UI. The session bearer is forwarded (uiBearerCtx), so
// the daemon verifies the old password and authorizes the change as the caller.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderAccountPage(w, r, map[string]any{"PwError": "Could not read the form."})
		return
	}
	newPw := r.FormValue("new_password")
	if newPw == "" || newPw != r.FormValue("confirm_password") {
		s.renderAccountPage(w, r, map[string]any{"PwError": "New password and confirmation do not match."})
		return
	}
	_, err := s.grpc.ChangePassword(s.uiBearerCtx(r), &pb.ChangePasswordRequest{
		OldPassword: r.FormValue("old_password"),
		NewPassword: newPw,
	})
	if err != nil {
		msg := err.Error()
		if st, ok := status.FromError(err); ok {
			msg = st.Message()
		}
		s.renderAccountPage(w, r, map[string]any{"PwError": msg})
		return
	}
	s.renderAccountPage(w, r, map[string]any{"PwSuccess": "Password changed."})
}

// handleWebAuthnBegin proxies the begin-registration call. The browser
// passed Accept: application/json so we return the daemon's options
// blob verbatim — the JS feeds it into navigator.credentials.create
// without parsing.
func (s *Server) handleWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	resp, err := s.grpc.BeginWebAuthnRegistration(ctx, &pb.BeginWebAuthnRegistrationRequest{})
	if err != nil {
		writeWebAuthnError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp.OptionsJson)
}

// handleWebAuthnFinish posts the browser's attestation blob to the
// daemon. The browser's CredentialResponse.JSON() output is sent
// raw — go-webauthn's parser is the only thing that should touch it.
func (s *Server) handleWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	ctx := s.uiBearerCtx(r)
	resp, err := s.grpc.FinishWebAuthnRegistration(ctx, &pb.FinishWebAuthnRegistrationRequest{
		AttestationJson: body,
	})
	if err != nil {
		writeWebAuthnError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"credential_label": resp.CredentialLabel,
	})
}

// uiBearerCtx pulls the session cookie + attaches it as a Bearer
// header on the outgoing gRPC call so the daemon's auth interceptor
// can identify the caller. requireAuthFunc already guarantees the
// cookie is present, so a missing cookie here is a programming error.
func (s *Server) uiBearerCtx(r *http.Request) context.Context {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return withBearerToken(r.Context(), c.Value)
	}
	slog.Error("uiBearerCtx invoked outside requireAuth")
	return r.Context()
}

// writeWebAuthnError translates a gRPC error to an HTTP response with
// the status code the JS layer reads back, plus a JSON error body.
func writeWebAuthnError(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if st, ok := status.FromError(err); ok {
		switch st.Code().String() {
		case "Unauthenticated":
			code = http.StatusUnauthorized
		case "Unimplemented":
			code = http.StatusServiceUnavailable
		case "PermissionDenied":
			code = http.StatusForbidden
		case "Internal":
			code = http.StatusInternalServerError
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": err.Error(),
	})
}
