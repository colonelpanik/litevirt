package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleAccount2FA_RendersPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/account/2fa", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, needle := range []string{
		"Two-factor authentication",
		"Register security key",
		"webauthn-register-btn",
		"navigator.credentials.create",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("expected %q in body", needle)
		}
	}
}

func TestHandleAccount2FA_ShowsPasswordFormForLocalRealm(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock()) // mock Whoami returns realm "local"
	r := withAuth(httptest.NewRequest(http.MethodGet, "/account/2fa", nil))
	w := serveRequest(s, r)
	body := w.Body.String()
	for _, needle := range []string{"Change password", `action="/account/password"`, "new_password"} {
		if !strings.Contains(body, needle) {
			t.Errorf("local realm: expected %q in body (change-password form should show)", needle)
		}
	}
}

func TestHandleAccountPassword_SuccessAndMismatch(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())

	// Matching new+confirm → ChangePassword (mock OK) → success flash.
	r := withAuth(httptest.NewRequest(http.MethodPost, "/account/password",
		strings.NewReader("old_password=old&new_password=newpass12&confirm_password=newpass12")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Password changed") {
		t.Errorf("success: code=%d body=%s", w.Code, w.Body.String())
	}

	// Mismatched confirmation → rejected before any RPC.
	r2 := withAuth(httptest.NewRequest(http.MethodPost, "/account/password",
		strings.NewReader("old_password=old&new_password=a&confirm_password=b")))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := serveRequest(s, r2)
	if !strings.Contains(w2.Body.String(), "do not match") {
		t.Errorf("mismatch: expected error flash; body=%s", w2.Body.String())
	}
}

// TestHandleWebAuthnBegin_ProxiesJSON confirms the begin endpoint
// returns the daemon's options blob verbatim — the JS layer feeds it
// straight to navigator.credentials.create, so any rewriting here
// would break the WebAuthn dance.
func TestHandleWebAuthnBegin_ProxiesJSON(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodPost, "/account/2fa/webauthn/begin", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	// The mock returns `{"publicKey":{}}`; confirm that comes back unmodified.
	if w.Body.String() != `{"publicKey":{}}` {
		t.Errorf("body = %q, want exact passthrough", w.Body.String())
	}
}

// TestHandleWebAuthnFinish_ReturnsLabel posts a dummy attestation and
// confirms the JSON response surfaces the daemon's credential_label.
func TestHandleWebAuthnFinish_ReturnsLabel(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodPost, "/account/2fa/webauthn/finish",
		strings.NewReader(`{"dummy":"attestation"}`)))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var out struct {
		OK              bool   `json:"ok"`
		CredentialLabel string `json:"credential_label"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK || out.CredentialLabel != "test-label" {
		t.Fatalf("response = %+v", out)
	}
}
