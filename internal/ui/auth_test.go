package ui

import (
	"net/http"
	"strings"
	"testing"
)

func TestAuth_NoCookie_RedirectsToLogin(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := mustReq(t, "GET", "/")
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusFound)
	assertRedirect(t, w, "/login")
}

func TestAuth_ValidCookie_Passes(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAuth_EmptyCookie_RedirectsToLogin(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := mustReq(t, "GET", "/vms")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: ""})
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusFound)
	assertRedirect(t, w, "/login")
}

func TestAuth_LoginPageRenders(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := mustReq(t, "GET", "/login")
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "login")
}

func TestAuth_LoginPage_AlreadyLoggedIn_Redirects(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/login"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusFound)
	assertRedirect(t, w, "/")
}

func TestAuth_LoginSubmit_Success(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("username=admin&password=secret")
	r, _ := http.NewRequest("POST", "/login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusFound)
	assertRedirect(t, w, "/")

	// Session cookie should be set.
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value == "session-token-123" {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
	if mock.lastLoginReq.Username != "admin" {
		t.Errorf("login username = %q, want admin", mock.lastLoginReq.Username)
	}
}

func TestAuth_LoginSubmit_Failure(t *testing.T) {
	mock := newDefaultMock()
	mock.loginErr = errSimulated
	s := newTestUIServer(t, mock)
	body := strings.NewReader("username=admin&password=wrong")
	r, _ := http.NewRequest("POST", "/login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, r)

	// Should re-render login page (200, not redirect).
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Invalid")
}

func TestAuth_Logout(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "POST", "/logout"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusFound)
	assertRedirect(t, w, "/login")

	// Cookie should be cleared (MaxAge = -1).
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			return
		}
	}
	t.Error("expected session cookie to be cleared")
}
