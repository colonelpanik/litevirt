package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCSRFGuard exercises the cross-site request policy (WS6 CSRF).
func TestCSRFGuard(t *testing.T) {
	s := &Server{wsOriginPatterns: []string{"proxy.corp"}}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	h := s.csrfGuard(http.HandlerFunc(ok))

	type tc struct {
		desc        string
		method      string
		secFetch    string
		origin      string
		host        string
		wantBlocked bool
	}
	for _, c := range []tc{
		{"GET never blocked", "GET", "cross-site", "https://evil.com", "ui.local", false},
		{"POST same-origin", "POST", "same-origin", "", "ui.local", false},
		{"POST same-site", "POST", "same-site", "", "ui.local", false},
		{"POST none (bookmark)", "POST", "none", "", "ui.local", false},
		{"POST cross-site → blocked", "POST", "cross-site", "https://evil.com", "ui.local", true},
		{"DELETE cross-site → blocked", "DELETE", "cross-site", "", "ui.local", true},
		{"POST no-sfs, no-origin (curl) allowed", "POST", "", "", "ui.local", false},
		{"POST no-sfs, matching origin allowed", "POST", "", "https://ui.local", "ui.local", false},
		{"POST no-sfs, foreign origin blocked", "POST", "", "https://evil.com", "ui.local", true},
		{"POST no-sfs, allowlisted proxy origin", "POST", "", "https://proxy.corp", "ui.local", false},
	} {
		req := httptest.NewRequest(c.method, "http://"+c.host+"/x", nil)
		req.Host = c.host
		if c.secFetch != "" {
			req.Header.Set("Sec-Fetch-Site", c.secFetch)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		blocked := rr.Code == http.StatusForbidden
		if blocked != c.wantBlocked {
			t.Errorf("%s: blocked=%v want %v (code=%d)", c.desc, blocked, c.wantBlocked, rr.Code)
		}
	}
}
