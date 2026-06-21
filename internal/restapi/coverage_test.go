package restapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Confirm every new coverage route is wired (no 404), auth-protected
// (no 401 with a token), and rejects the wrong method (405). Hits the
// same shallow contract the parity routes use — deeper success paths
// need a working backend, which the in-tree mock doesn't fully
// implement for streaming.
func TestCoverage_RoutesRegistered(t *testing.T) {
	s := &Server{token: "t", mux: http.NewServeMux()}
	s.registerRoutes()

	cases := []struct {
		path   string
		method string
	}{
		{"/api/v1/stacks/deploy", http.MethodGet},
		{"/api/v1/stacks/delete", http.MethodGet},
		{"/api/v1/stacks/export", http.MethodPut},
		{"/api/v1/containers/create", http.MethodGet},
		{"/api/v1/containers/start", http.MethodGet},
		{"/api/v1/containers/stop", http.MethodGet},
		{"/api/v1/containers/delete", http.MethodGet},
		{"/api/v1/containers/exec", http.MethodGet},
		{"/api/v1/containers/pull", http.MethodGet},
		{"/api/v1/realms", http.MethodDelete},
		{"/api/v1/sessions", http.MethodPatch},
		{"/api/v1/services", http.MethodPatch},
		{"/api/v1/vms/bind-sgs", http.MethodGet},
		{"/api/v1/vms/move-volume", http.MethodGet},
		{"/api/v1/vms/replicate-volume", http.MethodGet},
		{"/api/v1/backup/snapshot", http.MethodGet},
		{"/api/v1/backup/restore", http.MethodGet},
		{"/api/v1/hosts/preflight-upgrade", http.MethodGet},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s → 404 (route not registered)", tc.method, tc.path)
		}
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s %s → 401 (auth wrapping missing)", tc.method, tc.path)
		}
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s → %d, want 405", tc.method, tc.path, rec.Code)
		}
	}
}

func TestCoverage_SessionPathRequiresID(t *testing.T) {
	s := &Server{token: "t", mux: http.NewServeMux()}
	s.registerRoutes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session id, got %d", rec.Code)
	}
}
