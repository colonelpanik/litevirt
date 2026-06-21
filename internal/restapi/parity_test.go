package restapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parity routes: confirm registration + auth + method
// dispatch. The legacy server_test.go pattern (auth + 405 for wrong
// methods) gives us the cheapest end-to-end check that doesn't need a
// real gRPC backend.

func TestParity_RoutesRegistered(t *testing.T) {
	s := &Server{token: "t", mux: http.NewServeMux()}
	s.registerRoutes()

	// Each entry: path + method that should *not* be 401 (i.e., the
	// route is wired and auth passes), and the expected non-OK status
	// — usually 405 for the wrong method or 500 from the unwired
	// gRPC client. We just want to prove "no 404 / no 401".
	cases := []struct {
		path   string
		method string
	}{
		{"/api/v1/rebalance/proposals", http.MethodDelete},          // wrong method → 405
		{"/api/v1/rebalance/proposals/abc/approve", http.MethodGet}, // wrong method → 405
		{"/api/v1/rebalance/run", http.MethodGet},
		{"/api/v1/2fa", http.MethodPatch},
		{"/api/v1/2fa/totp/enroll", http.MethodGet},
		{"/api/v1/containers", http.MethodPost},
		{"/api/v1/firewall/reload", http.MethodGet},
		{"/api/v1/regions", http.MethodPost},
		// third-pass parity: audit chain, storage pools, region list/migrate.
		{"/api/v1/audit/verify", http.MethodGet},    // POST only
		{"/api/v1/audit/export", http.MethodPost},   // GET only
		{"/api/v1/pools", http.MethodDelete},        // GET or POST
		{"/api/v1/pools/foo", http.MethodPut},       // GET or DELETE
		{"/api/v1/regions/list", http.MethodPost},   // GET only
		{"/api/v1/regions/migrate", http.MethodGet}, // POST only
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
			t.Errorf("%s %s → %d, want 405 (method check)", tc.method, tc.path, rec.Code)
		}
	}
}

func TestParity_RebalanceProposal_BadShape(t *testing.T) {
	s := &Server{token: "t", mux: http.NewServeMux()}
	s.registerRoutes()
	// Missing action segment.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rebalance/proposals/abc", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing action, got %d body=%q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

func TestParity_RebalanceProposal_UnknownAction(t *testing.T) {
	s := &Server{token: "t", mux: http.NewServeMux()}
	s.registerRoutes()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rebalance/proposals/abc/eat", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown action, got %d body=%q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
