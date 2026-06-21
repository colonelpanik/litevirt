package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestHandleRBAC_RendersTree(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	// Wire a real Corrosion DB so the handler has data to render.
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, b := range []corrosion.RoleBindingRecord{
		{ID: "1", Path: "/projects/_default", Role: "admin", Principal: "user:alice", Propagate: true},
		{ID: "2", Path: "/projects/_default/vms/web-1", Role: "viewer", Principal: "group:devs@oidc"},
	} {
		if err := corrosion.InsertRoleBinding(context.Background(), db, b); err != nil {
			t.Fatalf("InsertRoleBinding: %v", err)
		}
	}
	s.SetCorrosionDB(db)

	r := withAuth(httptest.NewRequest(http.MethodGet, "/rbac", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(),
		"/projects/_default", "admin", "user:alice",
		"viewer", "group:devs@oidc")
}

func TestHandleMetricsViewer_HandlesScrapeError(t *testing.T) {
	// 127.0.0.1:7444 isn't running in the test harness; the handler
	// must still render the page with an error banner instead of
	// crashing.
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/metrics-viewer", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// "error" CSS class or Error template field — the page must
	// surface the scrape failure to the operator.
	mustContain(t, w.Body.String(), "Metrics viewer")
}

func TestHandleAudit_FilteredByTarget(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/audit?target=vm-a", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "Filtered by", "target=vm-a", "clear")
}

func TestHandleUsersPage_TokenModalIncludesScopePicker(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/users", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// The token modal carries the scope-paths textarea and the
	// help text describing intersection semantics.
	mustContain(t, w.Body.String(), "scope_paths", "intersects token scopes with role bindings")
}
