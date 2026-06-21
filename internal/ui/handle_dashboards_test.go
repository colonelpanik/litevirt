package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleDashboards_ListsBundledFiles(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/dashboards", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Each bundled dashboard's UID should appear in the rendered
	// page so operators can identify them.
	for _, uid := range []string{
		"litevirt-cluster-overview",
		"litevirt-vm-io",
		"litevirt-placement",
		"litevirt-clustering-health",
	} {
		if !contains(body, uid) {
			t.Errorf("dashboards page missing UID %q", uid)
		}
	}
	// Download links should target /static/grafana/*.json.
	if !contains(body, "/static/grafana/cluster-overview.json") {
		t.Errorf("dashboards page missing download link for cluster-overview.json")
	}
}

func TestListGrafanaDashboards_ParsesMetadata(t *testing.T) {
	entries, err := listGrafanaDashboards()
	if err != nil {
		t.Fatalf("listGrafanaDashboards: %v", err)
	}
	if len(entries) < 4 {
		t.Fatalf("expected ≥4 bundled dashboards, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Title == "" || e.UID == "" {
			t.Errorf("dashboard %q missing title/uid: %+v", e.Filename, e)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
