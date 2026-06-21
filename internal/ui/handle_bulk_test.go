package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func bulkPost(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withAuth(r)
}

// TestBulkVMs_StartAllSucceeds verifies the happy path: every VM starts;
// no partial-failure dialog rendered.
func TestBulkVMs_StartAllSucceeds(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	form := url.Values{
		"action": {"start"},
		"names":  {"vm1,vm2,vm3"},
	}.Encode()
	r := bulkPost(t, "/ui/vms/bulk", form)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Refresh"); got != "true" {
		t.Errorf("HX-Refresh = %q, want true (no partial failure)", got)
	}
	if strings.Contains(w.Body.String(), "partial failure") {
		t.Error("body contains 'partial failure' for fully-successful bulk")
	}
}

// TestBulkVMs_PartialFailureRendersDialog verifies that when at least one
// VM fails, we render the partial-failure dialog instead of HX-Refresh.
func TestBulkVMs_PartialFailureRendersDialog(t *testing.T) {
	mock := newDefaultMock()
	mock.startVMErr = errSimulated // every StartVM call fails
	s := newTestUIServer(t, mock)

	form := url.Values{
		"action": {"start"},
		"names":  {"vm1,vm2"},
	}.Encode()
	r := bulkPost(t, "/ui/vms/bulk", form)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Refresh"); got == "true" {
		t.Error("HX-Refresh=true on partial failure; expected dialog instead")
	}
	body := w.Body.String()
	if !strings.Contains(body, "partial failure") {
		t.Errorf("missing partial-failure dialog:\n%s", body)
	}
}

// TestBulkVMs_RejectsUnknownAction verifies invalid actions are rejected.
func TestBulkVMs_RejectsUnknownAction(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	form := url.Values{"action": {"explode"}, "names": {"vm1"}}.Encode()
	r := bulkPost(t, "/ui/vms/bulk", form)
	w := serveRequest(s, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid action", w.Code)
	}
}

// TestBulkVMs_EmptyNamesIsNoop verifies that an empty selection toasts but
// returns OK rather than failing.
func TestBulkVMs_EmptyNamesIsNoop(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	form := url.Values{"action": {"start"}, "names": {""}}.Encode()
	r := bulkPost(t, "/ui/vms/bulk", form)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// TestBulkHosts_DrainAllSucceeds verifies the host-bulk path.
func TestBulkHosts_DrainAllSucceeds(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	form := url.Values{"action": {"drain"}, "names": {"host1,host2"}}.Encode()
	r := bulkPost(t, "/ui/hosts/bulk", form)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// TestBulkVMs_VMsPageRendersBulkBar verifies the bulk toolbar markup is
// present on the VM list page (so the JS has something to wire up).
func TestBulkVMs_VMsPageRendersBulkBar(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/vms"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	for _, want := range []string{
		`data-bulk-table`,
		`data-bulk-toolbar`,
		`/ui/vms/bulk`,
		`bulk-check`,
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("VMs page missing %q in body", want)
		}
	}
}

func TestBulkHosts_HostsPageRendersBulkBar(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/hosts"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	for _, want := range []string{
		`data-bulk-table`,
		`/ui/hosts/bulk`,
		`bulk-check`,
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("Hosts page missing %q in body", want)
		}
	}
}
