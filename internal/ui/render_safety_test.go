package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDeleteVMSurfacesError verifies a failed delete (e.g. linked-clone guard,
// RBAC) is reported instead of falsely redirecting to /vms as success.
func TestDeleteVMSurfacesError(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteVMErr = errSimulated
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/vms/vm1")))
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "" {
		t.Errorf("HX-Redirect = %q, want empty (delete failed, must not redirect as success)", got)
	}
}

// TestDeleteVMSuccessRedirects verifies the happy path still redirects to /vms.
func TestDeleteVMSuccessRedirects(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/vms/vm1")))
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/vms" {
		t.Errorf("HX-Redirect = %q, want /vms", got)
	}
}

// TestRenderFragmentErrorIsVisible verifies a render failure produces a visible
// error fragment (so htmx swaps it in) rather than a blank region. Triggered by
// passing data of the wrong shape so ExecuteTemplate fails mid-render.
func TestRenderFragmentErrorIsVisible(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := httptest.NewRecorder()
	// exec_output.html dereferences fields like .ExitCode; an int has none, so
	// ExecuteTemplate errors.
	s.renderFragment(w, "exec_output.html", 42)
	if !strings.Contains(w.Body.String(), "went wrong") {
		t.Errorf("expected visible render-error fragment, got: %q", w.Body.String())
	}
}
