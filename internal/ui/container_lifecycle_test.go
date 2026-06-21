package ui

import (
	"net/http"
	"strings"
	"testing"
)

// ctPost builds an x-www-form-urlencoded POST request.
func ctPost(t *testing.T, path, form string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", path, strings.NewReader(form))
	if err != nil {
		t.Fatalf("NewRequest %s: %v", path, err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestContainerLifecycleUI exercises the create modal, create POST, and the
// start/stop/delete/exec action endpoints wired in this MR.
func TestContainerLifecycleUI(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())

	t.Run("create modal renders form", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/containers/new-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "Create Container", `name="distro"`, `name="release"`, `hx-post="/ui/containers"`)
	})

	t.Run("create posts and redirects", func(t *testing.T) {
		w := serveRequest(s, withAuth(ctPost(t, "/ui/containers", "host=host-a&name=alpine-1&distro=alpine&release=3.19&arch=amd64&cpu=0&memory=0")))
		assertStatus(t, w, http.StatusOK)
		if got := w.Header().Get("HX-Redirect"); got != "/containers" {
			t.Errorf("expected HX-Redirect to /containers, got %q", got)
		}
	})

	t.Run("start returns table", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/containers/host-a/ct-1/start")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "All Containers")
	})

	t.Run("stop returns table", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/containers/host-a/ct-1/stop")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "All Containers")
	})

	t.Run("delete returns table", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/containers/host-a/ct-1")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "All Containers")
	})

	t.Run("exec modal renders", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/containers/host-a/ct-1/exec-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "Execute Command", `hx-post="/ui/containers/host-a/ct-1/exec"`)
	})

	t.Run("exec returns output", func(t *testing.T) {
		w := serveRequest(s, withAuth(ctPost(t, "/ui/containers/host-a/ct-1/exec", "command=uname -a")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "exit:")
	})
}
