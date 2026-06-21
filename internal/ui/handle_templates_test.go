package ui

import (
	"net/http"
	"strings"
	"testing"
)

func TestHandler_CloneModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/clone-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Clone") {
		t.Error("clone modal should render a Clone form")
	}
}

func TestHandler_CloneVM(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/clone", strings.NewReader("target=vm1-clone&mode=full"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/vms/vm1-clone" {
		t.Errorf("HX-Redirect = %q, want /vms/vm1-clone", got)
	}
}

func TestHandler_CloneVM_RequiresName(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/clone", strings.NewReader("target="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestHandler_ConvertTemplate(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/template", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/vms/vm1" {
		t.Errorf("HX-Redirect = %q, want /vms/vm1", got)
	}
}
