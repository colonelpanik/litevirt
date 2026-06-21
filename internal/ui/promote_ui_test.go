package ui

import (
	"net/http"
	"strings"
	"testing"
)

func TestHandler_PromoteModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/promote-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Promote replica") {
		t.Error("promote modal should render")
	}
}

func TestHandler_PromoteReplica_Redirects(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/promote", strings.NewReader("new_name=vm1-dr&force=on"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, withAuth(r))
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/vms/vm1-dr" {
		t.Errorf("HX-Redirect = %q, want /vms/vm1-dr", got)
	}
	if mock.lastPromoteReq == nil || mock.lastPromoteReq.VmName != "vm1" || mock.lastPromoteReq.NewName != "vm1-dr" || !mock.lastPromoteReq.Force {
		t.Errorf("promote req not forwarded correctly: %+v", mock.lastPromoteReq)
	}
}

func TestHandler_PromoteReplica_TakeoverNoNewName(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/promote", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, withAuth(r))
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/vms/vm1" {
		t.Errorf("HX-Redirect = %q, want /vms/vm1 (takeover)", got)
	}
}
