package ui

import (
	"net/http"
	"testing"
)

// TestCreateVMISOBoot: the create modal exposes the installer-ISO + boot
// fields, and the handler forwards them into the spec.
func TestCreateVMISOBoot(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/new-modal")))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), `name="iso"`, `name="boot"`, "blank disk")

	mock := newDefaultMock()
	cs := newTestUIServer(t, mock)
	r := ctPost(t, "/ui/vms", "name=isovm&image=&cpu=2&memory=2048&disk=20G&iso=/isos/debian.iso&boot=cdrom")
	cw := serveRequest(cs, withAuth(r))
	assertStatus(t, cw, http.StatusOK)
	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM not called")
	}
	if got := mock.lastCreateVMReq.Spec.Iso; got != "/isos/debian.iso" {
		t.Errorf("spec.Iso = %q, want /isos/debian.iso", got)
	}
	if got := mock.lastCreateVMReq.Spec.Boot; got != "cdrom" {
		t.Errorf("spec.Boot = %q, want cdrom", got)
	}
}
