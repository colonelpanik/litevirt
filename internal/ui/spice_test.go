package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestSpiceModalAndVV(t *testing.T) {
	mock := newDefaultMock()
	mock.spiceInfoResp = &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5901, Uri: "spice://10.0.0.5:5901"}
	s := newTestUIServer(t, mock)

	t.Run("modal shows uri + download link", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "spice://10.0.0.5:5901", "5901", "/ui/vms/vm1/spice.vv")
	})

	t.Run("vv file is a virt-viewer connection file", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice.vv")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		for _, want := range []string{"[virt-viewer]", "type=spice", "host=10.0.0.5", "port=5901"} {
			if !strings.Contains(body, want) {
				t.Errorf(".vv missing %q:\n%s", want, body)
			}
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "vm1.vv") {
			t.Errorf("Content-Disposition = %q, want attachment vm1.vv", cd)
		}
	})

	t.Run("modal surfaces unavailable error", func(t *testing.T) {
		em := newDefaultMock()
		em.spiceInfoErr = errSimulated
		es := newTestUIServer(t, em)
		w := serveRequest(es, withAuth(mustReq(t, "GET", "/ui/vms/vm1/spice-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "SPICE console", "only while the VM is running")
	})
}

// TestSpiceCreateToggle: the create modal exposes the enable-SPICE checkbox,
// and the create handler honors it.
func TestSpiceCreateToggle(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/new-modal")))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), `name="enable_spice"`)

	mock := newDefaultMock()
	cs := newTestUIServer(t, mock)
	r := ctPost(t, "/ui/vms", "name=spicevm&image=ubuntu&cpu=2&memory=2048&enable_spice=true")
	cw := serveRequest(cs, withAuth(r))
	assertStatus(t, cw, http.StatusOK)
	if mock.lastCreateVMReq == nil || !mock.lastCreateVMReq.Spec.EnableSpice {
		t.Errorf("create did not set EnableSpice; req=%+v", mock.lastCreateVMReq)
	}
}
