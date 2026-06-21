package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestLBUsesThemedConfirm guards that LB delete/drain use hx-post + hx-confirm
// (themed dialog) rather than the native onsubmit=confirm() that bypassed it.
func TestLBUsesThemedConfirm(t *testing.T) {
	mock := newDefaultMock()
	mock.listLBsResp = &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{{Name: "lb1", State: "active"}}}
	mock.inspectLBResp = &pb.LoadBalancer{
		Name: "lb1", State: "active",
		Backends: []*pb.LBBackend{{VmName: "web-1", Address: "10.0.0.1:80", Status: "active"}},
	}
	s := newTestUIServer(t, mock)

	for _, tc := range []struct{ path, mustHave string }{
		{"/lb", `hx-post="/lb/lb1/delete"`},
		{"/lb/lb1", `hx-post="/lb/lb1/delete"`},
		{"/lb/lb1", `hx-post="/lb/lb1/drain"`},
	} {
		w := serveRequest(s, withAuth(mustReq(t, "GET", tc.path)))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		if !strings.Contains(body, tc.mustHave) {
			t.Errorf("%s missing %q", tc.path, tc.mustHave)
		}
		if strings.Contains(body, "onsubmit=\"return confirm") {
			t.Errorf("%s still uses native confirm()", tc.path)
		}
		if !strings.Contains(body, "hx-confirm=") {
			t.Errorf("%s missing hx-confirm", tc.path)
		}
	}

	// The enable/disable backend buttons must use the backend identifier
	// (vm_name/address), not the nonexistent LBBackend.Name field that used to
	// 500 the page once a backend existed.
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/lb/lb1")))
	if !strings.Contains(w.Body.String(), "/backend/web-1/disable") {
		t.Errorf("enable/disable button missing the backend identifier; body:\n%s", w.Body.String())
	}
}
