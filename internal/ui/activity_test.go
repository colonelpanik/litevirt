package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestEventsPage asserts the unified /events page seeds the cluster-wide
// history table (durable vm_events, empty vm_name) that the live SSE tail then
// prepends onto.
func TestEventsPage(t *testing.T) {
	mock := newDefaultMock()
	mock.vmEventsResp = &pb.ListVMEventsResponse{Events: []*pb.VMEvent{
		{Type: "vm.started", VmName: "web-1", HostName: "host-a", Result: "ok", Username: "admin", Ts: "2026-06-08T07:00:00Z"},
		{Type: "backup.failed", VmName: "db-1", HostName: "host-b", Result: "error", Ts: "2026-06-08T06:59:00Z"},
	}}
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(mustReq(t, "GET", "/events")))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	mustContain(t, body, "Events", "vm.started", "backup.failed", "web-1", "host-b")

	// The page seeds from cluster-wide events (empty vm_name).
	if mock.lastVMEventsReq == nil || mock.lastVMEventsReq.VmName != "" {
		t.Errorf("events should query cluster-wide (empty vm_name); got %+v", mock.lastVMEventsReq)
	}
}

// TestActivityRedirect asserts the former /activity page redirects to the
// unified /events page (back-compat for old bookmarks / cross-links).
func TestActivityRedirect(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/activity?limit=50")))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != "/events?limit=50" {
		t.Errorf("redirect Location = %q, want /events?limit=50", loc)
	}
}
