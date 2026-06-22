package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestDashboardRecentEvents asserts the dashboard's "Recent Events" panel is
// sourced from the durable, cluster-wide vm_events store (via ListVMEvents) —
// not the never-populated ClusterStatus.RecentEvents field, which left the panel
// permanently empty even when VMs had events.
func TestDashboardRecentEvents(t *testing.T) {
	mock := newDefaultMock()
	mock.vmEventsResp = &pb.ListVMEventsResponse{Events: []*pb.VMEvent{
		{Type: "vm.started", VmName: "web-1", HostName: "host-a", Result: "ok", Ts: "2026-06-08T07:00:00Z"},
		{Type: "backup.failed", VmName: "db-1", HostName: "host-b", Result: "error", Ts: "2026-06-08T06:59:00Z"},
	}}
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(mustReq(t, "GET", "/")))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	// The durable events must render in the dashboard panel.
	mustContain(t, body, "Recent Events", "vm.started", "web-1", "backup.failed")

	// And it must query the durable store cluster-wide (empty vm_name).
	if mock.lastVMEventsReq == nil {
		t.Fatal("dashboard did not call ListVMEvents — panel still uses the empty ClusterStatus.RecentEvents")
	}
	if mock.lastVMEventsReq.VmName != "" {
		t.Errorf("dashboard events should be cluster-wide (empty vm_name); got %q", mock.lastVMEventsReq.VmName)
	}
}
