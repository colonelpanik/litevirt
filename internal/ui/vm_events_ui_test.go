package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestVMDetail_ActivityTimeline asserts the VM detail page renders the per-VM
// Activity section, surfacing a failed backup (the motivating case) with an
// error badge.
func TestVMDetail_ActivityTimeline(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectVMResp = &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1", Spec: &pb.VMSpec{}}
	mock.vmEventsResp = &pb.ListVMEventsResponse{Events: []*pb.VMEvent{
		{VmName: "vm1", Type: "backup.failed", Result: "error", HostName: "host1", Detail: "disk gone", Ts: "2026-06-06T10:00:00Z"},
		{VmName: "vm1", Type: "vm.started", Result: "ok", HostName: "host1", Ts: "2026-06-06T09:00:00Z"},
	}}
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Activity")
	assertContains(t, w, "backup.failed")
	assertContains(t, w, "disk gone")
}
