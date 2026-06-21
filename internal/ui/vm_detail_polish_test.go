package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestVMDetailPolish locks in the grouped action bar + auto-fit overview cards.
func TestVMDetailPolish(t *testing.T) {
	t.Run("running VM: stop/console primary, rest in overflow menu", func(t *testing.T) {
		mock := newDefaultMock()
		mock.inspectVMResp = &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1", Spec: &pb.VMSpec{Image: "ubuntu-22.04"}}
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		// Layout scaffolding.
		mustContain(t, body, `class="card-grid"`, "IP Address", `class="menu"`, "menu-list", "action-sep")
		// Primary lifecycle for a running VM.
		mustContain(t, body, "/ui/vms/vm1/stop", "/ui/vms/vm1/restart", "/ui/vms/vm1/console-modal")
		// Secondary actions still present (folded into the menu).
		mustContain(t, body, "/ui/vms/vm1/migrate-modal", "/ui/vms/vm1/edit-modal", "Delete")
		if strings.Contains(body, "/ui/vms/vm1/start") {
			t.Error("running VM should not offer Start")
		}
	})

	t.Run("stopped VM: Start is primary", func(t *testing.T) {
		mock := newDefaultMock()
		mock.inspectVMResp = &pb.VM{Name: "vm1", State: pb.VMState_VM_STOPPED, HostName: "host1"}
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		mustContain(t, body, "/ui/vms/vm1/start", "Convert to template")
		if strings.Contains(body, "/ui/vms/vm1/stop") {
			t.Error("stopped VM should not offer Stop")
		}
	})
}
