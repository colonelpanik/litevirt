package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestBulkVMs_BulkNamesField proves the real toolbar contract: the bulk bar
// posts the hidden input `bulk_names` (not `names`), so the handler must read
// it. Before the fix this returned "no VMs selected".
func TestBulkVMs_BulkNamesField(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	form := url.Values{"action": {"start"}, "bulk_names": {"vm1,vm2"}}.Encode()
	w := serveRequest(s, bulkPost(t, "/ui/vms/bulk", form))
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Refresh"); got != "true" {
		t.Errorf("HX-Refresh = %q, want true (bulk_names should have been read)", got)
	}
}

// TestVMsBulkBarContract guards the field-name contract: the rendered toolbar's
// hidden input + hx-include selector must match what the handler reads.
func TestVMsBulkBarContract(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms")))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{`name="bulk_names"`, `hx-include="[name=bulk_names]"`} {
		if !strings.Contains(body, want) {
			t.Errorf("VMs bulk bar missing %q — handler reads bulk_names", want)
		}
	}
}

// TestBulkContainers covers start/stop/delete over host/name keys.
func TestBulkContainers(t *testing.T) {
	t.Run("happy path refreshes", func(t *testing.T) {
		s := newTestUIServer(t, newDefaultMock())
		form := url.Values{"action": {"stop"}, "bulk_names": {"host-a/ct-1,host-b/ct-2"}}.Encode()
		w := serveRequest(s, bulkPost(t, "/ui/containers/bulk", form))
		assertStatus(t, w, http.StatusOK)
		if got := w.Header().Get("HX-Refresh"); got != "true" {
			t.Errorf("HX-Refresh = %q, want true", got)
		}
	})

	t.Run("none selected warns", func(t *testing.T) {
		s := newTestUIServer(t, newDefaultMock())
		form := url.Values{"action": {"delete"}}.Encode()
		w := serveRequest(s, bulkPost(t, "/ui/containers/bulk", form))
		assertStatus(t, w, http.StatusOK)
		if w.Header().Get("HX-Refresh") == "true" {
			t.Error("empty selection should not refresh")
		}
	})

	t.Run("bulk bar + checkboxes render", func(t *testing.T) {
		mock := newDefaultMock()
		mock.listContainersResp = &pb.ListContainersResponse{Containers: []*pb.Container{{
			HostName: "host-a", Name: "ct-1", State: "running",
		}}}
		s := newTestUIServer(t, mock)
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/containers")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		for _, want := range []string{`data-bulk-table`, `data-bulk-name="host-a/ct-1"`, `/ui/containers/bulk`, `data-bulk-master`} {
			if !strings.Contains(body, want) {
				t.Errorf("containers page missing bulk markup %q", want)
			}
		}
	})
}
