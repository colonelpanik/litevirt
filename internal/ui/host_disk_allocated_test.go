package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The hosts list and host detail pages show declared allocation beside actual
// usage. Since colonelpanik/litevirt#142, pb.Host.disk_used_gib is statfs usage
// and allocation travels in disk_allocated_gib — so a template still reading
// DiskUsedGib labels USAGE as "alloc"/"committed", and the allocation the
// operator wanted (a same-host pool move frees real space but changes none of
// it) silently disappears.
func TestHostPages_ShowAllocationFromItsOwnField(t *testing.T) {
	host := &pb.Host{
		Name: "host1", State: pb.HostState_HOST_ACTIVE,
		DiskTotalGib: 100, DiskUsedGib: 27, DiskAllocatedGib: 98,
	}
	mock := newDefaultMock()
	mock.inspectHostResp = host
	mock.listHostsResp = &pb.ListHostsResponse{Hosts: []*pb.Host{host}}
	s := newTestUIServer(t, mock)

	for path, want := range map[string]string{
		"/hosts":       "98G alloc",
		"/hosts/host1": "98G committed",
	} {
		w := serveRequest(s, withAuth(httptest.NewRequest("GET", path, nil)))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, want) {
			t.Errorf("GET %s: missing %q — allocation must come from disk_allocated_gib", path, want)
		}
		if bad := strings.Replace(want, "98", "27", 1); strings.Contains(body, bad) {
			t.Errorf("GET %s: renders %q — statfs usage labelled as allocation", path, bad)
		}
	}
}
