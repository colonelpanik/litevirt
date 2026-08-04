package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The panel's whole design is plan-then-confirm: intent edits change nothing,
// the plan modal fronts the server-side refusals, and the apply carries the
// written force confirmation. These tests pin the UI half of that contract.

func TestHostDetailRendersNetworkPanel(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectHostResp = &pb.Host{Name: "host1", State: pb.HostState_HOST_ACTIVE}
	mock.listHostNetworksResp = &pb.ListHostNetworksResponse{Networks: []*pb.HostNetwork{
		{HostName: "host1", Name: "vmbr0", Kind: "bridge", Members: []string{"eth1"}, State: "applied", Generation: 2},
		{HostName: "host1", Name: "bond0", Kind: "bond", State: "rolled_back", LastError: "gateway unreachable"},
	}}
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(httptest.NewRequest("GET", "/hosts/host1", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("host detail: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Host Network Configuration", "vmbr0", "rolled back", "gateway unreachable",
		"network-plan-modal", // the Plan & Apply entry point must exist
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host detail missing %q", want)
		}
	}
}

func TestHostNetworkSavePostsIntent(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)

	form := url.Values{
		"iface": {"vmbr0"}, "kind": {"bridge"}, "members": {"eth1, eth2"},
		"addresses": {"10.0.10.2/24"}, "gateway": {"10.0.10.1"}, "mtu": {"9000"},
	}
	r := httptest.NewRequest("POST", "/ui/hosts/host1/network", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveRequest(s, withAuth(r))
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	got := mock.lastUpsertHostNetwork.GetNetwork()
	if got.HostName != "host1" || got.Name != "vmbr0" || got.Kind != "bridge" ||
		len(got.Members) != 2 || got.Mtu != 9000 {
		t.Fatalf("upsert request: %+v", got)
	}
	if !strings.Contains(got.Addressing, "10.0.10.1") {
		t.Fatalf("addressing blob missing gateway: %q", got.Addressing)
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Fatal("a recorded intent must refresh the page")
	}
}

func TestHostNetworkPlanModalFrontsTheCutoff(t *testing.T) {
	mock := newDefaultMock()
	mock.planHostNetworkResp = &pb.PlanHostNetworkResponse{
		Rendered:         "network:\n  version: 2\n",
		CutoffReason:     "intent \"vmbr0\" enslaves the cluster-LAN interface net1",
		ClusterInterface: "net1",
	}
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(httptest.NewRequest("GET", "/ui/hosts/host1/network-plan-modal", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("plan modal: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Cutoff risk") || !strings.Contains(body, "force_interface") {
		t.Fatalf("the plan modal must front the cutoff and its written confirmation, got: %.300s", body)
	}

	// And the apply carries the typed confirmation through.
	form := url.Values{"force_interface": {"net1"}}
	r := httptest.NewRequest("POST", "/ui/hosts/host1/network-apply", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = serveRequest(s, withAuth(r))
	if w.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	if mock.lastApplyHostNetwork.GetForceInterface() != "net1" {
		t.Fatalf("force confirmation not carried: %+v", mock.lastApplyHostNetwork)
	}
}

func TestHostNetworkDeleteIsTwoStep(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)

	w := serveRequest(s, withAuth(httptest.NewRequest("DELETE", "/ui/hosts/host1/network/vmbr0", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	if mock.lastDeleteHostNetwork.GetName() != "vmbr0" || mock.lastDeleteHostNetwork.GetHostName() != "host1" {
		t.Fatalf("delete request: %+v", mock.lastDeleteHostNetwork)
	}
}
