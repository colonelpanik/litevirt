package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The resource-mapping pages' create, add-device and remove-device actions
// wrote the host's database in-process, with no authorization beyond holding
// a session with some role: a Viewer could repoint which host PCI device a
// mapping hands a VM. The RPCs `lv mapping` calls require resourcemap.write.
// The pages now call those RPCs, so they are held to the same check.

func TestUIResourceMappings_ViewerRefused(t *testing.T) {
	cases := map[string]func(t *testing.T) (*Server, *corrosion.Client){
		"bound Viewer":  func(t *testing.T) (*Server, *corrosion.Client) { return newUIBoundTo(t, "vic", "Viewer") },
		"legacy viewer": func(t *testing.T) (*Server, *corrosion.Client) { return newUIOverRealDaemon(t, "vic", "viewer") },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s, db := mk(t)
			ctx := context.Background()
			if err := corrosion.CreateResourceMapping(ctx, db, "gpu", "seed"); err != nil {
				t.Fatalf("CreateResourceMapping: %v", err)
			}
			if err := corrosion.AddMappingDevice(ctx, db, "gpu", "h1", "0000:01:00.0", "", ""); err != nil {
				t.Fatalf("AddMappingDevice: %v", err)
			}
			reqs := map[string]*http.Request{
				"create":     uiSessionReq(t, "POST", "/ui/resource-mappings", url.Values{"name": {"sneaky"}}),
				"add device": uiSessionReq(t, "POST", "/ui/resource-mappings/gpu/devices", url.Values{"host": {"h2"}, "address": {"0000:02:00.0"}}),
				"rm device":  uiSessionReq(t, "DELETE", "/ui/resource-mappings/gpu/devices?host=h1&address=0000:01:00.0", nil),
			}
			for what, r := range reqs {
				if w := serveRequest(s, r); w.Code != http.StatusForbidden {
					t.Errorf("%s: status = %d, want %d", what, w.Code, http.StatusForbidden)
				}
			}
			all, err := corrosion.ListResourceMappings(ctx, db)
			if err != nil || len(all) != 1 || all[0].Name != "gpu" ||
				len(all[0].Devices) != 1 || all[0].Devices[0].Address != "0000:01:00.0" {
				t.Errorf("a viewer changed resource mappings: %+v (err %v)", all, err)
			}
		})
	}
}

// An Operator holds resourcemap.write, so the page must keep working for one.
//
// On the fork's main this also asserts the RPC's resourcemap.add audit row;
// this branch's CreateResourceMapping writes none (and neither did the
// in-process write it replaces), so only the authorization half is carried.
func TestUIResourceMappings_OperatorAllowed(t *testing.T) {
	s, db := newUIBoundTo(t, "olga", "Operator")
	ctx := context.Background()

	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/resource-mappings", url.Values{
		"name": {"gpu"}, "description": {"a100s"},
	}))
	assertStatus(t, w, http.StatusOK)
	if m, err := corrosion.GetResourceMapping(ctx, db, "gpu"); err != nil || m == nil {
		t.Fatalf("mapping gpu not created (err %v)", err)
	}

	w = serveRequest(s, uiSessionReq(t, "POST", "/ui/resource-mappings/gpu/devices", url.Values{
		"host": {"h1"}, "address": {"0000:01:00.0"},
	}))
	assertStatus(t, w, http.StatusOK)
	m, err := corrosion.GetResourceMapping(ctx, db, "gpu")
	if err != nil || m == nil || len(m.Devices) != 1 {
		t.Fatalf("mapping = %+v (err %v), want one device", m, err)
	}

	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/resource-mappings/gpu/devices?host=h1&address=0000:01:00.0", nil))
	assertStatus(t, w, http.StatusOK)
	if m, _ := corrosion.GetResourceMapping(ctx, db, "gpu"); m == nil || len(m.Devices) != 0 {
		t.Fatalf("mapping = %+v, want the device removed", m)
	}
}
