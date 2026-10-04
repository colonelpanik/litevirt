package ui

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Notification-target create and delete, and resource-mapping delete, wrote
// the host's database in-process with no authorization beyond holding a
// session with some role. A Viewer could add a webhook target, delete the
// targets that page the on-call, or delete a resource mapping VMs depend on.
// Their RPCs require operator (notifications) and resourcemap.write (mappings);
// the pages now call them, so they are held to the same check.

func TestUINotifyTargetWrites_ViewerRefused(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "vic", "viewer")
	ctx := context.Background()
	if err := corrosion.InsertNotificationTarget(ctx, db, corrosion.NotificationTarget{
		ID: "t1", Name: "pager", Type: "webhook", Config: `{"url":"http://127.0.0.1:1/hook"}`, Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
	reqs := map[string]*http.Request{
		"create": uiSessionReq(t, "POST", "/ui/notifications/targets", url.Values{
			"name": {"sneaky"}, "type": {"webhook"}, "url": {"http://127.0.0.1:1/x"},
		}),
		"delete": uiSessionReq(t, "DELETE", "/ui/notifications/targets/t1", nil),
	}
	for what, r := range reqs {
		if w := serveRequest(s, r); w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want %d", what, w.Code, http.StatusForbidden)
		}
	}
	targets, err := corrosion.ListNotificationTargets(ctx, db)
	if err != nil || len(targets) != 1 || targets[0].ID != "t1" {
		t.Errorf("a viewer changed notification targets: %+v (err %v)", targets, err)
	}
}

func TestUINotifyTargetWrites_OperatorAllowed(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "olga", "operator")
	ctx := context.Background()

	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/notifications/targets", url.Values{
		"name": {"pager"}, "type": {"webhook"}, "url": {"http://127.0.0.1:1/hook"},
	}))
	assertStatus(t, w, http.StatusOK)
	targets, err := corrosion.ListNotificationTargets(ctx, db)
	if err != nil || len(targets) != 1 || targets[0].Name != "pager" {
		t.Fatalf("targets = %+v (err %v), want the one just created", targets, err)
	}

	w = serveRequest(s, uiSessionReq(t, "DELETE", "/ui/notifications/targets/"+targets[0].ID, nil))
	assertStatus(t, w, http.StatusOK)
	if left, _ := corrosion.ListNotificationTargets(ctx, db); len(left) != 0 {
		t.Fatalf("target still present after delete: %+v", left)
	}
}

func TestUIResourceMappingDelete_ViewerRefusedOperatorAllowed(t *testing.T) {
	cases := []struct {
		name     string
		mk       func(t *testing.T) (*Server, *corrosion.Client)
		wantCode int
		wantLeft int
	}{
		{"bound Viewer", func(t *testing.T) (*Server, *corrosion.Client) { return newUIBoundTo(t, "vic", "Viewer") }, http.StatusForbidden, 1},
		{"legacy viewer", func(t *testing.T) (*Server, *corrosion.Client) { return newUIOverRealDaemon(t, "vic", "viewer") }, http.StatusForbidden, 1},
		{"bound Operator", func(t *testing.T) (*Server, *corrosion.Client) { return newUIBoundTo(t, "olga", "Operator") }, http.StatusOK, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := tc.mk(t)
			ctx := context.Background()
			if err := corrosion.CreateResourceMapping(ctx, db, "gpu", "seed"); err != nil {
				t.Fatalf("CreateResourceMapping: %v", err)
			}
			w := serveRequest(s, uiSessionReq(t, "DELETE", "/ui/resource-mappings/gpu", nil))
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
			all, err := corrosion.ListResourceMappings(ctx, db)
			if err != nil || len(all) != tc.wantLeft {
				t.Errorf("mappings after delete = %+v (err %v), want %d", all, err, tc.wantLeft)
			}
		})
	}
}
