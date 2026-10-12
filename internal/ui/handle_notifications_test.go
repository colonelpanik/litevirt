package ui

import (
	"context"
	"net/http"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestHandleNotifications_RendersAndModals(t *testing.T) {
	// Targets are listed through the daemon's RPC, so the page needs a real
	// daemon behind it, not the mock.
	s, db, _ := newUIOverRealDaemonSvc(t, "oscar", "operator")
	ctx := context.Background()
	_ = corrosion.InsertNotificationTarget(ctx, db, corrosion.NotificationTarget{ID: "t1", Name: "ops-slack", Type: "slack", Config: `{"url":"http://x"}`, Enabled: true})
	_ = corrosion.InsertNotificationRoute(ctx, db, corrosion.NotificationRoute{ID: "r1", EventPattern: "backup.*", TargetID: "t1", MinSeverity: "warn", Enabled: true})

	w := serveRequest(s, uiSessionReq(t, http.MethodGet, "/notifications", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	mustContain(t, w.Body.String(), "ops-slack", "slack", "backup.*", "warn",
		"/ui/notifications/targets/t1/test")

	for _, p := range []string{"/ui/notifications/target-modal", "/ui/notifications/route-modal"} {
		if w := serveRequest(s, uiSessionReq(t, http.MethodGet, p, nil)); w.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d", p, w.Code)
		}
	}
	w = serveRequest(s, uiSessionReq(t, http.MethodGet, "/ui/notifications/route-modal", nil))
	mustContain(t, w.Body.String(), `<option value="t1">ops-slack (slack)</option>`)
}
