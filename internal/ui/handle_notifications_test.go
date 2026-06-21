package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestHandleNotifications_RendersAndModals(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	ctx := context.Background()
	_ = corrosion.InsertNotificationTarget(ctx, db, corrosion.NotificationTarget{ID: "t1", Name: "ops-slack", Type: "slack", Config: `{"url":"http://x"}`, Enabled: true})
	_ = corrosion.InsertNotificationRoute(ctx, db, corrosion.NotificationRoute{ID: "r1", EventPattern: "backup.*", TargetID: "t1", MinSeverity: "warn", Enabled: true})
	s.SetCorrosionDB(db)

	r := withAuth(httptest.NewRequest(http.MethodGet, "/notifications", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	mustContain(t, w.Body.String(), "ops-slack", "slack", "backup.*", "warn")

	for _, p := range []string{"/ui/notifications/target-modal", "/ui/notifications/route-modal"} {
		r := withAuth(httptest.NewRequest(http.MethodGet, p, nil))
		if w := serveRequest(s, r); w.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d", p, w.Code)
		}
	}
}
