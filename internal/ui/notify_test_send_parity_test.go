package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The notification page's "test" button used to load the target and send to
// it in-process, so any session with a role, a Viewer included, could make the
// daemon fire at a configured endpoint with its stored credentials. The
// TestNotificationTarget RPC requires operator; the page now calls it.
func TestUINotifyTestSend_HeldToTheRPCsCheck(t *testing.T) {
	for _, tc := range []struct {
		role     string
		wantCode int
		wantHits int32
	}{
		{"viewer", http.StatusForbidden, 0},
		{"operator", http.StatusOK, 1},
	} {
		t.Run(tc.role, func(t *testing.T) {
			var hits atomic.Int32
			hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(hook.Close)

			s, db := newUIOverRealDaemon(t, "tess", tc.role)
			if err := corrosion.InsertNotificationTarget(context.Background(), db, corrosion.NotificationTarget{
				ID: "t1", Name: "ops", Type: "webhook", Config: `{"url":"` + hook.URL + `"}`, Enabled: true,
			}); err != nil {
				t.Fatalf("InsertNotificationTarget: %v", err)
			}

			w := serveRequest(s, uiSessionReq(t, "POST", "/ui/notifications/targets/t1/test", nil))
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if got := hits.Load(); got != tc.wantHits {
				t.Errorf("endpoint received %d sends, want %d", got, tc.wantHits)
			}
		})
	}
}
