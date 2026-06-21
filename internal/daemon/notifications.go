package daemon

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedNotificationDefaults provisions a catch-all webhook target+route from the
// notifications.default_webhook config shortcut (#5), so an operator can get
// alerts without touching the CLI/UI. Deterministic IDs make it idempotent and
// CRDT-convergent across daemons/restarts. min-severity is "warn" so routine
// info events don't spam the webhook.
func (d *Daemon) seedNotificationDefaults(ctx context.Context) {
	url := d.cfg.Notifications.DefaultWebhook
	if url == "" || d.db == nil {
		return
	}
	cfgJSON, _ := json.Marshal(map[string]string{"url": url})
	if err := corrosion.InsertNotificationTarget(ctx, d.db, corrosion.NotificationTarget{
		ID: "default-webhook", Name: "default-webhook", Type: "webhook", Config: string(cfgJSON), Enabled: true,
	}); err != nil {
		slog.Warn("notify: seed default webhook target", "error", err)
		return
	}
	if err := corrosion.InsertNotificationRoute(ctx, d.db, corrosion.NotificationRoute{
		ID: "default-webhook-all", EventPattern: "*", TargetID: "default-webhook", MinSeverity: "warn", Enabled: true,
	}); err != nil {
		slog.Warn("notify: seed default webhook route", "error", err)
	}
}
