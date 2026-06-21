package corrosion

import (
	"context"
	"time"
)

// NotificationTarget is a configured delivery destination (#5).
type NotificationTarget struct {
	ID      string
	Name    string
	Type    string // webhook | slack
	Config  string // JSON (url, …)
	Enabled bool
}

// NotificationRoute selects which event patterns (at which min severity) go to
// a target.
type NotificationRoute struct {
	ID           string
	EventPattern string
	TargetID     string
	MinSeverity  string // info | warn | error
	Enabled      bool
}

func InsertNotificationTarget(ctx context.Context, c *Client, t NotificationTarget) error {
	now := time.Now().UTC().Format(time.RFC3339)
	en := 0
	if t.Enabled {
		en = 1
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO notification_targets (id, name, type, config, enabled, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		t.ID, t.Name, t.Type, t.Config, en, now, now,
	)
}

func ListNotificationTargets(ctx context.Context, c *Client) ([]NotificationTarget, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, type, config, enabled FROM notification_targets WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]NotificationTarget, 0, len(rows))
	for _, r := range rows {
		out = append(out, NotificationTarget{
			ID: r.String("id"), Name: r.String("name"), Type: r.String("type"),
			Config: r.String("config"), Enabled: r.Int64("enabled") != 0,
		})
	}
	return out, nil
}

func DeleteNotificationTarget(ctx context.Context, c *Client, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE notification_targets SET deleted_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
}

func InsertNotificationRoute(ctx context.Context, c *Client, r NotificationRoute) error {
	now := time.Now().UTC().Format(time.RFC3339)
	en := 0
	if r.Enabled {
		en = 1
	}
	if r.MinSeverity == "" {
		r.MinSeverity = "info"
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO notification_routes (id, event_pattern, target_id, min_severity, enabled, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		r.ID, r.EventPattern, r.TargetID, r.MinSeverity, en, now, now,
	)
}

func ListNotificationRoutes(ctx context.Context, c *Client) ([]NotificationRoute, error) {
	rows, err := c.Query(ctx,
		`SELECT id, event_pattern, target_id, min_severity, enabled FROM notification_routes WHERE deleted_at IS NULL ORDER BY event_pattern`)
	if err != nil {
		return nil, err
	}
	out := make([]NotificationRoute, 0, len(rows))
	for _, r := range rows {
		out = append(out, NotificationRoute{
			ID: r.String("id"), EventPattern: r.String("event_pattern"), TargetID: r.String("target_id"),
			MinSeverity: r.String("min_severity"), Enabled: r.Int64("enabled") != 0,
		})
	}
	return out, nil
}

func DeleteNotificationRoute(ctx context.Context, c *Client, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE notification_routes SET deleted_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
}
