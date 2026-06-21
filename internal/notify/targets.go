package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func httpClient() *http.Client { return &http.Client{Timeout: 8 * time.Second} }

// ── Webhook target ──────────────────────────────────────────────────────────

// webhookConfig is the JSON stored in notification_targets.config for a
// "webhook" target.
type webhookConfig struct {
	URL string `json:"url"`
}

// WebhookTarget POSTs the notification as a JSON body. The simplest target;
// downstream consumers parse the Notification shape directly.
type WebhookTarget struct {
	name   string
	url    string
	client *http.Client
}

func newWebhookTarget(name, configJSON string) (Target, error) {
	var c webhookConfig
	if err := json.Unmarshal([]byte(configJSON), &c); err != nil {
		return nil, fmt.Errorf("webhook target %q: bad config: %w", name, err)
	}
	if c.URL == "" {
		return nil, fmt.Errorf("webhook target %q: url required", name)
	}
	return &WebhookTarget{name: name, url: c.URL, client: httpClient()}, nil
}

func (w *WebhookTarget) Name() string { return w.name }

func (w *WebhookTarget) Send(ctx context.Context, n Notification) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return postJSON(ctx, w.client, w.url, body)
}

// ── Slack target ────────────────────────────────────────────────────────────

type slackConfig struct {
	URL string `json:"url"` // Slack incoming-webhook URL
}

// SlackTarget posts a Slack incoming-webhook message. Slack incoming webhooks
// accept a simple {"text": "..."} JSON; we prefix a severity emoji so the
// channel scans at a glance.
type SlackTarget struct {
	name   string
	url    string
	client *http.Client
}

func newSlackTarget(name, configJSON string) (Target, error) {
	var c slackConfig
	if err := json.Unmarshal([]byte(configJSON), &c); err != nil {
		return nil, fmt.Errorf("slack target %q: bad config: %w", name, err)
	}
	if c.URL == "" {
		return nil, fmt.Errorf("slack target %q: url required", name)
	}
	return &SlackTarget{name: name, url: c.URL, client: httpClient()}, nil
}

func (s *SlackTarget) Name() string { return s.name }

func (s *SlackTarget) Send(ctx context.Context, n Notification) error {
	body, err := json.Marshal(map[string]string{"text": SlackText(n)})
	if err != nil {
		return err
	}
	return postJSON(ctx, s.client, s.url, body)
}

// SlackText renders a Notification as a one-line Slack message. Exported for
// testing.
func SlackText(n Notification) string {
	emoji := ":information_source:"
	switch n.Severity {
	case SevError:
		emoji = ":rotating_light:"
	case SevWarn:
		emoji = ":warning:"
	}
	cluster := ""
	if n.Cluster != "" {
		cluster = "[" + n.Cluster + "] "
	}
	msg := fmt.Sprintf("%s %s*%s* — %s", emoji, cluster, n.Kind, n.Subject)
	if n.Detail != "" {
		msg += ": " + n.Detail
	}
	return msg
}

func postJSON(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return nil
}
