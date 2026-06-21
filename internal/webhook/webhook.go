// Package webhook sends HTTP POST notifications on litevirt events.
// Payloads are JSON; delivery is best-effort (failures are logged, not fatal).
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	deliveryTimeout = 10 * time.Second
	maxRetries      = 3
	baseRetryDelay  = 2 * time.Second
)

// Event types sent in the "event" field.
const (
	EventVMCreated   = "vm.created"
	EventVMStarted   = "vm.started"
	EventVMStopped   = "vm.stopped"
	EventVMDeleted   = "vm.deleted"
	EventVMFailed    = "vm.failed"
	EventStackDeploy = "stack.deployed"
	EventStackDelete = "stack.deleted"
	EventHostOffline = "host.offline"
	EventHostFenced  = "host.fenced"
	EventFailover    = "host.failover"
)

// Payload is the JSON body sent to the webhook URL.
type Payload struct {
	Event     string         `json:"event"`
	Timestamp string         `json:"timestamp"`
	Stack     string         `json:"stack,omitempty"`
	VM        string         `json:"vm,omitempty"`
	Host      string         `json:"host,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
}

// Send delivers a webhook payload to url, retrying up to maxRetries times.
// It is safe to call with an empty url (no-op).
func Send(ctx context.Context, url string, p Payload) {
	if url == "" {
		return
	}
	p.Timestamp = time.Now().UTC().Format(time.RFC3339)

	go func() {
		if err := sendWithRetry(ctx, url, p); err != nil {
			slog.Warn("webhook delivery failed", "url", url, "event", p.Event, "error", err)
		}
	}()
}

func sendWithRetry(ctx context.Context, url string, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			// Exponential backoff: 2s, 4s, 8s,...
			delay := baseRetryDelay * (1 << (i - 1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		reqCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "litevirt-webhook/1.0")

		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			slog.Debug("webhook delivered", "url", url, "event", p.Event, "status", resp.StatusCode)
			return nil
		}

		// Honor Retry-After header on 429/503 responses (#35).
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs <= 300 {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(time.Duration(secs) * time.Second):
					}
				}
			}
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return lastErr
}
