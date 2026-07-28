// Package billing emits metered events to a configurable destination
// — today a JSON-over-HTTP webhook, structured so swapping in Kafka
// later is a one-implementation change.
//
// VMs accumulate vm.minute, disk.gb-hour, bandwidth.gb
// per-project; the daemon doesn't keep cents-per-resource pricing
// (that belongs to whatever invoicing pipeline the operator runs).
// Our job is to push every state transition with enough context for
// downstream aggregation.
//
// Failure mode is "fire and log": billing events that can't reach
// the webhook are dropped after a bounded retry, never blocking the
// VM lifecycle. The alternative (block CreateVM on billing health)
// would let a wedged invoicing system take down the cluster.
package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// Event is one metered transition. Kind is the verb-period-noun
// pattern ("vm.create", "vm.delete", "disk.attach", "backup.push").
// Subject is the resource the event is about (VM name, disk name,
// etc.). The optional numeric fields carry the dimensions the
// downstream pipeline needs to compute units.
type Event struct {
	Kind    string `json:"kind"`
	Project string `json:"project"`
	Subject string `json:"subject"`

	VCPU      int   `json:"vcpu,omitempty"`
	MemMiB    int   `json:"mem_mib,omitempty"`
	DiskGiB   int   `json:"disk_gib,omitempty"`
	BackupGiB int   `json:"backup_gib,omitempty"`
	Bytes     int64 `json:"bytes,omitempty"`

	// Timestamp is set by the emitter so retries don't drift.
	Timestamp time.Time `json:"timestamp"`
}

// Emitter is the contract billing-aware code consumes. Two
// production implementations today: NopEmitter (drops everything)
// and WebhookEmitter (POSTs JSON).
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// NopEmitter is the default when no billing destination is
// configured. Cheaper than nil-checks at every call site.
type NopEmitter struct{}

func (NopEmitter) Emit(_ context.Context, _ Event) {}

// WebhookEmitter POSTs every event as a JSON body to URL. The HTTP
// client uses a short timeout and a single in-band retry; persistent
// failure logs a warning but never blocks the caller.
type WebhookEmitter struct {
	URL    string
	Client *http.Client
}

// NewWebhookEmitter returns an emitter that fires JSON POSTs to url.
// Empty url → returns NopEmitter so a default config doesn't post
// to a phantom destination.
func NewWebhookEmitter(url string) Emitter {
	if url == "" {
		return NopEmitter{}
	}
	return &WebhookEmitter{
		URL: url,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Emit fires the event. Returns asynchronously — the caller never
// blocks on slow webhooks; downstream metering pipelines must
// tolerate a small replay window.
func (w *WebhookEmitter) Emit(ctx context.Context, e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Detach from the caller's context: Emit runs the POST on a goroutine, and the
	// caller is a gRPC handler whose context the runtime cancels the moment the RPC
	// returns — a successful CreateVM/DeleteVM would otherwise cancel its own billing
	// POST. WithoutCancel keeps values (trace) but drops cancellation+deadline; the
	// POST stays bounded by the emitter's own Client.Timeout.
	go w.doEmit(context.WithoutCancel(ctx), e)
}

func (w *WebhookEmitter) doEmit(ctx context.Context, e Event) {
	body, err := json.Marshal(e)
	if err != nil {
		slog.Warn("billing: marshal event", "kind", e.Kind, "error", err)
		return
	}
	// Two attempts total — handles a momentary 5xx without making
	// the daemon a retry storm on a wedged downstream.
	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
		if err != nil {
			slog.Warn("billing: build request", "url", w.URL, "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := w.Client.Do(req)
		if err != nil {
			if attempt < 2 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			slog.Error("billing: post failed — event dropped", "url", w.URL, "kind", e.Kind, "error", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		if attempt < 2 && resp.StatusCode >= 500 {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		slog.Error("billing: non-success status — event dropped", "url", w.URL, "kind", e.Kind, "status", resp.StatusCode)
		return
	}
}

// RecordingEmitter is a test helper that collects events in memory.
// Tests assert on the recorded sequence rather than standing up a
// real webhook listener.
type RecordingEmitter struct {
	Events []Event
}

func (r *RecordingEmitter) Emit(_ context.Context, e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	r.Events = append(r.Events, e)
}
