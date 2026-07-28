package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWebhookEmitter_DeliversDespiteCancelledContext pins the P1 fix: Emit runs the
// POST on a goroutine, so if it captures the caller's request context — which the gRPC
// runtime cancels the moment the handler (e.g. CreateVM/DeleteVM) returns — a
// successful operation cancels its own billing POST and the event is silently dropped.
// The emitter must run the POST on a detached context.
func TestWebhookEmitter_DeliversDespiteCancelledContext(t *testing.T) {
	got := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		_ = json.NewDecoder(r.Body).Decode(&e)
		select {
		case got <- e:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em := NewWebhookEmitter(srv.URL)

	// Model the handler returning: the caller's context is ALREADY cancelled by the
	// time the emit goroutine gets to run the POST.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	em.Emit(ctx, Event{Kind: "vm.create", Project: "p", Subject: "vm1"})

	select {
	case e := <-got:
		if e.Kind != "vm.create" {
			t.Fatalf("delivered event kind = %q, want vm.create", e.Kind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("billing POST never delivered — the emit goroutine dropped it on the cancelled context")
	}
}
