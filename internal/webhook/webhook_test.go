package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSend_EmptyURL_NoOp(t *testing.T) {
	// Should not panic or error.
	Send(context.Background(), "", Payload{Event: EventVMCreated, VM: "test"})
}

func TestSend_Delivered(t *testing.T) {
	var received atomic.Int32
	var got Payload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	Send(context.Background(), srv.URL, Payload{
		Event: EventVMCreated,
		VM:    "vm1",
		Stack: "mystack",
	})

	// Wait for async delivery.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && received.Load() == 0 {
		time.Sleep(50 * time.Millisecond)
	}

	if received.Load() == 0 {
		t.Fatal("webhook was not delivered")
	}
	if got.Event != EventVMCreated {
		t.Errorf("expected event %q, got %q", EventVMCreated, got.Event)
	}
	if got.VM != "vm1" {
		t.Errorf("expected vm=vm1, got %q", got.VM)
	}
	if got.Timestamp == "" {
		t.Error("timestamp should be set")
	}
}

func TestSend_ServerError_Retries(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	Send(ctx, srv.URL, Payload{Event: EventHostFenced, Host: "h1"})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 3 {
		time.Sleep(100 * time.Millisecond)
	}

	if calls.Load() < 3 {
		t.Errorf("expected at least 3 attempts (retries), got %d", calls.Load())
	}
}

func TestSend_AllFail_LogsError(t *testing.T) {
	// Server always returns 500 — all retries fail. Should not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	Send(ctx, srv.URL, Payload{Event: EventVMFailed, VM: "broken"})
	// Give goroutine time to finish retries.
	time.Sleep(baseRetryDelay*maxRetries + 500*time.Millisecond)
}
