package restapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestWantsSSE_AcceptHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/event-stream")
	if !wantsSSE(r) {
		t.Error("wantsSSE() = false for Accept: text/event-stream")
	}
}

func TestWantsSSE_QueryParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/?stream=sse", nil)
	if !wantsSSE(r) {
		t.Error("wantsSSE() = false for ?stream=sse")
	}
}

func TestWantsSSE_Default(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if wantsSSE(r) {
		t.Error("wantsSSE() = true for default request")
	}
}

func TestStreamSSE_DeliversAllItems(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	// Three items then EOF.
	items := []proto.Message{
		wrapperspb.String("alpha"),
		wrapperspb.String("beta"),
		wrapperspb.String("gamma"),
	}
	idx := 0
	streamSSE(w, r, func() (proto.Message, error) {
		if idx >= len(items) {
			return nil, io.EOF
		}
		m := items[idx]
		idx++
		return m, nil
	})

	resp := w.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	body := w.Body.String()
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "event: complete") {
		t.Errorf("body missing terminator event:\n%s", body)
	}
}

func TestStreamSSE_ErrorEmitsErrorEvent(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	called := 0
	streamSSE(w, r, func() (proto.Message, error) {
		called++
		if called == 1 {
			return wrapperspb.String("first"), nil
		}
		return nil, errors.New("boom")
	})

	body := w.Body.String()
	if !strings.Contains(body, "first") {
		t.Errorf("body missing successful first item:\n%s", body)
	}
	if !strings.Contains(body, "event: error") {
		t.Errorf("body missing error event:\n%s", body)
	}
	if !strings.Contains(body, "boom") {
		t.Errorf("body missing error message:\n%s", body)
	}
}

// httptest.NewRecorder doesn't implement http.Flusher by default in older
// stdlib; this guard makes the requirement explicit.
var _ http.Flusher = httptest.NewRecorder()
