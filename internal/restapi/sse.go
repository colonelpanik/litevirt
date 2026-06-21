package restapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// wantsSSE reports whether the client opted into Server-Sent Events for a
// streaming RPC. Clients signal via either:
//   - `Accept: text/event-stream` (standard EventSource header), or
//   - `?stream=sse` query parameter (convenient for curl / scripts).
//
// Without these, REST endpoints fall back to legacy "first message + ack"
// behavior so existing clients keep working.
func wantsSSE(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		return true
	}
	if r.URL.Query().Get("stream") == "sse" {
		return true
	}
	return false
}

// streamSSE consumes a gRPC server-streaming RPC and writes each message as
// a Server-Sent Events frame. Closes cleanly on EOF or context cancellation.
//
// SSE format per RFC: lines of `event: <name>\ndata: <json>\n\n`. We emit:
//
//	event: progress
//	data: {<message-json>}
//
// followed by a final `event: complete` (or `event: error` on failure).
//
// Recv is a closure pulling one message at a time, typed as `proto.Message`
// so we can render the same way for every stream RPC.
//
// The eventName is fixed to "progress" for in-stream items; this keeps the
// client side simple and is sufficient for migrate/backup/deploy/drain.
// Endpoints that need richer event taxonomy (e.g. service rollout with
// per-replica events) can wrap streamSSE with their own dispatcher.
//
// Proxy compatibility: nginx and Apache buffer responses by default, which
// breaks SSE. We set X-Accel-Buffering: no for nginx and rely on flushing
// after every event so chunked transfer wakes intermediate proxies.
func streamSSE(w http.ResponseWriter, r *http.Request, recv func() (proto.Message, error)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, http.StatusInternalServerError, "streaming unsupported by HTTP server")
		return
	}

	// A streamed RPC (migrate/drain/backup/restore/deploy) can run far longer
	// than the gateway's WriteTimeout (120s); without clearing the deadline the
	// connection is torn down mid-stream, which cancels the request context and
	// aborts the in-flight op. Clear read+write deadlines for this long-lived
	// response. (httptest.ResponseRecorder returns ErrNotSupported — harmless to
	// ignore.) Every REST stream funnels through here, so this covers them all.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})

	// SSE response headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctxDone := r.Context().Done()
	for {
		// Cancel if the client disconnected.
		select {
		case <-ctxDone:
			return
		default:
		}

		msg, err := recv()
		if errors.Is(err, io.EOF) {
			writeSSEEvent(w, "complete", nil)
			flusher.Flush()
			return
		}
		if err != nil {
			writeSSEError(w, err)
			flusher.Flush()
			return
		}

		body, err := protojson.Marshal(msg)
		if err != nil {
			writeSSEError(w, fmt.Errorf("marshal stream item: %w", err))
			flusher.Flush()
			return
		}
		writeSSEEvent(w, "progress", body)
		flusher.Flush()
	}
}

// writeSSEEvent writes one SSE frame.
func writeSSEEvent(w http.ResponseWriter, event string, data []byte) {
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	if len(data) == 0 {
		fmt.Fprintf(w, "data: {}\n\n")
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

// writeSSEError writes an error event to the SSE stream.
func writeSSEError(w http.ResponseWriter, err error) {
	body := fmt.Sprintf(`{"error":%q}`, err.Error())
	writeSSEEvent(w, "error", []byte(body))
}
