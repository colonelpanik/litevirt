package restapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
)

// detachedOpCeiling bounds an operation the REST gateway has acknowledged and
// stopped watching. Long enough for a real drain or storage migration of a
// large host; short enough that a wedged one cannot hold a goroutine and a gRPC
// stream open indefinitely.
const detachedOpCeiling = 6 * time.Hour

// detachedOpContext derives a context that keeps ctx's VALUES but not its
// cancellation, bounded by detachedOpCeiling.
//
// The values matter as much as the detachment: the gRPC call is authenticated
// by metadata carried on the request context, so a context built from
// Background() would turn every acknowledged operation into an unauthenticated
// one.
func detachedOpContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedOpCeiling)
}

// ackAndDetach is the non-SSE half of a server-streaming RPC: the caller has
// been told the operation started, so it now has to actually run.
//
// The handler used to open the stream on r.Context(), never call Recv, write
// its ack and return — at which point net/http cancelled r.Context(), the
// stream's parent, and the operation died part-way through. Draining the stream
// in the background does two things: it lets the RPC run to completion, and it
// keeps reading so the server is never blocked on Send once the flow-control
// window fills.
//
// cancel is the detached context's, released once the stream ends.
func ackAndDetach(op string, cancel context.CancelFunc, recv func() (proto.Message, error)) {
	go func() {
		defer cancel()
		// This runs after the handler has returned, so a panic here has no
		// http.Server recover above it and would take the daemon down with it.
		defer func() {
			if p := recover(); p != nil {
				slog.Error("restapi: detached operation panicked", "op", op, "panic", p)
			}
		}()
		for {
			_, err := recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					slog.Debug("restapi: detached operation completed", "op", op)
				} else {
					slog.Warn("restapi: detached operation ended with an error", "op", op, "error", err)
				}
				return
			}
		}
	}()
}
