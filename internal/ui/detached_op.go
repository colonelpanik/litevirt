package ui

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"
)

// detachedOpCeiling bounds an operation the UI started and stopped watching,
// matching the REST API's (internal/restapi/detached_op.go).
const detachedOpCeiling = 6 * time.Hour

// detachedOpContext keeps ctx's values — the operator's session bearer, so the
// daemon authorises the operation as them — but not its cancellation. A
// server-streaming RPC runs off its stream's context, and net/http cancels the
// request context as soon as the handler returns (#192).
func detachedOpContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedOpCeiling)
}

// drainInBackground reads a stream the handler has stopped watching to its
// end, so the operation runs to completion and the server is never blocked on
// Send once the flow-control window fills. cancel is released when it ends.
func drainInBackground(op string, cancel context.CancelFunc, recv func() error) {
	go func() {
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				slog.Error("ui: detached operation panicked", "op", op, "panic", p)
			}
		}()
		for {
			if err := recv(); err != nil {
				if !errors.Is(err, io.EOF) {
					slog.Warn("ui: detached operation ended with an error", "op", op, "error", err)
				}
				return
			}
		}
	}()
}

// drainAckTimeout bounds how long a drain request waits for DrainHost's first
// frame before answering "drain started" anyway. DrainHost sends that frame
// only once its first VM is drained — a whole live migration — so an unbounded
// wait held the request past the UI's 30s WriteTimeout, and held a bulk drain's
// slot for a migration per host. It stays well under the WriteTimeout. A var so
// a test can shrink it; nothing in production reassigns it.
var drainAckTimeout = 10 * time.Second

// firstOrDetach waits up to bound for the first Recv of a server-streaming RPC:
// the UI's equivalent of the REST gateway's (internal/restapi/detached_op.go),
// over the func() error shape drainInBackground reads.
//
// It returns that Recv's error (nil, io.EOF or a refusal) when it arrives in
// time. Otherwise timedOut is set and the first Recv is still in flight; rest
// then hands its result to the background reader before reading further, so no
// frame is dropped. On both paths rest is what drainInBackground should read.
func firstOrDetach(recv func() error, bound time.Duration) (err error, timedOut bool, rest func() error) {
	ch := make(chan error, 1)
	go func() { ch <- recv() }()
	select {
	case err := <-ch:
		return err, false, recv
	case <-time.After(bound):
		pending := true
		return nil, true, func() error {
			if pending {
				pending = false
				return <-ch
			}
			return recv()
		}
	}
}
