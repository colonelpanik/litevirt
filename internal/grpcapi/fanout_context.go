package grpcapi

import (
	"context"
	"time"
)

// peerFanoutTimeout bounds a peer call made from a goroutine no handler waits
// for. Without one, a detached context leaks the goroutine for as long as the
// dial and RPC take to give up on their own, which for an unreachable peer is
// effectively forever: pki.PeerDial wraps grpc.NewClient, which is lazy, so the
// dial returns immediately and the call is what blocks.
const peerFanoutTimeout = 30 * time.Second

// detachedFanout returns the context a fire-and-forget peer call must use.
//
// A gRPC unary handler's context is cancelled the instant the handler returns.
// Several fan-outs here launch `go func(host string)` closing over that context
// and then return after a local read — microseconds later — so the goroutine
// reaches its peer call on an already-dead context and fails with
// codes.Canceled. Every one of those failures was logged and discarded, so the
// RPC reported success while remote holders received nothing.
//
// context.WithoutCancel rather than context.Background: cancellation is the
// only thing that should be dropped. The values carry the caller's identity and
// trace span, and a peer call that loses them is authenticated and attributed
// differently from the handler that started it.
//
// Two paths in lb.go already got this right by hand — one with
// context.Background() plus a timeout, one with a WaitGroup the handler waits
// on — which is why the inconsistency read as an oversight rather than a
// deliberate choice. This is the shared spelling.
func detachedFanout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), peerFanoutTimeout)
}
