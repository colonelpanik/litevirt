package grpcapi

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The NetBox inventory mirror's wiring.
//
// The reconciler itself lives in internal/netboxsync, which knows nothing about
// this package. What it cannot own is the LEADER LEASE: the mirror runs under
// the SAME `leader_election` key as the orphan sweeper (netBoxLeaseKey), and
// two keys would let the sweeper and the mirror each believe it leads the
// cluster — one reclaiming addresses while the other rewrote the inventory that
// names them. So the lease is threaded in as two function values here rather
// than reimplemented there, and there is exactly one copy of the SQL.

// netboxMirror builds the reconciler for this node.
//
// A fresh value per pass. The reconciler carries per-sweep state (the resolved
// NetBox cluster id), so a long-lived one shared between the ticker and a
// harness-driven pass would let one pass observe the other's half-resolved
// state.
func (s *Server) netboxMirror(interval time.Duration) *netboxsync.Reconciler {
	if interval <= 0 {
		interval = defaultNetBoxSweepInterval
	}
	return netboxsync.New(netboxsync.Options{
		NetBox:   s.netbox,
		DB:       s.db,
		Metrics:  s.nbMetrics(),
		Interval: interval,
		// The TTL is sized from the cadence this node actually runs at, exactly
		// as the sweeper's is, so a cluster on a slower cadence does not hand
		// leadership away between its own passes.
		AcquireLease: func(ctx context.Context) bool { return s.acquireNetBoxLease(ctx, interval) },
		HoldsLease:   s.netboxMirrorHoldsLease,
	})
}

// netboxMirrorHoldsLease is the lease READ — no write, no renewal — the mirror
// re-runs before each write batch, with the test seam folded in.
func (s *Server) netboxMirrorHoldsLease(ctx context.Context) bool {
	if s.nbLeaseProbe != nil {
		return s.nbLeaseProbe(ctx)
	}
	return s.holdsLeaderLease(ctx)
}

// StartNetBoxMirror starts the inventory mirror if — and only if — this node is
// configured for NetBox, and reports whether it did.
//
// The guard is the same one StartNetBoxMaintenance uses and for the same
// reason: a node with no NetBox client has nothing to mirror into, and the loop
// it would run could only ever be a goroutine taking no decisions. Every
// configured node runs it; the lease decides which one writes.
func (s *Server) StartNetBoxMirror(ctx context.Context, interval time.Duration) bool {
	if s.netbox == nil || s.db == nil {
		return false
	}
	go s.netboxMirror(interval).Run(ctx)
	return true
}

// RunNetBoxMirrorOnce runs exactly one leader-gated mirror pass. It exists so a
// test can drive a pass deterministically instead of waiting on a ticker,
// through the SAME gate the loop uses — a harness that reached past the gate
// could not tell a leader-gated mirror from an ungated one.
func (s *Server) RunNetBoxMirrorOnce(ctx context.Context) error {
	if s.netbox == nil || s.db == nil {
		return nil
	}
	return s.netboxMirror(defaultNetBoxSweepInterval).SyncOnce(ctx)
}

// SetNetBoxLeaseProbe replaces the lease read the mirror re-validates before
// each write batch.
//
// Test-only seam, nil in production. It is the only way to model a leadership
// handover that lands MID-SWEEP, which is precisely what the per-batch
// re-validation exists for: a real lease can be stolen between passes, but not
// between two batches of one pass without racing the test.
//
// It deliberately does NOT replace the ACQUIRE. Folding it in there too would
// let the acquire's own read-back consume the seam's budget, and a scenario
// meaning "lose the lease after the first batch" would instead never start.
func (s *Server) SetNetBoxLeaseProbe(fn func(context.Context) bool) { s.nbLeaseProbe = fn }
