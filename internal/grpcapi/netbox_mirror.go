package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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

// The netbox_sync_queue ops the lifecycle paths record. The mirror resolves
// NOTHING from a queued item — the full sweep covers every object one could name
// — so these are for the operator reading the table, and for any future consumer
// that wants to act on one item without diffing the fleet.
const (
	mirrorOpUpsert = "upsert"
	mirrorOpDelete = "delete"
)

// enqueueMirrorSync names one VM for the inventory mirror's next pass.
//
// LATENCY ONLY. Every caller has already committed the operation locally, and
// the periodic full sweep converges the mirror whether or not anything was
// queued — which it has to, because a node that dies mid-operation never
// enqueues at all. So a failure here is logged and the operation continues:
// failing an operator's delete over a queue row would report a delete that
// genuinely happened as an error.
//
// Gated on a wired NetBox client. Without one nothing ever drains this queue,
// and every VM lifecycle operation on a cluster that does not use NetBox would
// leave a row behind forever.
func (s *Server) enqueueMirrorSync(ctx context.Context, vmName, op string) {
	if s.netbox == nil || s.db == nil {
		return
	}
	if err := corrosion.EnqueueSync(ctx, s.db, netboxsync.QueueKind, vmName, op); err != nil {
		slog.Warn("netbox mirror: could not queue a VM for the mirror; the next full sweep covers it",
			"vm", vmName, "op", op, "error", err)
	}
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
