package grpcapi

import (
	"context"
	"log/slog"
	"time"
)

// defaultNetBoxSweepInterval is the maintenance cadence when
// netbox.sweep_interval_sec is unset or nonsensical.
//
// It is the ONE cadence: the sweeper's leader lease is sized from whatever
// interval a pass actually runs at (2x, exactly as the dual-run detector's
// lease is), so there is no second constant that could drift away from the
// configured value and leave a lease sized for a cadence nothing runs at.
const defaultNetBoxSweepInterval = 15 * time.Minute

// RunNetBoxMaintenance revalidates bindings and sweeps orphans on a ticker.
//
// ORDER MATTERS, and it is the only decision this loop makes. Revalidation runs
// FIRST, so a binding that has drifted is suspended before the sweep could act
// on it; a revalidation that FAILS skips the sweep entirely, because a binding
// litevirt could not check is not a binding it may delete against. Sweeping is
// the one operation that removes state from NetBox — every doubt resolves
// towards leaving an address allocated.
//
// There is deliberately no pass at startup. The first pass lands one interval
// in, so a node that has just restarted (or a cluster mid-rolling-upgrade) is
// not sweeping while its own view of the fleet is still assembling — and a
// restart loop can never turn into a reclamation loop.
func (s *Server) RunNetBoxMaintenance(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultNetBoxSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.netboxMaintenanceTick(ctx, interval)
			if s.onMaintenanceTick != nil {
				s.onMaintenanceTick()
			}
		}
	}
}

// StartNetBoxMaintenance starts the maintenance loop if — and only if — this
// node is configured for NetBox, and reports whether it did.
//
// The guard lives here rather than at the call site so there is ONE answer to
// "does this node run maintenance", shared by the daemon and by any harness
// that stands a server up. A node with no NetBox client has nothing to
// validate and nothing to prove an address orphaned with; the loop it would run
// could only ever be a goroutine taking no decisions.
func (s *Server) StartNetBoxMaintenance(ctx context.Context, interval time.Duration) bool {
	if s.netbox == nil {
		return false
	}
	go s.RunNetBoxMaintenance(ctx, interval)
	return true
}

// RunNetBoxMaintenanceOnce runs exactly one maintenance pass. It exists so a
// test can drive the pass deterministically instead of waiting on a ticker; the
// daemon runs the same pass on an interval.
//
// The leader lease is sized from the DEFAULT interval rather than a
// caller-supplied one because this path is test-only; the daemon's own loop
// passes its configured interval through netboxMaintenanceTick.
func (s *Server) RunNetBoxMaintenanceOnce(ctx context.Context) error {
	return s.netboxMaintenanceTick(ctx, defaultNetBoxSweepInterval)
}

// netboxMaintenanceTick is ONE pass: revalidate, and sweep only if that
// succeeded. It holds no logic of its own beyond that skip — both halves decide
// everything else for themselves.
//
// Under this node's single-pass gate, for the same reason the inventory mirror
// is: the orphan sweep reclaims the addresses a re-key is re-stamping, and the
// `netbox` leader lease names the NODE, so on the node running a re-key it
// separates nothing.
func (s *Server) netboxMaintenanceTick(ctx context.Context, interval time.Duration) error {
	return s.netboxExclusivePass(ctx, func(ctx context.Context) error {
		return s.netboxMaintenancePass(ctx, interval)
	})
}

func (s *Server) netboxMaintenancePass(ctx context.Context, interval time.Duration) error {
	if err := s.revalidateBindings(ctx); err != nil {
		slog.Warn("netbox: binding revalidation failed; skipping the sweep this pass", "error", err)
		return err
	}
	if err := s.sweepOrphans(ctx, interval); err != nil {
		slog.Warn("netbox: orphan sweep failed", "error", err)
		return err
	}
	return nil
}
