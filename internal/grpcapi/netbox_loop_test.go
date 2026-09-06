package grpcapi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestMaintenanceTickerRunsOnInterval pins the ticker itself: the interval
// handed in drives the cadence, and cancelling the context stops the loop.
//
// The cadence is not cosmetic — the sweeper's leader lease is derived from it,
// so a loop that ignored its interval would hold a lease sized for a cadence it
// does not run at.
func TestMaintenanceTickerRunsOnInterval(t *testing.T) {
	// No database and no NetBox client: every tick is a no-op pass, which is
	// all this test wants — it is about the ticker, not the work.
	s := &Server{}
	var ticks atomic.Int64
	s.onMaintenanceTick = func() { ticks.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		s.RunNetBoxMaintenance(ctx, 20*time.Millisecond)
		close(stopped)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the context must stop the maintenance loop")
	}

	got := ticks.Load()
	if got < 3 {
		t.Fatalf("ticks = %d over 100ms at a 20ms interval, want >= 3 — the interval must drive the cadence", got)
	}

	// And nothing keeps running behind the cancelled context.
	time.Sleep(100 * time.Millisecond)
	if after := ticks.Load(); after != got {
		t.Fatalf("ticks kept coming after cancellation: %d -> %d", got, after)
	}
}

// TestMaintenanceNotStartedWithoutNetBoxClient pins the guard the daemon and the
// fleet harness both go through: no NetBox client, no goroutine.
func TestMaintenanceNotStartedWithoutNetBoxClient(t *testing.T) {
	s := &Server{}
	if s.StartNetBoxMaintenance(context.Background(), time.Minute) {
		t.Fatal("a node with no NetBox client must not start the maintenance loop")
	}
}
