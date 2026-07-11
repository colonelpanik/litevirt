package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The watchdog must be armed BEFORE telemetry setup runs — setup can block on a
// slow collector, and only an already-armed watchdog can roll back that hang.
// Guards finding 3 (boot ordering).
func TestArmWatchdogThenSetupTelemetry_Order(t *testing.T) {
	var seq []string
	armed := false

	shutdown := func(context.Context) error { return nil }
	got, err := armWatchdogThenSetupTelemetry(
		func() { seq = append(seq, "watchdog"); armed = true },
		func() (func(context.Context) error, error) {
			seq = append(seq, "setup")
			if !armed {
				t.Error("telemetry setup ran BEFORE the watchdog was armed — a setup hang would never roll back")
			}
			return shutdown, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got == nil {
		t.Fatal("shutdown func not propagated from setup")
	}
	if len(seq) != 2 || seq[0] != "watchdog" || seq[1] != "setup" {
		t.Errorf("call order = %v; want [watchdog setup]", seq)
	}
}

// The setup error must propagate (fail-open is the caller's job, but the error
// has to reach it to be logged).
func TestArmWatchdogThenSetupTelemetry_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	_, err := armWatchdogThenSetupTelemetry(
		func() {},
		func() (func(context.Context) error, error) { return func(context.Context) error { return nil }, wantErr },
	)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v; want %v", err, wantErr)
	}
}

// A shutdown that blocks on an unreachable collector must return within the
// bound, and the context it receives must carry that deadline. Guards finding 4.
func TestBoundedTelemetryShutdown_Bounds(t *testing.T) {
	const timeout = 60 * time.Millisecond
	var sawDeadline bool

	start := time.Now()
	err := boundedTelemetryShutdown(func(ctx context.Context) error {
		_, sawDeadline = ctx.Deadline()
		// Simulate a collector that never responds; a correctly-bounded shutdown
		// cancels the context, so a ctx-respecting flush unblocks here.
		<-ctx.Done()
		return ctx.Err()
	}, timeout)
	elapsed := time.Since(start)

	if !sawDeadline {
		t.Error("shutdown received a context with no deadline — the flush is unbounded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v; want context.DeadlineExceeded", err)
	}
	if elapsed > 10*timeout {
		t.Errorf("boundedTelemetryShutdown took %s; the bound did not fire", elapsed)
	}
}

// Nil shutdown is a no-op (the flush closure may run before setup assigns one).
func TestBoundedTelemetryShutdown_NilSafe(t *testing.T) {
	if err := boundedTelemetryShutdown(nil, time.Second); err != nil {
		t.Errorf("nil shutdown returned %v; want nil", err)
	}
}

// newTestFlushTelemetry builds the flush closure Run assigns to
// d.flushTelemetry BEFORE the watchdog is armed: it reads the real shutdown
// func from an atomic.Pointer rather than closing over it directly, so the
// closure itself is safe to assign once and call at any time — including
// before obs.Setup (and the atomic Store that follows it) has run. Guards
// finding 7 (flush-hook race / lost rollback telemetry).
func newTestFlushTelemetry(d *Daemon) func() {
	return func() {
		if fn := d.telemetryShutdown.Load(); fn != nil {
			_ = boundedTelemetryShutdown(*fn, telemetryShutdownTimeout)
		}
	}
}

// exit() must be safe to call before Setup completes — the watchdog goroutine
// is spawned before Setup runs, so it can call exit() while
// d.telemetryShutdown is still nil. Must not panic; flush is a no-op.
func TestExit_BeforeTelemetryShutdownSet_NoopSafe(t *testing.T) {
	var exitCode int
	d := &Daemon{exitFunc: func(code int) { exitCode = code }}
	d.flushTelemetry = newTestFlushTelemetry(d)

	d.exit(3)

	if exitCode != 3 {
		t.Errorf("exitFunc called with %d; want 3", exitCode)
	}
}

// Once Setup completes and stores the real shutdown func, exit() must flush
// through it.
func TestExit_AfterTelemetryShutdownSet_Flushes(t *testing.T) {
	d := &Daemon{exitFunc: func(int) {}}
	d.flushTelemetry = newTestFlushTelemetry(d)

	var flushed atomic.Bool
	shutdown := func(context.Context) error { flushed.Store(true); return nil }
	d.telemetryShutdown.Store(&shutdown)

	d.exit(0)

	if !flushed.Load() {
		t.Error("exit() did not flush telemetry after telemetryShutdown was set")
	}
}

// The flush closure is assigned once, before the watchdog goroutine starts;
// only the atomic.Pointer is written concurrently with reads from exit() —
// this must be race-clean (run with -race).
func TestExit_ConcurrentWithTelemetryShutdownStore_RaceSafe(t *testing.T) {
	d := &Daemon{exitFunc: func(int) {}}
	d.flushTelemetry = newTestFlushTelemetry(d)

	shutdown := func(context.Context) error { return nil }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); d.telemetryShutdown.Store(&shutdown) }()
	go func() { defer wg.Done(); d.exit(0) }()
	wg.Wait()
}
