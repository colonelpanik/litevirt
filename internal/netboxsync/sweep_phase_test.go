package netboxsync

import (
	"context"
	"testing"
	"time"
)

// The mirror's sweep loop and the orphan sweeper's maintenance loop run on the
// SAME configured cadence and serialise on the SAME per-node gate, and the
// daemon starts them microseconds apart. Two tickers of equal period created
// together stay in lockstep for the life of the process, so whichever loop
// reaches the gate second is declined every interval, indefinitely.
//
// For the mirror that is not a lost tick but the whole feature: its sweep is the
// only caller that ACQUIRES the leader lease, and the queue poll acts only on a
// lease already held — so a sweep that never wins the gate means no node ever
// leads, the poll can never pull work forward, and no inventory is ever written.
//
// SweepPhase is what holds the two schedules apart, so Run must actually wait it
// out before its first sweep rather than create the ticker and drop a tick,
// which would leave the periods aligned exactly as before.
func TestRunDelaysTheFirstSweepBySweepPhase(t *testing.T) {
	const phase = 120 * time.Millisecond

	swept := make(chan time.Time, 4)
	r := New(Options{
		Interval:     40 * time.Millisecond,
		PollInterval: time.Hour, // the poll must not stand in for the sweep here
		SweepPhase:   phase,
		// Fail closed on everything else: this test is about WHEN the sweep
		// fires, and a pass that got as far as needing NetBox would panic on the
		// nil client. An unlatched reconciler returns before that.
		Latched: func(context.Context) bool {
			swept <- time.Now()
			return false
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go r.Run(ctx)

	select {
	case at := <-swept:
		if waited := at.Sub(start); waited < phase {
			t.Fatalf("first sweep fired after %v, before the %v phase delay had elapsed — "+
				"the loop is still in lockstep with the maintenance loop it shares a gate with",
				waited, phase)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sweep within 2s; the phase delay swallowed the loop entirely")
	}

	// And the loop keeps ticking afterwards: a delay that ran once and left the
	// ticker unstarted would mirror exactly once per process.
	select {
	case <-swept:
	case <-time.After(2 * time.Second):
		t.Fatal("only one sweep ever fired; the phase delay replaced the ticker instead of shifting it")
	}
}

// A zero phase must keep the previous behaviour — the first sweep one interval
// in — so a reconciler wired without the option is not silently delayed.
func TestRunWithoutSweepPhaseFiresAtOneInterval(t *testing.T) {
	swept := make(chan struct{}, 2)
	r := New(Options{
		Interval:     40 * time.Millisecond,
		PollInterval: time.Hour,
		Latched: func(context.Context) bool {
			swept <- struct{}{}
			return false
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go r.Run(ctx)

	select {
	case <-swept:
		// Generous upper bound: the assertion is that nothing ADDED a delay, not
		// that the scheduler is punctual.
		if waited := time.Since(start); waited > time.Second {
			t.Fatalf("first sweep waited %v with no phase configured", waited)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sweep within 2s with no phase configured")
	}
}

// Run must return when its context ends DURING the phase delay. A daemon
// shutting down inside the first half-interval would otherwise leak the
// goroutine until the delay expired.
func TestRunReturnsIfCancelledDuringTheSweepPhase(t *testing.T) {
	r := New(Options{
		Interval:     time.Hour,
		PollInterval: time.Hour,
		SweepPhase:   30 * time.Second,
		Latched:      func(context.Context) bool { return false },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on cancellation; it is blocked until the phase delay expires")
	}
}
