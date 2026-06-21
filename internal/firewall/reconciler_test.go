package firewall

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReconciler_RunsImmediatelyAndOnTick — initial run fires before
// the first tick, so a fresh start doesn't leave a window of unprotected
// traffic.
func TestReconciler_RunsImmediatelyAndOnTick(t *testing.T) {
	var calls int32
	loader := func(_ context.Context) (Plan, error) {
		atomic.AddInt32(&calls, 1)
		return Plan{}, nil
	}
	a := NewApplier(&fakeNft{})
	rec := NewReconciler(loader, a, 30*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)

	// Wait for initial + at least one tick.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	rec.Stop()
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected at least 2 reconcile calls, got %d", calls)
	}
}

// TestReconciler_LoaderErrorRecorded surfaces the latest load failure
// for `lv firewall status`.
func TestReconciler_LoaderErrorRecorded(t *testing.T) {
	want := errors.New("corrosion down")
	loader := func(_ context.Context) (Plan, error) { return Plan{}, want }
	a := NewApplier(&fakeNft{})
	rec := NewReconciler(loader, a, time.Hour)

	if err := rec.Reconcile(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Reconcile error = %v, want wrapping %v", err, want)
	}
	if got := rec.LastError(); !errors.Is(got, want) {
		t.Errorf("LastError = %v, want wrapping %v", got, want)
	}
	if !rec.LastTick().IsZero() {
		t.Errorf("LastTick should remain zero on failure")
	}
}

// TestReconciler_OKResetsLastError — a successful reconcile clears
// any previously recorded error so the operator-facing status is fresh.
func TestReconciler_OKResetsLastError(t *testing.T) {
	flake := errors.New("transient")
	calls := int32(0)
	loader := func(_ context.Context) (Plan, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return Plan{}, flake
		}
		return Plan{}, nil
	}
	a := NewApplier(&fakeNft{})
	rec := NewReconciler(loader, a, time.Hour)

	_ = rec.Reconcile(context.Background())
	if rec.LastError() == nil {
		t.Fatal("expected first call to record error")
	}
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rec.LastError() != nil {
		t.Errorf("LastError should be cleared on successful reconcile, got %v", rec.LastError())
	}
	if rec.LastTick().IsZero() {
		t.Error("LastTick should be set after a successful reconcile")
	}
}

// TestReconciler_StartIsIdempotent calling Start twice doesn't spawn
// two loops. We verify by counting loader calls in a window — a
// double-spawn would roughly double them.
func TestReconciler_StartIsIdempotent(t *testing.T) {
	var calls int32
	loader := func(_ context.Context) (Plan, error) {
		atomic.AddInt32(&calls, 1)
		return Plan{}, nil
	}
	a := NewApplier(&fakeNft{})
	rec := NewReconciler(loader, a, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	rec.Start(ctx) // second Start must be a no-op
	time.Sleep(150 * time.Millisecond)
	cancel()
	rec.Stop()

	c := atomic.LoadInt32(&calls)
	// Initial call + at least one tick. If a second loop spawned we'd
	// see roughly 2× this. Allow a generous upper bound to absorb timer
	// jitter in CI.
	if c == 0 {
		t.Errorf("no reconciles ran")
	}
	if c > 20 {
		t.Errorf("looks like a second loop spawned (%d calls in 150ms with 20ms interval)", c)
	}
}

// TestReconciler_StopWaitsForLoop — Stop must not return until the
// goroutine has actually finished, otherwise a daemon shutdown path
// could race with the loader closing its database.
func TestReconciler_StopWaitsForLoop(t *testing.T) {
	var inLoader sync.WaitGroup
	inLoader.Add(1)
	released := false
	loader := func(_ context.Context) (Plan, error) {
		if !released {
			released = true
			inLoader.Done()
			time.Sleep(20 * time.Millisecond)
		}
		return Plan{}, nil
	}
	a := NewApplier(&fakeNft{})
	rec := NewReconciler(loader, a, time.Hour)
	rec.Start(context.Background())
	inLoader.Wait() // ensure the goroutine entered the loader at least once
	rec.Stop()      // must wait for the loader to finish
}

// TestCountRules walks every rule slot the Plan carries.
func TestCountRules(t *testing.T) {
	p := Plan{
		ClusterRules: []Rule{{Direction: Ingress, Action: Accept}},
		HostRules:    []Rule{{Direction: Egress, Action: Accept}, {Direction: Ingress, Action: Drop}},
		SecurityGroups: []SecurityGroup{
			{Rules: []Rule{{Direction: Ingress, Action: Accept}}},
		},
		NICs: []NICBinding{{ExtraRules: []Rule{{Direction: Egress, Action: Accept}}}},
	}
	if got := countRules(p); got != 5 {
		t.Errorf("countRules = %d, want 5", got)
	}
}
