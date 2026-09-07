package netboxsync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The per-pass capability predicate.
//
// The mirror writes two tables an older peer has never heard of, so it must not
// run until the cluster-wide contract has formed. The interesting half is WHEN
// the question is asked: a latch closes while the daemon is running — it is
// what the last node of a rolling upgrade completes — and nothing restarts the
// loop when it does. A predicate sampled once, at construction or at the first
// tick, leaves the mirror inert for the life of the process.

// fireSweeps drives n sweep ticks through the PRODUCTION loop.
//
// Deterministic, with no sleep: the tick channel is unbuffered, so send i
// returns only once the loop has TAKEN tick i, which is the barrier proving
// pass i-1 finished. Passes 1..n-1 are therefore complete when this returns;
// the LAST one is still in flight and is cut short by the cancel, so no
// scenario here may depend on what it did. Every one below arranges its gate so
// that the trailing pass cannot affect the count.
//
// The poll channel is nil, which blocks forever, so nothing here reaches a pass
// by the other route.
func fireSweeps(t *testing.T, r *Reconciler, n int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sweep := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx, sweep, nil) }()
	for range n {
		sweep <- time.Now()
	}
	cancel()
	<-done
}

// TestSweepDeclinesUntilTheCapabilityLatchIsRead is the fail-closed half.
//
// A reconciler whose gate says no writes nothing at all — it does not even
// resolve its NetBox cluster, which is the first call any sweep makes.
func TestSweepDeclinesWhileTheCapabilityIsUnlatched(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{
		AcquireLease: leaseHeld, HoldsLease: leaseHeld,
		Latched: func(context.Context) bool { return false },
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macGuard)

	fireSweeps(t, r, 3)

	if got := nb.Sweeps(); got != 0 {
		t.Fatalf("%d sweep(s) ran while the capability was unlatched", got)
	}
}

// TestSweepStartsWhenTheLatchFormsMidLoop is why the predicate is read per
// pass.
//
// ONE loop, running throughout: the gate answers no for the first pass and yes
// afterwards, exactly as a real latch does when the last peer of a rolling
// upgrade comes up. A predicate read once — at construction, or cached after
// the first tick — leaves this at zero mirrored objects forever.
func TestSweepStartsWhenTheLatchFormsMidLoop(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	var reads atomic.Int64
	r := pollingReconciler(t, nb, Options{
		AcquireLease: leaseHeld, HoldsLease: leaseHeld,
		// no, YES, no. Only the SECOND pass may sweep, so the count does not
		// depend on the trailing pass fireSweeps leaves in flight.
		Latched: func(context.Context) bool { return reads.Add(1) == 2 },
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macGuard)

	fireSweeps(t, r, 3)

	// Exactly one pass swept, and only the second one could have. A count of 2
	// means the gate was never consulted; 0 means it was consulted once and the
	// answer cached.
	if got := nb.Sweeps(); got != 1 {
		t.Fatalf("%d passes swept, want exactly the one after the latch formed", got)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.created) != 1 {
		t.Fatalf("the pass after the latch formed mirrored %+v, want the one VM", nb.created)
	}
}

// TestUnwiredCapabilityPredicateWritesNothing pins the fail-closed default.
//
// Every other gate on this reconciler is nil-safe in the same direction (see
// Options.AcquireLease): an incomplete wiring must be inert, not an ungated
// writer. A nil predicate read as "latched" would make the safe default the one
// nobody wrote down.
func TestUnwiredCapabilityPredicateWritesNothing(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	// Built through New directly: pollingReconciler wires a latched predicate
	// for every OTHER scenario, and this one is about its absence.
	r := New(Options{
		NetBox: nb, DB: newMirrorDB(t), Metrics: &countingMetrics{},
		AcquireLease: leaseHeld, HoldsLease: leaseHeld,
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macGuard)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("an unwired predicate must decline quietly: %v", err)
	}
	if got := nb.Sweeps(); got != 0 {
		t.Fatalf("%d sweep(s) ran with no capability predicate wired", got)
	}
}
