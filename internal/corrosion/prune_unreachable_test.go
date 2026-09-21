package corrosion

import (
	"context"
	"testing"
	"time"
)

// A peer we can no longer PUSH to must not pin the log for a whole
// LiveWatermarkWindow.
//
// replication_watermarks.updated_at only advances on a SUCCESSFUL push, so a
// peer that has just become unreachable keeps a "fresh" row — the timestamp of
// the last push that worked — while its last_seq is frozen. For the whole
// window it therefore counts as live and its stale seq is the MIN, so the
// prune deletes nothing at all. A daemon restart re-arms this every time,
// because it resets the timestamp to the last success before the restart.
//
// The replicator learns the peer is unreachable within seconds (replicateOnce
// returns the push error), so the window is not the signal — the failing push
// is.
func TestPruneMutationLog_UnreachablePeerDoesNotPin(t *testing.T) {
	defer restoreVars(saveVars())
	defer func(g time.Duration) { UnreachablePeerGrace = g }(UnreachablePeerGrace)
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour
	UnreachablePeerGrace = 0 // any observed failure counts, so the test needs no clock

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ { // seqs 1..10, all past PruneMinAge
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "reachable-peer", 9, tsAgo(5*time.Second))
	// Fresh row, frozen seq: the last push that SUCCEEDED was 2 minutes ago and
	// every push since has failed.
	setWatermark(t, c, "stuck-peer", 3, tsAgo(2*time.Minute))

	r := NewReplicator(c, "", RelayConfig{})
	r.notePushFailure("stuck-peer")
	r.pruneMutationLog(context.Background())

	// stuck-peer is excluded, so MIN over the remaining live peers is 9 and
	// only seq 10 survives. Pinned behaviour would leave 7 rows.
	if got := countLog(t, c); got != 1 {
		t.Fatalf("after prune: %d rows remain, want 1 — a peer whose pushes are failing "+
			"pinned the log on a watermark it can no longer advance", got)
	}
}

// The grace period is what separates a broken peer from a blip. A peer whose
// pushes only just started failing must still be protected, or one dropped
// connection costs it a full anti-entropy resync.
func TestPruneMutationLog_BrieflyFailingPeerStillPins(t *testing.T) {
	defer restoreVars(saveVars())
	defer func(g time.Duration) { UnreachablePeerGrace = g }(UnreachablePeerGrace)
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour
	UnreachablePeerGrace = time.Minute

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ {
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "fast-peer", 9, tsAgo(5*time.Second))
	setWatermark(t, c, "blip-peer", 3, tsAgo(2*time.Minute))

	r := NewReplicator(c, "", RelayConfig{})
	r.notePushFailure("blip-peer") // streak starts now, well inside the grace
	r.pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 7 {
		t.Fatalf("after prune: %d rows remain, want 7 — a peer failing for less than the "+
			"grace must keep its protection, or a single blip forces a full resync", got)
	}
}

// A recovered peer is a live peer again. The streak must be cleared by the
// next successful push, not left to expire.
func TestPruneMutationLog_RecoveredPeerPinsAgain(t *testing.T) {
	defer restoreVars(saveVars())
	defer func(g time.Duration) { UnreachablePeerGrace = g }(UnreachablePeerGrace)
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour
	UnreachablePeerGrace = 0 // even at zero grace, a cleared streak must not exclude

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ {
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "fast-peer", 9, tsAgo(5*time.Second))
	setWatermark(t, c, "flapped-peer", 3, tsAgo(2*time.Minute))

	r := NewReplicator(c, "", RelayConfig{})
	r.notePushFailure("flapped-peer")
	r.notePushSuccess("flapped-peer") // pushes work again
	r.pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 7 {
		t.Fatalf("after prune: %d rows remain, want 7 — a peer whose pushes recovered is "+
			"live again and must protect its tail", got)
	}
}

// The prune can only skip a stalled peer if something records the stall. This
// pins the wiring: a push that fails marks the peer, so the very next prune
// tick sees it rather than waiting out LiveWatermarkWindow.
func TestReplicateToPeer_RecordsPushFailure(t *testing.T) {
	c := newPruneTestClient(t)
	insertLogRow(t, c, tsAgo(time.Minute)) // something to push, so a peer is dialled
	r := NewReplicator(c, "", RelayConfig{})
	// The peer supports proofs, so the fail-closed proof filter does not empty
	// the batch before it can be sent. Proof filtering is not what this covers,
	// and with a nil gate the push never happens at all.
	r.SetProofReplicaGate(func(context.Context, string) bool { return true })

	// No such peer exists, so the dial fails — the real error path, not a stub.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r.replicateToPeer(ctx, "ghost-peer")

	if !r.pushStalled("ghost-peer", time.Now().Add(time.Hour)) {
		t.Fatal("a peer whose pushes fail was never recorded as failing, so the prune keeps " +
			"counting it and the log stays pinned for the whole window")
	}
}

// The other half: a peer that works must not accumulate a permanent mark.
// An empty log makes replicateOnce succeed without dialling anyone, which is
// the success path this needs to exercise.
func TestReplicateToPeer_ClearsFailureOnSuccess(t *testing.T) {
	c := newPruneTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	r.notePushFailure("peer-a")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r.replicateToPeer(ctx, "peer-a")

	if r.pushStalled("peer-a", time.Now().Add(time.Hour)) {
		t.Fatal("a peer whose pushes succeeded is still marked failing — its tail would be " +
			"pruned out from under it and cost an anti-entropy resync")
	}
}
