package corrosion

import (
	"context"
	"testing"
	"time"
)

// servePeers marks peers as current replication targets, the way syncPeers does
// when it starts their goroutines.
func servePeers(r *Replicator, names ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range names {
		_, cancel := context.WithCancel(context.Background())
		r.peers[n] = cancel
	}
}

// A watermark for a peer this node does not replicate to must not pin the log.
//
// Replication is PUSH over the relay topology, so a node only pushes to the
// peers in its target set. When the topology changes, syncPeers cancels the
// goroutine and drops the peer from r.peers — but the replication_watermarks
// row is left behind, frozen at whatever it last reached. It can never advance
// again, because nothing will ever push to that peer from here.
//
// updated_at therefore keeps the timestamp of the last push from back when we
// did serve it. For a whole LiveWatermarkWindow after a restart that looks
// recent, so the row counts as live, is the MIN, and the prune reclaims
// nothing. Push health cannot catch this: a peer we never push to never
// produces a push error.
func TestPruneMutationLog_UnservedPeerDoesNotPin(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ { // seqs 1..10, all past PruneMinAge
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "served-peer", 9, tsAgo(5*time.Second))
	// Fresh-looking row left over from when this node served it.
	setWatermark(t, c, "unserved-peer", 3, tsAgo(2*time.Minute))

	r := NewReplicator(c, "", RelayConfig{})
	servePeers(r, "served-peer") // unserved-peer has no goroutine here
	r.pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 1 {
		t.Fatalf("after prune: %d rows remain, want 1 — a watermark for a peer this node "+
			"never pushes to pinned the log on a sequence that can never advance", got)
	}
}

// The peers we DO serve must keep their protection — this is the check that
// stops the fix above from simply pruning everything.
func TestPruneMutationLog_ServedPeerStillPins(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ {
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "fast-peer", 9, tsAgo(5*time.Second))
	setWatermark(t, c, "slow-peer", 3, tsAgo(2*time.Minute))

	r := NewReplicator(c, "", RelayConfig{})
	servePeers(r, "fast-peer", "slow-peer")
	r.pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 7 {
		t.Fatalf("after prune: %d rows remain, want 7 — a peer we actively push to must keep "+
			"its tail until it has acked", got)
	}
}

// Serving nothing yet must not license pruning the log out from under every
// peer. A replicator whose targets have not been computed has no knowledge to
// act on, and keeping log costs disk while dropping it costs a resync.
func TestPruneMutationLog_NoServedPeersPrunesNothing(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ {
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "some-peer", 9, tsAgo(5*time.Second))

	r := NewReplicator(c, "", RelayConfig{}) // no targets started
	r.pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 10 {
		t.Fatalf("after prune: %d rows remain, want 10 — with no known targets the watermark "+
			"prune must defer to the retention ceiling rather than guess", got)
	}
}
