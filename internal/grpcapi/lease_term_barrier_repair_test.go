package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The sweep's own doc argues that stopping at a quorum-sized set of answers
// "discards exactly the evidence it went looking for — an accept that a complete
// sweep would have refused", and closes with "Every reachable peer is asked."
//
// Asking is not answering. A peer this node memoised as silent is asked on a
// 250ms probe instead of the 3s budget, and if it gives no answer the sweep
// still accepts as long as the OTHER peers carry the quorum. The repair pass
// that exists for exactly this was gated on `answers < needed` — a quorum
// SHORTFALL — so the one case it could not repair was the case where quorum was
// met without the short-deadlined peer.
//
// That peer is not hypothetical: noteSilentPeers re-stamps time.Now() on every
// miss, so a healthy node that answers slower than the probe stays pinned in the
// silent set and is never asked at full price again.
//
// Here node-c holds the superseding term. Accepting without it is the
// shared-storage double-start the fencing token exists to prevent, and the
// accept is byte-identical to a correct one.
func TestLeaseTermBarrier_AQuorumMetWithoutASilencedPeerStillRepairsTheShortcut(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 2*time.Second, 20*time.Millisecond)

	// needed = 2, so node-b's answer alone carries the quorum.
	s := barrierNode(t, 4, 2, "node-b", "node-c")
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		switch host {
		case "node-b":
			return &fakeHighWaterPeer{term: 4}, func() {}, nil
		case "node-c":
			// Healthy, and holds the superseding term — just slower than the
			// silent probe.
			return &fakeHighWaterPeer{term: 9, delay: 200 * time.Millisecond}, func() {}, nil
		}
		return nil, nil, context.DeadlineExceeded
	}

	// node-c missed an earlier sweep, so this one short-deadlines it.
	s.leaseBarrierMu.Lock()
	if s.leaseBarrierSilent == nil {
		s.leaseBarrierSilent = make(map[string]time.Time, 1)
	}
	s.leaseBarrierSilent["node-c"] = time.Now()
	s.leaseBarrierMu.Unlock()

	highest, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover)
	if !ok {
		t.Fatal("sweep returned no answer although quorum was available")
	}
	if highest != 9 {
		t.Errorf("highest term = %d, want 9\n"+
			"node-c holds the superseding term and was skipped because THIS node "+
			"short-deadlined it, then never repaired the shortcut because the other "+
			"peers happened to carry the quorum. A proof at term 4 is now accepted "+
			"and the workload starts on shared storage the superseding coordinator "+
			"still believes it owns.", highest)
	}

	// And the memo must clear once the peer has answered, or it stays pinned and
	// the same shortcut recurs on every later sweep.
	s.leaseBarrierMu.Lock()
	_, stillSilent := s.leaseBarrierSilent["node-c"]
	s.leaseBarrierMu.Unlock()
	if stillSilent {
		t.Error("node-c answered the repair pass but is still memoised as silent, " +
			"so the next sweep short-deadlines it again")
	}
}

// An accept reached without every peer answering is byte-identical to one
// reached on a complete sweep. The accept criterion is deliberately left at
// quorum — tightening it to a complete sweep is an availability trade that
// belongs in its own change — but it must not also be INVISIBLE, or the one
// shape that can miss a superseding term is the one nothing records.
func TestLeaseTermBarrier_AnIncompleteAcceptIsCounted(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 300*time.Millisecond, 20*time.Millisecond)

	var gotKey string
	var gotAnswered, gotPeers int
	var fired int

	s := barrierNode(t, 4, 2, "node-b", "node-c")
	s.SetLeaseBarrierIncompleteObserver(func(key string, answered, peers int) {
		fired++
		gotKey, gotAnswered, gotPeers = key, answered, peers
	})
	// node-c is genuinely dead: it takes the connection and never replies, so no
	// budget recovers it.
	s.peerClientOverride = mixedPeers(
		map[string]int64{"node-b": 4},
		map[string]bool{"node-c": true},
	)

	if _, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover); !ok {
		t.Fatal("sweep refused although node-b carried the quorum")
	}

	if fired == 0 {
		t.Fatal("an accept was reached without node-c answering and nothing recorded it; " +
			"the incomplete sweep is invisible to telemetry")
	}
	if gotKey != corrosion.LeaseKeyFailover {
		t.Errorf("key = %q, want %q", gotKey, corrosion.LeaseKeyFailover)
	}
	if gotAnswered != 1 || gotPeers != 2 {
		t.Errorf("answered/peers = %d/%d, want 1/2 — the counts must say how much of "+
			"the sweep was actually evidence", gotAnswered, gotPeers)
	}
}

// The mirror: a complete sweep must NOT be reported as incomplete, or the
// signal is noise and gets muted.
func TestLeaseTermBarrier_ACompleteSweepIsNotCounted(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 300*time.Millisecond, 20*time.Millisecond)

	fired := 0
	s := barrierNode(t, 4, 2, "node-b", "node-c")
	s.SetLeaseBarrierIncompleteObserver(func(string, int, int) { fired++ })
	s.peerClientOverride = mixedPeers(
		map[string]int64{"node-b": 4, "node-c": 4},
		nil,
	)

	if _, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover); !ok {
		t.Fatal("sweep refused although every peer answered")
	}
	if fired != 0 {
		t.Errorf("a complete sweep reported %d incomplete accepts", fired)
	}
}

// The repair pass shares the ONE budget the first fan-out already spent, so it
// is a no-op precisely when some other peer is the thing that hung.
//
// node-d carries the quorum, so the sweep accepts. node-c is not memoised and
// hangs, burning the whole budget. node-b IS memoised, holds the superseding
// term, and is alive — it just needs more than the 250ms probe. The repair
// exists for exactly node-b, and it cannot run, because the context it inherits
// is already expired.
//
// The accept is at the stale term and is byte-identical to a correct one.
func TestLeaseTermBarrier_TheRepairPassIsNotStarvedByAnotherPeersHang(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 300*time.Millisecond, 20*time.Millisecond)

	s := barrierNode(t, 4, 2, "node-b", "node-c", "node-d")
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		switch host {
		case "node-b":
			// Alive, slower than the probe, and holds the superseding term.
			return &fakeHighWaterPeer{term: 9, delay: 100 * time.Millisecond}, func() {}, nil
		case "node-c":
			// Takes the connection and never replies: burns the whole budget.
			return hangingHighWaterPeer{}, func() {}, nil
		case "node-d":
			return &fakeHighWaterPeer{term: 4}, func() {}, nil
		}
		return nil, nil, context.DeadlineExceeded
	}

	s.leaseBarrierMu.Lock()
	s.leaseBarrierSilent = map[string]time.Time{"node-b": time.Now()}
	s.leaseBarrierMu.Unlock()

	highest, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover)
	if !ok {
		t.Fatal("sweep refused although node-d carried the quorum")
	}
	if highest != 9 {
		t.Errorf("highest term = %d, want 9\n"+
			"node-b holds the superseding term and is alive. It was short-deadlined by "+
			"our own memo, and the repair that exists to undo that could not run because "+
			"node-c had already spent the shared budget. The barrier accepted a stale "+
			"term on evidence it chose not to collect.", highest)
	}
}

// Both barrier memos are keyed by host name, and every access — the TTL prune
// included — iterates the CURRENT peer list. An entry for a host that leaves the
// fleet is therefore never visited again, so the TTL that looks like it bounds
// these maps only ever runs for peers still present.
//
// It is unowned state that grows with fleet churn: every decommission, rename or
// re-IP leaves a key behind for the process lifetime.
func TestLeaseTermBarrier_MemosForDepartedPeersAreForgotten(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 300*time.Millisecond, 20*time.Millisecond)

	// node-b is the only peer the fleet still has.
	s := barrierNode(t, 4, 2, "node-b")
	s.peerClientOverride = mixedPeers(map[string]int64{"node-b": 4}, nil)

	// node-gone was decommissioned while memoised in BOTH maps.
	s.leaseBarrierMu.Lock()
	s.leaseBarrierSilent = map[string]time.Time{"node-gone": time.Now()}
	s.leaseBarrierFullProbe = map[string]time.Time{"node-gone": time.Now()}
	s.leaseBarrierMu.Unlock()

	if _, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover); !ok {
		t.Fatal("sweep refused although node-b answered")
	}

	s.leaseBarrierMu.Lock()
	_, stillSilent := s.leaseBarrierSilent["node-gone"]
	_, stillProbed := s.leaseBarrierFullProbe["node-gone"]
	s.leaseBarrierMu.Unlock()

	if stillSilent {
		t.Error("leaseBarrierSilent still holds a departed host; the TTL never runs for " +
			"a peer that is no longer in HealthyPeers, so the entry outlives the fleet " +
			"member forever")
	}
	if stillProbed {
		t.Error("leaseBarrierFullProbe still holds a departed host — the same unowned-state " +
			"shape, introduced alongside the repair bound")
	}
}
