package grpcapi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// answerThenHangPeer answers its first call and takes every later one without
// replying: a peer that was reachable for the first fan-out and died — or
// stalled — before the repair pass asked it again.
type answerThenHangPeer struct {
	pb.LiteVirtClient
	term  int64
	calls int64
}

func (p *answerThenHangPeer) GetLeaseTermHighWater(
	ctx context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption,
) (*pb.GetLeaseTermHighWaterResponse, error) {
	if atomic.AddInt64(&p.calls, 1) > 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: req.GetKey(), Term: p.term}, nil
}

// The repair pass re-runs the fan-out and REPLACES the first pass's result,
// re-seeding `highest` from this node's own ledger. Evidence the first pass
// already collected — a peer reporting a superseding term — is discarded if
// that peer gives no answer the second time.
//
// node-c answered term 9 in the first sweep, then stalled. The repair exists
// only to give the short-deadlined node-d its full-price ask; it must not
// forget what node-c already said. The observed maximum only rises, and the
// barrier had already observed that term 4 was superseded — accepting a
// term-5 proof afterwards defeats the fencing check on exactly the
// intermittent-peer failure it is supposed to survive.
func TestLeaseTermBarrier_TheRepairPassKeepsTheFirstSweepsHighWater(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 300*time.Millisecond, 20*time.Millisecond)

	nodeC := &answerThenHangPeer{term: 9}
	s := barrierNode(t, 4, 2, "node-b", "node-c", "node-d")
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		switch host {
		case "node-b":
			return &fakeHighWaterPeer{term: 4}, func() {}, nil
		case "node-c":
			return nodeC, func() {}, nil
		case "node-d":
			// Memoised silent below, and slower than the probe, so the first
			// sweep misses it and the repair pass runs.
			return &fakeHighWaterPeer{term: 4, delay: 100 * time.Millisecond}, func() {}, nil
		}
		return nil, nil, context.DeadlineExceeded
	}
	s.leaseBarrierMu.Lock()
	s.leaseBarrierSilent = map[string]time.Time{"node-d": time.Now()}
	s.leaseBarrierMu.Unlock()

	highest, ok := s.sweepLeaseTermHighWater(ctx, corrosion.LeaseKeyFailover)
	if !ok {
		t.Fatal("sweep refused although node-b and node-d carried the quorum")
	}
	if atomic.LoadInt64(&nodeC.calls) < 2 {
		t.Fatalf("fixture inert: node-c was asked %d time(s); the repair pass never ran, so "+
			"nothing here exercises it", nodeC.calls)
	}
	if highest != 9 {
		t.Errorf("highest term = %d, want 9\n"+
			"node-c reported term 9 in the first sweep and stalled during the repair. "+
			"The repair replaced the first sweep's maximum with one re-seeded from this "+
			"node's own ledger, so a superseding term the barrier had ALREADY OBSERVED "+
			"was forgotten and a term-5 proof is now accepted.", highest)
	}
}
