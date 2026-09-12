package grpcapi

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"google.golang.org/grpc"
)

// fakeHighWaterPeer answers GetLeaseTermHighWater and nothing else. The
// embedded nil interface satisfies the rest of pb.LiteVirtClient, which is the
// package's existing convention for peer doubles.
type fakeHighWaterPeer struct {
	pb.LiteVirtClient
	term     int64
	key      string        // when set, the key this peer answers ABOUT (to fake a wrong-key answer)
	delay    time.Duration // block before answering, to fake an unreachable peer
	err      error
	requests *int64 // optional call counter
}

func (f *fakeHighWaterPeer) GetLeaseTermHighWater(ctx context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption) (*pb.GetLeaseTermHighWaterResponse, error) {
	if f.requests != nil {
		atomic.AddInt64(f.requests, 1)
	}
	if f.delay > 0 {
		// An unreachable peer does NOT fail fast: pki.PeerDial wraps
		// grpc.NewClient, which is lazy, so the dial returns immediately and the
		// call blocks until the deadline. That is what this reproduces.
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	key := req.GetKey()
	if f.key != "" {
		key = f.key
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: key, Term: f.term, Holder: "node-x"}, nil
}

// fakePeers wires a peer-name → newest-term map.
func fakePeers(terms map[string]int64) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		term, ok := terms[host]
		if !ok {
			return nil, nil, context.DeadlineExceeded
		}
		return &fakeHighWaterPeer{term: term}, func() {}, nil
	}
}

// countingPeers is fakePeers that records how many answers it served, so a test
// can assert a cached refusal cost no fan-out.
func countingPeers(calls *int64, terms map[string]int64) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		term, ok := terms[host]
		if !ok {
			return nil, nil, context.DeadlineExceeded
		}
		return &fakeHighWaterPeer{term: term, requests: calls}, func() {}, nil
	}
}

// unreachablePeers fails every dial.
func unreachablePeers() func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, context.DeadlineExceeded
	}
}

// fakePeersAnsweringKey answers about a DIFFERENT key than the one requested.
func fakePeersAnsweringKey(key string, terms map[string]int64) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		term, ok := terms[host]
		if !ok {
			return nil, nil, context.DeadlineExceeded
		}
		return &fakeHighWaterPeer{term: term, key: key}, func() {}, nil
	}
}

// barrierNode is a server with a seeded local ledger and a quorum-holding gate.
func barrierNode(t *testing.T, localTerm int64, needed int, peers ...string) *Server {
	t.Helper()
	s := inventoryServer(t)
	if localTerm > 0 {
		if held, term, err := corrosion.AcquireLeaseWithTerm(context.Background(), s.db,
			corrosion.LeaseKeyFailover, "node-a", 30*time.Second,
			time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)); err != nil || !held {
			t.Fatalf("seed lease: held=%v term=%d err=%v", held, term, err)
		}
		// Walk the ledger up to localTerm with successive lapsed tenures, using
		// the real allocator rather than inserting rows.
		now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
		for term := int64(2); term <= localTerm; term++ {
			now = now.Add(2 * time.Minute)
			if held, got, err := corrosion.AcquireLeaseWithTerm(context.Background(), s.db,
				corrosion.LeaseKeyFailover, "node-a", 30*time.Second, now); err != nil || !held || got != term {
				t.Fatalf("seed term %d: held=%v got=%d err=%v", term, held, got, err)
			}
		}
	}
	s.SetGate(fakeServerGate{quorum: health.QuorumYes, needed: needed, healthy: peers})
	return s
}

// TestLeaseTermBarrier_APeerHigherTermBeatsTheLocalReplica is the single case
// the whole barrier exists for. The executor's own ledger says 4, a quorum peer
// answers 6, and a term-5 proof must be refused.
func TestLeaseTermBarrier_APeerHigherTermBeatsTheLocalReplica(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 4, 2, "node-c")
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 6})

	verdict, threshold := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5)
	if verdict != leaseTermStale {
		t.Errorf("verdict = %v (threshold %d), want stale — the local MAX is 4 but a quorum "+
			"peer holds 6, so term 5 is superseded", verdict, threshold)
	}
	if threshold != 6 {
		t.Errorf("threshold = %d, want 6 (the highest across all answers)", threshold)
	}
}

// TestLeaseTermBarrier_QuorumShortfallRefuses. Failing OPEN here would be worse
// than having no barrier at all: it would present as protection while providing
// none.
func TestLeaseTermBarrier_QuorumShortfallRefuses(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 4, 3, "node-c")
	s.peerClientOverride = unreachablePeers()

	verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5)
	if verdict != leaseTermUnconfirmed {
		t.Errorf("verdict = %v, want unconfirmed — 1 answer against a needed 3 must refuse, "+
			"and must be distinguishable from a stale-term refusal", verdict)
	}
}

// TestLeaseTermBarrier_QuorumUnknownRefuses: QuorumProof is tri-state, and
// Unknown means "neither proof nor loss". This is a gate, so it fails closed.
func TestLeaseTermBarrier_QuorumUnknownRefuses(t *testing.T) {
	ctx := context.Background()
	s := inventoryServer(t)
	s.SetGate(fakeServerGate{quorum: health.QuorumUnknown, needed: 1})

	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5); verdict != leaseTermUnconfirmed {
		t.Errorf("verdict = %v on QuorumUnknown, want unconfirmed", verdict)
	}
}

// TestLeaseTermBarrier_NoGateRefuses: nothing wired means nothing established.
func TestLeaseTermBarrier_NoGateRefuses(t *testing.T) {
	s := inventoryServer(t)
	s.gate = nil
	if verdict, _ := s.leaseTermBarrier(context.Background(), corrosion.LeaseKeyFailover, 5); verdict != leaseTermUnconfirmed {
		t.Errorf("verdict = %v with no gate, want unconfirmed", verdict)
	}
}

// TestLeaseTermBarrier_AMalformedAnswerIsNotAgreement: a peer answering about a
// different key, or erroring, counts as no answer — never as agreement, and
// never as term 0.
func TestLeaseTermBarrier_AMalformedAnswerIsNotAgreement(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 0, 2, "node-c")
	s.peerClientOverride = fakePeersAnsweringKey(corrosion.LeaseKeyRebalancer, map[string]int64{"node-c": 9})

	verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5)
	if verdict != leaseTermUnconfirmed {
		t.Errorf("verdict = %v, want unconfirmed — an answer about another key is no answer, "+
			"so quorum was never reached", verdict)
	}
}

// TestLeaseTermBarrier_AcceptsAtOrAboveTheThreshold: the barrier must not refuse
// everything. A term equal to the threshold is the ordinary current-tenure case.
func TestLeaseTermBarrier_AcceptsAtOrAboveTheThreshold(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 6, 2, "node-c")
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 6})

	if verdict, th := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 6); verdict != leaseTermCurrent {
		t.Errorf("verdict = %v (threshold %d) for a term EQUAL to the threshold, want current", verdict, th)
	}
}

// TestLeaseTermBarrier_TheCacheNeverTurnsARefusalIntoAnAccept pins the
// monotonicity argument that makes the cache safe at all.
//
// The high-water term only increases, so a cached value is a LOWER BOUND on the
// truth. Refusing from a lower bound is sound: if cached > term, the true
// maximum is at least that. ACCEPTING from one is not: the true maximum may have
// moved past the proof's term since the cache was written. So an accept always
// costs a fresh sweep.
func TestLeaseTermBarrier_TheCacheNeverTurnsARefusalIntoAnAccept(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 4, 2, "node-c")

	// Warm the cache at threshold 4.
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 4})
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5); verdict != leaseTermCurrent {
		t.Fatalf("warmup: verdict = %v, want current", verdict)
	}

	// The truth advances to 6 while the cache still says 4.
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 6})
	if verdict, th := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5); verdict != leaseTermStale {
		t.Errorf("verdict = %v (threshold %d), want stale. Serving an ACCEPT from the cached "+
			"lower bound accepts a proof a fresh sweep would refuse", verdict, th)
	}
}

// TestLeaseTermBarrier_ACachedThresholdCanRefuseWithoutASweep is the other half:
// the cache must actually be used, or it is dead weight on the recovery path.
func TestLeaseTermBarrier_ACachedThresholdCanRefuseWithoutASweep(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 6, 2, "node-c")

	var sweeps int64
	s.peerClientOverride = countingPeers(&sweeps, map[string]int64{"node-c": 6})
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 6); verdict != leaseTermCurrent {
		t.Fatalf("warmup: want current")
	}
	before := atomic.LoadInt64(&sweeps)

	// A term below the cached threshold is refusable from the cache alone.
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 2); verdict != leaseTermStale {
		t.Fatal("a term below the cached threshold must be refused")
	}
	if got := atomic.LoadInt64(&sweeps); got != before {
		t.Errorf("the cached refusal cost a fresh sweep (%d → %d); on a 40-VM failover that is "+
			"40 avoidable fan-outs on the recovery path", before, got)
	}
}

// TestLeaseTermBarrier_ThresholdDoesNotRegressWithinTheTTL pins the clamp's
// actual job: a slow sweep landing after a fast one must not walk the bound
// backwards. That reordering resolves in milliseconds, so the clamp only ever
// needs to hold inside the TTL — which is exactly as far as it may reach.
//
// THE MIDDLE QUERY MUST BE AT THE CACHED THRESHOLD, not below it. Asking about
// a lower term short-circuits on the cached-refusal fast path and returns
// before any sweep runs, so the clamp is never reached and the test passes with
// the clamp deleted — verified by mutation. Querying AT the threshold forces a
// fresh sweep, which is the only way the lower observation reaches
// storeLeaseThreshold at all, and only then does the third query reveal which
// value was kept.
func TestLeaseTermBarrier_ThresholdDoesNotRegressWithinTheTTL(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 0, 2, "node-c")

	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 6})
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 6); verdict != leaseTermCurrent {
		t.Fatalf("warmup at 6: want current")
	}

	// A reordered slow sweep answers lower. Queried AT the cached threshold, so
	// it takes the sweep path and the answer reaches the clamp.
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 4})
	if verdict, got := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 6); verdict != leaseTermCurrent {
		t.Fatalf("term 6 judged %v against threshold %d, want current", verdict, got)
	}

	// The bound must still be 6, which only shows up now: term 5 is below 6 and
	// above the lower observation, so it is refused if and only if the clamp
	// held.
	if verdict, got := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5); verdict != leaseTermStale {
		t.Errorf("term 5 judged %v against threshold %d; a reordered slow sweep walked a live "+
			"bound backwards from 6 to 4", verdict, got)
	}
}

// TestLeaseTermBarrier_ThresholdAdoptsARegressionAfterTheTTL is what makes
// leaseBarrierCacheTTL mean anything at all.
//
// A reseed is the one event that walks the observed high water BACKWARDS: the
// node loses exactly the terms its reseed source never received, so its
// ledger's maximum legitimately drops. The TTL exists to bound how long a
// pre-reseed observation can keep refusing proofs the post-reseed cluster
// considers current.
//
// The clamp in storeLeaseThreshold must therefore read expiry. Clamping against
// an EXPIRED entry keeps the higher value AND re-stamps `at`, so the entry never
// ages out — and because every accept pays for a fresh sweep, ordinary traffic
// renews it forever. The second half of this test is the one that catches that:
// a single post-expiry sweep is not enough, because the bug only shows once the
// renewed entry is consulted again.
func TestLeaseTermBarrier_ThresholdAdoptsARegressionAfterTheTTL(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 0, 2, "node-c")

	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 6})
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 6); verdict != leaseTermCurrent {
		t.Fatalf("warmup at 6: want current")
	}

	// Age the cached observation past the TTL, in-package rather than by sleeping.
	s.leaseBarrierMu.Lock()
	e := s.leaseBarrierCache[corrosion.LeaseKeyFailover]
	e.at = time.Now().Add(-2 * leaseBarrierCacheTTL)
	s.leaseBarrierCache[corrosion.LeaseKeyFailover] = e
	s.leaseBarrierMu.Unlock()

	// Post-reseed the quorum answers lower. Term 5 is current again.
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 4})
	for i, want := range []leaseTermVerdict{leaseTermCurrent, leaseTermCurrent} {
		verdict, got := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 5)
		if verdict != want {
			t.Fatalf("sweep %d: term 5 judged %v against threshold %d, want %v — an EXPIRED "+
				"threshold that survives its own TTL refuses valid proofs forever, because each "+
				"accept's fresh sweep re-stamps it", i+1, verdict, got, want)
		}
	}
}

// TestLeaseTermBarrier_ConcurrentCallersShareOneSweep is the accept path's cost
// bound, and it is the one the original design did not have.
//
// An accept can never be served from cache (see above), so every accepted proof
// pays for a fresh sweep. A dead peer does not fail fast — pki.PeerDial wraps
// grpc.NewClient, which is lazy, so the dial returns at once and the RPC blocks
// until the deadline — and an unreachable peer is the DEFINING condition of a
// failover. Without sharing, a host loss with 40 workloads ran 40 independent
// fan-outs, each paying the full 3s budget: roughly two minutes of serialised
// latency added to recovery, at the one moment the system is meant to be fast.
//
// The fix is deliberately NOT "return once answers >= needed". That would bound
// the cost by discarding the very evidence the barrier exists to find — a peer
// holding a HIGHER term than this node's replica — turning a refusal a complete
// sweep would have produced into an accept.
func TestLeaseTermBarrier_ConcurrentCallersShareOneSweep(t *testing.T) {
	s := barrierNode(t, 4, 2, "node-c")

	var served int64
	release := make(chan struct{})
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &blockingPeer{term: 6, requests: &served, gate: release}, func() {}, nil
	}

	const callers = 20

	// Every caller must have ARRIVED before any of them starts reading —
	// otherwise the ones that arrive mid-sweep correctly pay for their own, and
	// this measures the scheduler rather than the sharing.
	//
	// This used to be a 100ms sleep, which held only because a multi-core
	// scheduler happened to interleave the callers. Pinned to one CPU the
	// callers serialise, all 20 ran their own sweep, and the assertion below
	// failed 20 times out of 20 against code doing exactly what it specifies.
	// The seam makes the premise a fact of the test rather than a hope about
	// the runtime.
	arrivedAll := make(chan struct{})
	var arrivals int64
	s.leaseBarrierArrived = func() {
		if atomic.AddInt64(&arrivals, 1) == callers {
			close(arrivedAll)
		}
		<-arrivedAll
	}

	var wg sync.WaitGroup
	verdicts := make([]leaseTermVerdict, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			verdicts[i], _ = s.leaseTermBarrier(context.Background(), corrosion.LeaseKeyFailover, 5)
		}(i)
	}

	<-arrivedAll // all 20 are past the arrival stamp; one will now publish a flight
	close(release)
	wg.Wait()

	// Sharing is bounded by SWEEP GENERATIONS, not by callers, and a burst costs
	// at most a small constant number of them. It is deliberately not exactly
	// one: admission to a batch closes when that batch begins its reads, because
	// a caller that arrived afterwards cannot be ACCEPTED on evidence gathered
	// before it existed (see leaseBarrierSweep.startedAt). Callers that miss a
	// batch queue up and are served by the NEXT one together — which is what
	// keeps this O(generations) instead of O(callers).
	const maxGenerations = 3
	if got := atomic.LoadInt64(&served); got < 1 || got > maxGenerations {
		t.Errorf("%d callers produced %d peer fan-outs, want between 1 and %d. Each unshared "+
			"sweep pays the full %s budget when a peer is unreachable, which is exactly "+
			"the failover case", callers, got, maxGenerations, leaseBarrierBudget)
	}
	for i, v := range verdicts {
		if v != leaseTermStale {
			t.Errorf("caller %d got %v, want stale — every caller must get a real sweep's "+
				"answer, not a degraded one", i, v)
		}
	}
}

// TestLeaseTermBarrier_ALateCallerIsNotAcceptedOnAPreArrivalSweep: joining an
// in-flight sweep must not accept a proof against evidence gathered before that
// proof was being judged.
//
// The sharing optimisation reintroduced, one layer up, the exact defect the
// cache asymmetry exists to prevent. leaseTermBarrier's whole premise is that a
// threshold may REFUSE however old it is — the true maximum only rises, so an
// old observation is a lower bound — but may only ACCEPT if it is current.
// Letting any arriving caller reuse an already-reading sweep's result made
// every late arrival an accept from a lower bound.
//
// Here the quorum's high water moves from 4 to 6 while the first sweep is still
// blocked on a peer. The early caller is legitimately accepted at term 5: when
// its validation began, 4 really was the truth. The late caller must not be,
// because by the time it arrived the cluster had already minted 6.
func TestLeaseTermBarrier_ALateCallerIsNotAcceptedOnAPreArrivalSweep(t *testing.T) {
	s := barrierNode(t, 4, 2, "node-c")

	peer := &steppedPeer{
		entered: make(chan struct{}),
		gate:    make(chan struct{}),
		first:   4,
		later:   6,
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return peer, func() {}, nil
	}

	var early, late leaseTermVerdict
	var earlyThr, lateThr int64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		early, earlyThr = s.leaseTermBarrier(context.Background(), corrosion.LeaseKeyFailover, 5)
	}()

	// Block until the first sweep has actually begun reading. Everything after
	// this point arrives strictly later than that sweep's recorded start.
	<-peer.entered

	wg.Add(1)
	go func() {
		defer wg.Done()
		late, lateThr = s.leaseTermBarrier(context.Background(), corrosion.LeaseKeyFailover, 5)
	}()
	time.Sleep(50 * time.Millisecond) // let the late caller reach the barrier and queue

	close(peer.gate) // the first sweep answers 4; every later sweep answers 6
	wg.Wait()

	if early != leaseTermCurrent || earlyThr != 4 {
		t.Errorf("early caller got %v against threshold %d, want current against 4 — it began "+
			"validating before the sweep read, so that sweep's evidence authorises it",
			early, earlyThr)
	}
	if late != leaseTermStale {
		t.Errorf("late caller got %v against threshold %d, want stale against 6. It arrived "+
			"after the first sweep had already read, so sharing that answer accepted a "+
			"term-5 proof on a pre-term-6 observation — an accept from a lower bound, "+
			"which is the one thing this barrier must never do", late, lateThr)
	}
}

// steppedPeer answers a different term on its first call than on every later
// one, so a test can move the cluster's high water between sweep generations.
// The first call blocks until `gate` closes, and `entered` reports when it has
// begun — which is when the first sweep has committed to its reads.
type steppedPeer struct {
	pb.LiteVirtClient
	calls        int64
	entered      chan struct{}
	gate         chan struct{}
	first, later int64
	once         sync.Once
}

func (p *steppedPeer) GetLeaseTermHighWater(ctx context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption) (*pb.GetLeaseTermHighWaterResponse, error) {
	if atomic.AddInt64(&p.calls, 1) == 1 {
		p.once.Do(func() { close(p.entered) })
		select {
		case <-p.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &pb.GetLeaseTermHighWaterResponse{Key: req.GetKey(), Term: p.first, Holder: "node-c"}, nil
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: req.GetKey(), Term: p.later, Holder: "node-c"}, nil
}

// blockingPeer answers only once `gate` is closed, so a test can hold a sweep
// open while other callers arrive.
type blockingPeer struct {
	pb.LiteVirtClient
	term     int64
	requests *int64
	gate     chan struct{}
}

func (b *blockingPeer) GetLeaseTermHighWater(ctx context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption) (*pb.GetLeaseTermHighWaterResponse, error) {
	atomic.AddInt64(b.requests, 1)
	select {
	case <-b.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: req.GetKey(), Term: b.term, Holder: "node-c"}, nil
}

// shrinkBarrierKnobs scales the barrier's wall-clock budgets down so a burst is
// observable in milliseconds. Mirrors fence.shrinkVerifyKnobs.
func shrinkBarrierKnobs(t *testing.T, budget, silentProbe time.Duration) {
	t.Helper()
	origBudget, origProbe := leaseBarrierBudget, leaseBarrierSilentProbe
	leaseBarrierBudget, leaseBarrierSilentProbe = budget, silentProbe
	t.Cleanup(func() {
		leaseBarrierBudget, leaseBarrierSilentProbe = origBudget, origProbe
	})
}

// hangingHighWaterPeer accepts the call and then never answers, which is the
// shape that actually costs the budget. A dial failure is cheap; a peer that
// took the connection before it died is not.
type hangingHighWaterPeer struct {
	pb.LiteVirtClient
}

func (hangingHighWaterPeer) GetLeaseTermHighWater(
	ctx context.Context, _ *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption,
) (*pb.GetLeaseTermHighWaterResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// mixedPeers answers for the hosts in terms and hangs for every host in hang.
func mixedPeers(terms map[string]int64, hang map[string]bool) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if hang[host] {
			return hangingHighWaterPeer{}, func() {}, nil
		}
		term, ok := terms[host]
		if !ok {
			return nil, nil, context.DeadlineExceeded
		}
		return &fakeHighWaterPeer{term: term}, func() {}, nil
	}
}

// TestLeaseTermBarrier_ASerialBurstDoesNotPayTheBudgetPerProof is the cost bound
// Task 5 claimed and did not have.
//
// The claim was that singleflight bounds the accept-path cost. It does not, on
// the path this phase exists for: internal/health's reconciler walks pending VMs
// in ONE serial loop on one ticker, so two accepts are never in flight together
// and there is nothing for singleflight to coalesce. Every accept pays for a
// fresh sweep (the cache asymmetry means only refusals may be served from
// cache), so a 40-workload host loss used to serialise 40 full budgets — about
// two minutes of added latency at the one moment the system is supposed to be
// fast — whenever a peer had died within the health-probe interval and so was
// still in HealthyPeers.
//
// What bounds it is remembering that the peer answered nothing and probing it on
// leaseBarrierSilentProbe next time. This test measures the burst rather than
// asserting the mechanism, because the mechanism is not the promise.
func TestLeaseTermBarrier_ASerialBurstDoesNotPayTheBudgetPerProof(t *testing.T) {
	ctx := context.Background()
	const proofs = 6

	shrinkBarrierKnobs(t, 400*time.Millisecond, 20*time.Millisecond)

	// needed = 2, so node-b's answer carries the quorum and node-c is pure cost:
	// it took the connection and will never reply.
	s := barrierNode(t, 4, 2, "node-b", "node-c")
	s.peerClientOverride = mixedPeers(
		map[string]int64{"node-b": 4},
		map[string]bool{"node-c": true},
	)

	start := time.Now()
	for i := 0; i < proofs; i++ {
		verdict, threshold := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 4)
		if verdict != leaseTermCurrent {
			t.Fatalf("proof %d: verdict = %v (threshold %d), want current — the shortcut must "+
				"not change any verdict, only the time spent reaching it", i, verdict, threshold)
		}
	}
	elapsed := time.Since(start)

	perProof := leaseBarrierBudget * proofs
	// One full budget for the sweep that discovers the silence, then a short
	// probe each. Generous headroom for scheduling on a loaded machine, while
	// still an order of magnitude below the per-proof cost.
	bound := leaseBarrierBudget + time.Duration(proofs)*leaseBarrierSilentProbe*6
	t.Logf("%d serial accepts with one connected-but-silent peer: %v "+
		"(budget-per-proof would be %v; bound %v)", proofs, elapsed, perProof, bound)

	if elapsed > bound {
		t.Errorf("the burst took %v, over the %v bound — with %d proofs at a %v budget the "+
			"unbounded shape is %v, and a serial reconciler pass over a lost host's "+
			"workloads is exactly this shape at 40x",
			elapsed, bound, proofs, leaseBarrierBudget, perProof)
	}
}

// TestLeaseTermBarrier_ARecoveredPeerIsStillCountedBeforeRefusing: the shortcut
// must not be able to cause a refusal.
//
// A peer probed on the short deadline may have recovered and simply be slower
// than it — so a sweep that falls short of quorum re-runs the fan-out at full
// budget before refusing anything. Without that, a peer that is reachable but
// consistently slower than leaseBarrierSilentProbe would be memoed, missed,
// memoed again, and refuse every reschedule indefinitely while being perfectly
// healthy.
func TestLeaseTermBarrier_ARecoveredPeerIsStillCountedBeforeRefusing(t *testing.T) {
	ctx := context.Background()
	shrinkBarrierKnobs(t, 2*time.Second, 5*time.Millisecond)

	// needed = 2, and node-b is the ONLY peer, so its answer is mandatory.
	s := barrierNode(t, 4, 2, "node-b")

	// First sweep: node-b hangs, so the barrier cannot confirm and remembers it.
	s.peerClientOverride = mixedPeers(nil, map[string]bool{"node-b": true})
	if verdict, _ := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 4); verdict != leaseTermUnconfirmed {
		t.Fatalf("first sweep: verdict = %v, want unconfirmed", verdict)
	}
	if silent := s.recentlySilentPeers([]string{"node-b"}); !silent["node-b"] {
		t.Fatal("node-b answered nothing and was not remembered as silent, so the rest of " +
			"this test would prove nothing")
	}

	// It recovers, but answers slower than the short probe. The full-budget
	// re-run must find it rather than refusing on the shortcut's evidence.
	s.peerClientOverride = func(ctx context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "node-b" {
			return nil, nil, context.DeadlineExceeded
		}
		return slowHighWaterPeer{term: 4, delay: 60 * time.Millisecond}, func() {}, nil
	}
	verdict, threshold := s.leaseTermBarrier(ctx, corrosion.LeaseKeyFailover, 4)
	if verdict != leaseTermCurrent {
		t.Fatalf("verdict = %v (threshold %d), want current — node-b is healthy and merely "+
			"slower than leaseBarrierSilentProbe; refusing here would strand every "+
			"reschedule on a cluster whose peer is a little slow", verdict, threshold)
	}
	if silent := s.recentlySilentPeers([]string{"node-b"}); silent["node-b"] {
		t.Error("node-b answered and is still remembered as silent, so it will keep being " +
			"short-probed and every sweep will pay for the full-budget re-run")
	}
}

// slowHighWaterPeer answers correctly, after delay.
type slowHighWaterPeer struct {
	pb.LiteVirtClient
	term  int64
	delay time.Duration
}

func (f slowHighWaterPeer) GetLeaseTermHighWater(
	ctx context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption,
) (*pb.GetLeaseTermHighWaterResponse, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: req.GetKey(), Term: f.term, Holder: "node-b"}, nil
}
