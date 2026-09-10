package grpcapi

import (
	"context"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// leaseTermVerdict is the barrier's answer about one proof's term.
type leaseTermVerdict int

const (
	// leaseTermCurrent: the term is at or above the quorum-observed high-water
	// mark. Always the result of a FRESH sweep — never served from cache.
	leaseTermCurrent leaseTermVerdict = iota
	// leaseTermStale: fenced. The term is below quorum-observed history.
	leaseTermStale
	// leaseTermUnconfirmed: quorum could not be established, so whether the term
	// is stale is unknown. Refuses, and stays distinct from leaseTermStale.
	leaseTermUnconfirmed
)

func (v leaseTermVerdict) String() string {
	switch v {
	case leaseTermCurrent:
		return "current"
	case leaseTermStale:
		return "stale"
	default:
		return "unconfirmed"
	}
}

const (
	// leaseBarrierCacheTTL bounds how stale a cached threshold may be.
	//
	// It is NOT protecting the refusal path. A cached threshold was a real
	// observation and the true maximum only rises, so a refusal served from this
	// cache is correct however old the entry is — age cannot buy that path any
	// safety it does not already have, and every accept pays for a fresh sweep
	// regardless (see leaseTermBarrier).
	//
	// It exists for the one event that walks the observed high water BACKWARDS: a
	// reseed. A reseeding node loses exactly the terms its reseed source never
	// received, so its ledger's maximum can legitimately drop, and a pre-reseed
	// observation left in cache would refuse proofs the post-reseed ledger
	// considers current. This bounds that window, which makes it a small fixed
	// constant rather than a fraction of any lease TTL — the three consumers keep
	// deliberately different TTLs (leaseDuration, 2*interval, 2*PollInterval), so
	// deriving from one would couple the barrier to whichever it borrowed from.
	// 3s matches health.capActiveNegTTL, the one short-lived negative cache
	// already in service.
	leaseBarrierCacheTTL = 3 * time.Second
	// leaseBarrierSilentTTL bounds how long a peer stays remembered as silent.
	//
	// It only has to span one reconciler pass, which is the burst this exists
	// for: internal/health's reconciler walks pending VMs SERIALLY, so a 40-VM
	// host loss makes 40 back-to-back accept sweeps, each of which used to wait
	// out the full budget on the same unreachable peer. Shorter than
	// reconcileInterval so a peer cannot stay remembered across two passes
	// without re-proving itself silent in between.
	leaseBarrierSilentTTL = 10 * time.Second
)

// The barrier's wall-clock budgets. These are vars rather than consts ONLY so
// tests can shrink them; nothing in production reassigns them. A test that had
// to spend real seconds to observe the burst behaviour would be too slow to run
// on every change, which is how a cost bound stops being checked.
var (
	// leaseBarrierBudget bounds ONE sweep in total — not per peer. A per-peer
	// timeout of this length would multiply by the fleet size exactly when the
	// fleet is unreachable, which is when the barrier runs.
	//
	// (leaseBarrierSilentProbe is a per-peer deadline, but a much shorter one and
	// only for a peer that already proved silent; the fan-out is concurrent and
	// still sits inside this budget, so it cannot multiply either.)
	leaseBarrierBudget = 3 * time.Second

	// leaseBarrierSilentProbe is the deadline given to a peer that gave no answer
	// on this node's previous sweep for the same key.
	//
	// The RPC it serves is one SELECT MAX over an append-only table, so a healthy
	// peer on a cluster network answers in single-digit milliseconds; this is two
	// orders of magnitude of headroom. A peer that needs longer than this WHILE
	// having already missed an entire 3s budget is indistinguishable, from here,
	// from one that is gone.
	//
	// Guessing wrong costs nothing that is not immediately repaired: a shortfall
	// re-runs the fan-out at full budget before refusing anything (see
	// runLeaseTermSweep), so the memo can only ever accelerate a sweep that was
	// already going to succeed, and total cost stays inside leaseBarrierBudget.
	leaseBarrierSilentProbe = 250 * time.Millisecond
)

type leaseBarrierEntry struct {
	threshold int64
	at        time.Time
}

// leaseBarrierSweep is one in-flight sweep that concurrent callers share.
//
// Without this, a host loss with 40 workloads runs 40 independent fan-outs,
// each paying the full budget whenever any peer is unreachable — and an
// unreachable peer is the defining condition of a failover. Callers that want
// the same answer to the same question at the same moment wait on one.
//
// startedAt is what makes "at the same moment" checkable rather than assumed.
// A sweep's answer is evidence gathered from startedAt onwards, and the
// asymmetry leaseTermBarrier is built on says a threshold may be used to REFUSE
// however old it is, but may only be used to ACCEPT if it was gathered after
// the accepting caller began validating: the true maximum only rises, so an
// older observation is a lower bound, and accepting from a lower bound admits
// work the current truth would have fenced. A caller that arrived after this
// sweep's reads began is in exactly that position, so it does not share this
// answer — it waits for the next one. Without the timestamp the sharing quietly
// reintroduced the defect the cache asymmetry exists to prevent, one layer up.
type leaseBarrierSweep struct {
	done      chan struct{}
	startedAt time.Time
	threshold int64
	ok        bool
}

// leaseTermBarrier judges `term` against the quorum-observed high-water mark for
// key, returning the verdict and the threshold it was judged against.
//
// THE CACHE IS ASYMMETRIC, and the asymmetry is derived rather than a
// convention. The high-water term is monotone: it only increases. So a cached
// threshold is a LOWER BOUND on the truth.
//
//   - Refusing from a lower bound is sound. If cached > term then the true
//     maximum is at least cached, so the term really is superseded.
//   - Accepting from a lower bound is not. The true maximum may have advanced
//     past `term` since the cache was written, so an accept must always pay for
//     a fresh sweep.
//
// (health.CapabilityActive implements the same "cache the negative, never the
// positive" split by convention. Here it falls out of monotonicity, which is a
// better reason and a load-bearing one — see the cache tests.)
func (s *Server) leaseTermBarrier(ctx context.Context, key string, term int64) (leaseTermVerdict, int64) {
	if cached, ok := s.cachedLeaseThreshold(key); ok && term < cached {
		return leaseTermStale, cached
	}
	threshold, ok := s.sweepLeaseTermHighWater(ctx, key)
	if !ok {
		return leaseTermUnconfirmed, 0
	}
	s.storeLeaseThreshold(key, threshold)
	if term < threshold {
		return leaseTermStale, threshold
	}
	return leaseTermCurrent, threshold
}

func (s *Server) cachedLeaseThreshold(key string) (int64, bool) {
	s.leaseBarrierMu.Lock()
	defer s.leaseBarrierMu.Unlock()
	e, ok := s.leaseBarrierCache[key]
	if !ok || time.Since(e.at) > leaseBarrierCacheTTL {
		return 0, false
	}
	return e.threshold, true
}

func (s *Server) storeLeaseThreshold(key string, threshold int64) {
	s.leaseBarrierMu.Lock()
	defer s.leaseBarrierMu.Unlock()
	if s.leaseBarrierCache == nil {
		s.leaseBarrierCache = make(map[string]leaseBarrierEntry, 1)
	}
	// Monotone WITHIN THE TTL: never let a lower observation replace a higher one
	// while the higher one is still live. A slow sweep finishing after a fast one
	// must not walk the bound backwards, and that reordering resolves in
	// milliseconds — far inside the TTL.
	//
	// The expiry check is LOAD-BEARING and must not be dropped as redundant with
	// cachedLeaseThreshold's. Clamping against an EXPIRED entry resurrects it:
	// the higher value is kept and `at` is re-stamped, so the entry never ages
	// out while traffic continues, and since every accept pays for a fresh sweep
	// (leaseTermBarrier), ordinary traffic renews it indefinitely. A post-reseed
	// threshold that legitimately drops from 6 to 4 would then refuse term-5
	// proofs forever — and the TTL, whose entire purpose is to bound exactly that
	// window, would bound nothing. Read expiry here or the constant is decorative.
	if e, ok := s.leaseBarrierCache[key]; ok &&
		time.Since(e.at) <= leaseBarrierCacheTTL && e.threshold > threshold {
		threshold = e.threshold
	}
	s.leaseBarrierCache[key] = leaseBarrierEntry{threshold: threshold, at: time.Now()}
}

// sweepLeaseTermHighWater asks a quorum of live hosts for their newest term for
// key and returns the highest answer. ok=false means quorum was NOT established,
// which is a refusal — never a pass, and never a threshold of 0.
//
// Concurrent callers for one key share ONE sweep. The alternative measured
// badly: a host loss with 40 workloads produced 40 independent fan-outs, each
// paying the full budget because a dead peer does not fail fast — pki.PeerDial
// wraps grpc.NewClient, which is lazy, so the dial returns immediately and the
// RPC blocks until the deadline. Serialised across a recovery that is
// ~2 minutes of added latency at the one moment the system is meant to be fast.
// Sharing collapses it to one budget for the whole burst.
//
// It deliberately does NOT return early once `answers >= needed`. That was
// offered as a way to bound the cost and it is the wrong trade here: the
// barrier's entire job is to find a term HIGHER than this node's own replica,
// and stopping at the first quorum-sized set of answers discards exactly the
// evidence it went looking for — an accept that a complete sweep would have
// refused. A quorum read only intersects a quorum write, and a term is minted
// by one node's guarded upsert plus CRDT replication, so there is no
// intersection guarantee to lean on. Every reachable peer is asked.
func (s *Server) sweepLeaseTermHighWater(ctx context.Context, key string) (int64, bool) {
	if s.gate == nil {
		return 0, false
	}

	// The instant this caller began validating. Only evidence gathered from here
	// onwards can authorise it; see leaseBarrierSweep.startedAt.
	arrived := time.Now()

	// A seam for the sharing test, nil everywhere else.
	//
	// Whether a burst of callers SHARES one sweep depends on them arriving before
	// the first of them publishes its flight — which is the accept-safety rule
	// working as designed, not a tunable. A test cannot establish that premise
	// with a sleep: under GOMAXPROCS=1 the callers serialise, each arrives after
	// the previous sweep began, and every one of them correctly pays for its own.
	// The cost-bound assertion then fails on a single-CPU runner while the code
	// is behaving exactly as specified.
	if s.leaseBarrierArrived != nil {
		s.leaseBarrierArrived()
	}

	// Join an in-flight sweep for this key, or become the one that runs it.
	//
	// The loop exists for the caller that arrives mid-sweep. It waits out the
	// running sweep, discards that answer as predating it, and goes round to
	// either start a fresh sweep or join one that began after it arrived. It
	// terminates after at most one such wait — once the running sweep is gone,
	// the next flight this caller sees was necessarily created later than
	// `arrived` — and ctx bounds it regardless.
	for {
		s.leaseBarrierMu.Lock()
		if fl, ok := s.leaseBarrierFlight[key]; ok {
			s.leaseBarrierMu.Unlock()
			select {
			case <-fl.done:
				if !fl.startedAt.Before(arrived) {
					return fl.threshold, fl.ok
				}
				// Its reads began before we did. Reusing it here would accept
				// against a bound that may already have been superseded.
				continue
			case <-ctx.Done():
				// The caller gave up first. Unconfirmed, not a pass.
				return 0, false
			}
		}
		if s.leaseBarrierFlight == nil {
			s.leaseBarrierFlight = make(map[string]*leaseBarrierSweep, 1)
		}
		// startedAt is stamped here, under the lock that publishes the flight,
		// so it is never LATER than the first read runLeaseTermSweep issues.
		// Erring early is the safe direction: it can only make a joiner decide
		// the evidence predates it and pay for another sweep.
		fl := &leaseBarrierSweep{done: make(chan struct{}), startedAt: time.Now()}
		s.leaseBarrierFlight[key] = fl
		s.leaseBarrierMu.Unlock()

		defer func() {
			s.leaseBarrierMu.Lock()
			delete(s.leaseBarrierFlight, key)
			s.leaseBarrierMu.Unlock()
			close(fl.done)
		}()

		fl.threshold, fl.ok = s.runLeaseTermSweep(ctx, key)
		return fl.threshold, fl.ok
	}
}

// runLeaseTermSweep is one actual fan-out. Only ever called with this key's
// in-flight slot held.
func (s *Server) runLeaseTermSweep(ctx context.Context, key string) (int64, bool) {
	// Reuse the quorum every other gate in this path uses. Two different quorum
	// rules inside one failover decision would be a defect in itself.
	state, _, needed := s.gate.QuorumProof(ctx)
	if state != health.QuorumYes {
		return 0, false
	}
	// HealthyPeers already excludes peers whose last probe was not healthy
	// (capability.go filters on status plus a non-zero lastHealthyAt), so a host
	// that has been down for longer than a probe interval costs nothing here.
	// What remains is a host that died WITHIN the last interval, which is why
	// the budget still has to exist.
	peers := s.gate.HealthyPeers(ctx)

	sctx, cancel := context.WithTimeout(ctx, leaseBarrierBudget)
	defer cancel()

	// This node's own ledger is one answer. If we cannot read it we cannot
	// establish anything, so this is a refusal rather than a zero answer.
	local, err := corrosion.CurrentLeaseTerm(sctx, s.db, key)
	if err != nil {
		return 0, false
	}
	// Peers that gave no answer on this node's PREVIOUS sweep for this key are
	// probed on a short deadline rather than the full budget.
	//
	// HealthyPeers already drops a peer whose last probe failed, so what reaches
	// here is a peer that died within the health-probe interval — and that
	// residual is expensive in exactly one shape: the reconciler walks pending
	// VMs serially, so a 40-workload host loss makes 40 back-to-back accept
	// sweeps (every accept pays for a fresh sweep, by the cache asymmetry above),
	// and each one used to wait out the whole budget on the same dead peer.
	//
	// This does not change WHICH peers are asked, and it is not a circuit
	// breaker: a peer that has recovered still answers, because answering takes
	// milliseconds. The one thing it can cost is an answer from a peer that
	// recovered but is slow, which is repaired below rather than left to a retry.
	silent := s.recentlySilentPeers(peers)

	highest, answers, answered := s.fanOutHighWater(sctx, key, local, peers, silent)

	// A shortfall must never be caused by our own shortcut. If the quorum was
	// missed and any peer was short-deadlined, pay full price before refusing —
	// sctx still bounds the whole sweep, so this cannot exceed the budget a
	// single-pass sweep would have spent anyway.
	if answers < needed && len(silent) > 0 {
		highest, answers, answered = s.fanOutHighWater(sctx, key, local, peers, nil)
	}

	s.noteSilentPeers(peers, answered)

	if answers < needed {
		return 0, false
	}
	return highest, true
}

// fanOutHighWater asks every peer for key's high-water term in parallel and
// folds the answers into (highest, count). Peers named in `silent` get
// leaseBarrierSilentProbe instead of the caller's full deadline.
//
// Concurrent, unlike CapabilityActive's sequential sweep. Sequential is fine
// for a periodic capability check; here it would serialise one timeout per
// unreachable peer up to the whole budget, on the recovery path. The peer count
// is already bounded by the host table.
func (s *Server) fanOutHighWater(
	ctx context.Context, key string, local int64, peers []string, silent map[string]bool,
) (highest int64, answers int, answered map[string]bool) {
	highest, answers = local, 1 // this node's own ledger is one answer
	answered = make(map[string]bool, len(peers))

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()

			pctx := ctx
			if silent[peer] {
				var cancel context.CancelFunc
				pctx, cancel = context.WithTimeout(ctx, leaseBarrierSilentProbe)
				defer cancel()
			}

			cl, closer, derr := s.dialPeer(pctx, peer)
			if derr != nil {
				return // no answer; never agreement
			}
			defer closer()
			resp, rerr := cl.GetLeaseTermHighWater(pctx, &pb.GetLeaseTermHighWaterRequest{Key: key})
			// A transport error, a nil response, or an answer about a DIFFERENT key
			// all count as no answer. Following the repo's rule that unknown must
			// never read as covered, none of them may count as agreement at 0.
			if rerr != nil || resp == nil || resp.GetKey() != key {
				return
			}
			mu.Lock()
			answers++
			answered[peer] = true
			if t := resp.GetTerm(); t > highest {
				highest = t
			}
			mu.Unlock()
		}(peer)
	}
	wg.Wait()
	return highest, answers, answered
}

// recentlySilentPeers returns the subset of peers this node remembers answering
// nothing, within leaseBarrierSilentTTL.
func (s *Server) recentlySilentPeers(peers []string) map[string]bool {
	s.leaseBarrierMu.Lock()
	defer s.leaseBarrierMu.Unlock()
	if len(s.leaseBarrierSilent) == 0 {
		return nil
	}
	var out map[string]bool
	for _, p := range peers {
		at, ok := s.leaseBarrierSilent[p]
		if !ok {
			continue
		}
		if time.Since(at) > leaseBarrierSilentTTL {
			delete(s.leaseBarrierSilent, p)
			continue
		}
		if out == nil {
			out = make(map[string]bool, len(peers))
		}
		out[p] = true
	}
	return out
}

// noteSilentPeers records which peers answered nothing and forgets the ones that
// answered. Keyed by peer rather than by (peer, key) on purpose: silence here is
// a property of reaching the peer at all, and the three keys are served by one
// RPC on one connection.
func (s *Server) noteSilentPeers(peers []string, answered map[string]bool) {
	s.leaseBarrierMu.Lock()
	defer s.leaseBarrierMu.Unlock()
	for _, p := range peers {
		if answered[p] {
			delete(s.leaseBarrierSilent, p)
			continue
		}
		if s.leaseBarrierSilent == nil {
			s.leaseBarrierSilent = make(map[string]time.Time, len(peers))
		}
		s.leaseBarrierSilent[p] = time.Now()
	}
}
