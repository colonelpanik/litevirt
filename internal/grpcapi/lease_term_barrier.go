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
	// leaseBarrierBudget bounds ONE sweep in total — not per peer. A per-peer
	// timeout multiplies by the fleet size exactly when the fleet is unreachable,
	// which is when the barrier runs.
	leaseBarrierBudget = 3 * time.Second
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
)

type leaseBarrierEntry struct {
	threshold int64
	at        time.Time
}

// leaseBarrierSweep is one in-flight sweep that concurrent callers share.
//
// Without this, a host loss with 40 workloads runs 40 independent fan-outs,
// each paying the full budget whenever any peer is unreachable — and an
// unreachable peer is the defining condition of a failover. Every caller wants
// the same answer to the same question at the same moment, so they wait on one.
type leaseBarrierSweep struct {
	done      chan struct{}
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

	// Join an in-flight sweep for this key, or become the one that runs it.
	s.leaseBarrierMu.Lock()
	if fl, ok := s.leaseBarrierFlight[key]; ok {
		s.leaseBarrierMu.Unlock()
		select {
		case <-fl.done:
			return fl.threshold, fl.ok
		case <-ctx.Done():
			// The caller gave up first. Unconfirmed, not a pass.
			return 0, false
		}
	}
	fl := &leaseBarrierSweep{done: make(chan struct{})}
	if s.leaseBarrierFlight == nil {
		s.leaseBarrierFlight = make(map[string]*leaseBarrierSweep, 1)
	}
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
	highest, answers := local, 1

	// Concurrent, unlike CapabilityActive's sequential sweep. Sequential is fine
	// for a periodic capability check; here it would serialise one timeout per
	// unreachable peer up to the whole budget, on the recovery path. The peer
	// count is already bounded by the host table.
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			cl, closer, derr := s.dialPeer(sctx, peer)
			if derr != nil {
				return // no answer; never agreement
			}
			defer closer()
			resp, rerr := cl.GetLeaseTermHighWater(sctx, &pb.GetLeaseTermHighWaterRequest{Key: key})
			// A transport error, a nil response, or an answer about a DIFFERENT key
			// all count as no answer. Following the repo's rule that unknown must
			// never read as covered, none of them may count as agreement at 0.
			if rerr != nil || resp == nil || resp.GetKey() != key {
				return
			}
			mu.Lock()
			answers++
			if t := resp.GetTerm(); t > highest {
				highest = t
			}
			mu.Unlock()
		}(peer)
	}
	wg.Wait()

	if answers < needed {
		return 0, false
	}
	return highest, true
}
