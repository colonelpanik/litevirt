package health

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Cluster-wide capability activation (Phase 1).
//
// CapabilityActive is recomputed from FRESH peer Pings (never from stale replicated
// rows): true only once every enforcement-relevant member advertises the token; if
// any is unreachable or lacks it, it's false (callers stay log-only + surface "HA
// degraded"). Enforced builds on that with a MONOTONE, per-token durable LATCH:
// once CapabilityActive has ever been confirmed, Enforced stays true (persisted to
// a marker file) even when a later Ping can't confirm — so a partition, which makes
// confirmation impossible, fails CLOSED rather than reverting to the legacy path.
// (The one-way latch is safe: a genuine downgrade during enforcement is an operator
// error surfaced as HA-degraded, not a reason to silently re-open the gate.)

// PeerPinger fresh-Pings a host and returns its advertised capability tokens.
// Injected from the daemon (grpcapi.Server.PeerCapabilities). An unreachable host
// returns an error so activation fails closed.
type PeerPinger func(ctx context.Context, host string) ([]string, error)

// capActivationTimeout bounds the fan-out of fresh Pings for one activation check.
const capActivationTimeout = 4 * time.Second

// capActiveNegTTL caches a NEGATIVE CapabilityActive result this long, so pre-latch
// Enforced() on hot paths doesn't re-fan-out every call. Short enough that a just-healed
// cluster activates promptly; only negatives are cached (a positive clears it + latches).
const capActiveNegTTL = 3 * time.Second

// capActivePosTTL caches a POSITIVE CapabilityActiveForHealth result this long. Only the
// post-latch HA monitor uses that wrapper (the activation path re-sweeps freshly), so a TTL
// longer than the negative one collapses its per-tick capability sweep across every voting
// peer to roughly once per window, while a capability regression on the latched cluster still
// surfaces within the TTL. Cleared on any negative (cacheNeg), so it never masks a regression.
const capActivePosTTL = 60 * time.Second

// SetPeerPinger injects the peer capability reader. Without it, no capability is
// ever active (every gate stays log-only) — fail closed.
func (c *Checker) SetPeerPinger(fn PeerPinger) {
	c.mu.Lock()
	c.peerPinger = fn
	c.mu.Unlock()
}

// peerCapTTL bounds how long a peer's advertised capabilities are cached before a
// fresh Ping — short enough to react to a downgrade, long enough to avoid a Ping
// storm from the (frequent) replication loop.
const peerCapTTL = 30 * time.Second

// SetActivationMarker sets the durable per-node marker BASE that latches
// "enforcement has activated". Each capability token gets its OWN marker file
// (base + "." + token) so features latch independently. Pre-loading existing
// markers at startup keeps enforcement ON across a restart during a partition (a
// restart must not silently re-open the legacy path).
func (c *Checker) SetActivationMarker(base string) {
	c.mu.Lock()
	c.activationMarkerBase = base
	if base != "" {
		for _, tok := range capabilities.All() {
			if _, err := os.Stat(markerPathFor(base, tok)); err == nil {
				c.activated[tok] = true
				c.activationPersisted[tok] = true // already durable — no re-write needed
			}
		}
	}
	c.mu.Unlock()
}

// markerPathFor derives a token's durable activation marker path from the base.
func markerPathFor(base, token string) string {
	return base + "." + token
}

// Enforced reports whether a fail-closed check for `token` must be enforced NOW.
// It LATCHES monotonically: once every enforcement-relevant member has advertised
// the token (CapabilityActive), enforcement stays on even if a later fresh Ping
// can't confirm it — so a partition (which makes confirmation impossible) fails
// CLOSED rather than reverting to the legacy ungated path, which would defeat the
// gate exactly when it is needed. The latch is persisted so a restart mid-partition
// can't reset it. The legacy (ungated) path is permitted ONLY before the first
// activation (a genuine mid-initial-roll, where no proofs exist yet).
func (c *Checker) Enforced(ctx context.Context, token string) bool {
	c.mu.Lock()
	already := c.activated[token]
	persisted := c.activationPersisted[token]
	base := c.activationMarkerBase
	c.mu.Unlock()
	if already {
		// Latched in-memory but the durable marker never landed (a prior disk
		// error): keep retrying so a restart before it persists can't re-open the
		// legacy path during a partition. Cheap — only until the write sticks.
		if base != "" && !persisted {
			c.persistActivationMarker(base, token)
		}
		return true
	}
	if active, _ := c.CapabilityActive(ctx, token); !active {
		return false
	}
	c.mu.Lock()
	c.activated[token] = true
	c.mu.Unlock()
	if base != "" {
		c.persistActivationMarker(base, token)
	}
	return true
}

// persistActivationMarker writes a token's durable activation latch. On failure it
// logs loudly and leaves activationPersisted[token] false so the next Enforced call
// retries — a silently-lost marker would let a restart mid-partition revert to the
// legacy ungated path, exactly the failure the latch exists to prevent.
func (c *Checker) persistActivationMarker(base, token string) {
	if err := os.WriteFile(markerPathFor(base, token), []byte("1\n"), 0o600); err != nil {
		slog.Error("split-brain: failed to persist activation latch — enforcement will not survive a daemon restart until this write succeeds; retrying next cycle",
			"token", token, "path", markerPathFor(base, token), "error", err)
		return
	}
	c.mu.Lock()
	c.activationPersisted[token] = true
	c.mu.Unlock()
}

// PeerSupports reports whether `peer` advertises `token`, using a fresh Ping CACHED
// for peerCapTTL. Fail-closed: no pinger, an unreachable peer, or a peer that
// advertises nothing all yield false. The cache makes this cheap for the
// HIGH-FREQUENCY WAL proof filter (avoids a Ping storm from the replication loop).
//
// It is NOT suitable for proof MINT sites: a cached positive can be up to peerCapTTL
// stale, so a target that advertised then was downgraded/replaced/de-advertised
// within the window would still pass — exactly the regression the mint-site check
// must catch. Mint sites use PeerSupportsFresh (uncached) instead.
func (c *Checker) PeerSupports(ctx context.Context, peer, token string) bool {
	c.mu.Lock()
	if e, ok := c.peerCaps[peer]; ok && time.Since(e.fetchedAt) < peerCapTTL {
		c.mu.Unlock()
		return capabilities.Has(e.caps, token)
	}
	c.mu.Unlock()
	return c.PeerSupportsFresh(ctx, peer, token)
}

// PeerSupportsFresh is PeerSupports WITHOUT the cache read: it always issues a fresh
// Ping (fail-closed on nil pinger / unreachable). Used at proof MINT sites so a
// target that advertised within the last peerCapTTL but has since regressed is
// caught immediately and never stamped a proof it can't honor. The fresh result
// still refreshes the cache for subsequent cheap PeerSupports reads.
// HealthyPeers returns the peers this daemon currently counts toward quorum: probed healthy
// at least once THIS run AND currently voting-eligible by host state (the SAME two predicates
// QuorumProof applies — probe freshness + votingEligible). A peer since marked
// offline/maintenance/fenced is therefore excluded, matching the "quorum-counted this run"
// relay constraint. Used to pick a "quorum-visible" relay peer for the VIP absence proof (the
// caller still confirms reachability by dialing it). Fail closed: if the host table can't be
// read, trust nobody as a relay.
func (c *Checker) HealthyPeers(ctx context.Context) []string {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil
	}
	eligible := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if votingEligible(h.State) {
			eligible[h.Name] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for name, ps := range c.peers {
		if eligible[name] && ps.status == "healthy" && !ps.lastHealthyAt.IsZero() {
			out = append(out, name)
		}
	}
	return out
}

func (c *Checker) PeerSupportsFresh(ctx context.Context, peer, token string) bool {
	c.mu.Lock()
	pinger := c.peerPinger
	c.mu.Unlock()
	if pinger == nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, capActivationTimeout)
	defer cancel()
	caps, err := pinger(pctx, peer)
	if err != nil {
		return false // fail-closed; don't cache a failure
	}
	c.mu.Lock()
	c.peerCaps[peer] = peerCapEntry{caps: caps, fetchedAt: time.Now()}
	c.mu.Unlock()
	return capabilities.Has(caps, token)
}

// CapabilityActive reports whether `token` is advertised by every
// enforcement-relevant member (non-deleted, non-fenced, non-maintenance,
// non-offline — i.e. votingEligible), computed from fresh Pings. On any
// unreachable or unsupporting relevant member it returns (false, reason) so the
// caller stays log-only and surfaces HA-degraded. Recomputed every call.
func (c *Checker) CapabilityActive(ctx context.Context, token string) (bool, string) {
	c.mu.Lock()
	pinger := c.peerPinger
	if e, ok := c.capActiveNeg[token]; ok && time.Since(e.at) < capActiveNegTTL {
		c.mu.Unlock()
		return false, e.reason // recent negative → skip the fresh-Ping fan-out (fail closed)
	}
	c.mu.Unlock()
	if pinger == nil {
		return c.cacheNeg(token, ReasonActivationUnconfirm)
	}

	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return c.cacheNeg(token, ReasonActivationUnconfirm)
	}

	pctx, cancel := context.WithTimeout(ctx, capActivationTimeout)
	defer cancel()

	for _, h := range hosts {
		if !votingEligible(h.State) {
			continue // decommissioned/offline/maintenance/fenced don't gate enforcement
		}
		caps, err := pinger(pctx, h.Name)
		if err != nil {
			// Unreachable enforcement-relevant member — can't confirm support.
			return c.cacheNeg(token, ReasonActivationUnconfirm)
		}
		if !capabilities.Has(caps, token) {
			return c.cacheNeg(token, ReasonUnsupportedCapability)
		}
	}
	// Positive: clear any cached negative so the latch reacts immediately. NB the positive
	// is NOT cached here — this is the activation path (Enforced) and must re-sweep freshly
	// every call; only CapabilityActiveForHealth caches positives, for the HA monitor.
	c.mu.Lock()
	delete(c.capActiveNeg, token)
	c.mu.Unlock()
	return true, ""
}

// CapabilityActiveForHealth is CapabilityActive with a POSITIVE-result cache, for the
// periodic HA-degraded monitor ONLY (RunHAHealthMonitor). It must NEVER be used on the
// activation path: Enforced needs a fresh sweep so the latch can't turn on from a stale
// positive. The positive is cached for capActivePosTTL and cleared on ANY negative (cacheNeg,
// invoked by the fresh CapabilityActive below or any other caller), so a capability
// regression still surfaces within the TTL.
func (c *Checker) CapabilityActiveForHealth(ctx context.Context, token string) (bool, string) {
	c.mu.Lock()
	if at, ok := c.capActivePos[token]; ok && time.Since(at) < capActivePosTTL {
		c.mu.Unlock()
		return true, "" // recent positive → skip the fan-out (a regression still surfaces within capActivePosTTL)
	}
	c.mu.Unlock()
	ok, reason := c.CapabilityActive(ctx, token)
	if ok {
		c.mu.Lock()
		c.capActivePos[token] = time.Now()
		c.mu.Unlock()
	}
	return ok, reason
}

// cacheNeg records a negative CapabilityActive result for capActiveNegTTL and returns it.
func (c *Checker) cacheNeg(token, reason string) (bool, string) {
	c.mu.Lock()
	c.capActiveNeg[token] = capNegEntry{reason: reason, at: time.Now()}
	delete(c.capActivePos, token) // a negative invalidates any cached positive (fail-closed)
	c.mu.Unlock()
	return false, reason
}
