package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

const (
	checkInterval    = 2 * time.Second
	checkTimeout     = 3 * time.Second
	suspectThreshold = 3
	// probeConcurrency caps how many peer health probes run at once per tick.
	probeConcurrency = 16
)

// peerState tracks the last known health state for a peer so we only write
// to the database on state transitions, not every tick.
//
// lastHealthyAt/lastFailureAt are LOCAL MONOTONIC anchors (time.Now, so they
// carry a monotonic reading): split-brain timing (Phase 2 self-demotion, Phase 5
// watchdog) must measure elapsed time by the local clock, never by comparing
// cross-node RFC3339 timestamps (which can be ±MaxSkew apart). They live only in
// memory, so a daemon restart deliberately resets them — a restart must re-earn
// its timing, not credit a pre-restart reading.
type peerState struct {
	status        string // "healthy" or "suspect"
	failures      int
	lastHealthyAt time.Time // monotonic; zero if never probed healthy
	lastFailureAt time.Time // monotonic; zero if never probed unhealthy
}

// Checker performs periodic health checks on peer hosts.
type Checker struct {
	hostName string
	pkiDir   string
	db       *corrosion.Client
	tlsCfg   *tls.Config

	mu     sync.Mutex
	peers  map[string]*peerState // target hostname → cached state
	crlVer int64                 // last published CRL version

	// Warmup / quorum-timing anchors (local monotonic; reset on restart).
	startedAt  time.Time // when Start began; bounds the Unknown warmup window
	probedOnce bool      // set true after the first full probe cycle completes

	// peerPinger fresh-Pings a peer for its capability tokens (SetPeerPinger).
	peerPinger PeerPinger
	// peerCaps caches each peer's advertised capabilities with a short TTL so the
	// replicator can gate proof replication per-peer without a Ping storm.
	peerCaps map[string]peerCapEntry

	// capActiveNeg caches a NEGATIVE CapabilityActive result per token for a short TTL, so
	// the frequent pre-latch Enforced() calls on hot paths (StartVM/MigrateVM/applyLBLocal,
	// the 2s demoter tick, owner-assert) don't re-fan-out fresh Pings every call. Only
	// negatives are cached — Enforced latches on the first positive, so there's no repeated
	// positive recompute to cache; the short TTL bounds how long a just-healed cluster waits
	// to activate.
	capActiveNeg map[string]capNegEntry

	// capActivePos caches a POSITIVE result per token for capActivePosTTL, populated and read
	// ONLY by CapabilityActiveForHealth — the post-latch HA monitor (evaluateHADegraded),
	// which would otherwise re-fan-out a fresh capability sweep across every voting peer on
	// every tick. The ACTIVATION path (CapabilityActive/Enforced) deliberately does NOT read
	// this — the latch must never turn on from a stale positive. A regression on an already-
	// latched cluster still surfaces within the TTL, and the entry is cleared the moment any
	// sweep yields a negative (cacheNeg), so a regression is never masked.
	capActivePos map[string]time.Time

	// activated latches, PER TOKEN, "enforcement has activated cluster-wide"
	// (monotone, durable via a per-token marker file) so a later partition fails
	// closed, not to legacy. Keyed by token so distinct features (Phase 2/4/5) latch
	// INDEPENDENTLY — a single global latch would conflate them. activationPersisted
	// tracks whether each token's durable marker write SUCCEEDED; a failed write is
	// retried on the next Enforced call (a lost marker would re-open the legacy path
	// across a restart during a partition). Per-token marker file = base + "." + token.
	activated            map[string]bool
	activationPersisted  map[string]bool
	activationMarkerBase string

	// selfFenced reports whether THIS node has self-fenced (tripped the watchdog) and is
	// waiting to reboot. When true, ExecutionGate AND DecisionGate fail closed regardless
	// of quorum/role — a doomed node must take no runtime-ownership decide/execute during
	// the fence-timeout window. Injected by the daemon from the watchdog controller;
	// nil-safe (unset → never fenced). This is the central chokepoint that also covers the
	// reconciler's startPendingVM and every other gate consumer.
	selfFenced func() bool
}

// SetSelfFenced injects the self-fenced predicate (Phase 2 defense-in-depth). nil-safe.
func (c *Checker) SetSelfFenced(fn func() bool) { c.selfFenced = fn }

// SelfFenced reports whether this node has self-fenced (nil predicate → false). Public so
// the reconcile/health loops can hard-gate runtime actions on it even on paths that don't
// consult Execution/DecisionGate (the markerless legacy path).
func (c *Checker) SelfFenced() bool { return c.isSelfFenced() }

// isSelfFenced reports whether this node has self-fenced (nil predicate → false).
func (c *Checker) isSelfFenced() bool { return c.selfFenced != nil && c.selfFenced() }

type peerCapEntry struct {
	caps      []string
	fetchedAt time.Time // local monotonic
}

type capNegEntry struct {
	reason string
	at     time.Time // local monotonic
}

// NewChecker creates a new health checker.
func NewChecker(hostName, pkiDir string, db *corrosion.Client) *Checker {
	return &Checker{
		hostName:            hostName,
		pkiDir:              pkiDir,
		db:                  db,
		peers:               make(map[string]*peerState),
		peerCaps:            make(map[string]peerCapEntry),
		capActiveNeg:        make(map[string]capNegEntry),
		capActivePos:        make(map[string]time.Time),
		activated:           make(map[string]bool),
		activationPersisted: make(map[string]bool),
	}
}

// Start begins periodic health checking. Blocks until context is cancelled.
func (c *Checker) Start(ctx context.Context) {
	// Anchor the warmup clock FIRST. A transient PeerTLSConfig failure below must not leave
	// startedAt==0 — that makes QuorumProof skip warmup and report a permanent false QuorumNo
	// (refusing every gated action on this node; post-Phase-2 it would demote/self-fence a
	// healthy node).
	c.mu.Lock()
	c.startedAt = time.Now()
	c.mu.Unlock()

	// Load TLS config for peer connections; RETRY a transient failure (e.g. a PKI-setup race
	// at boot) rather than giving up — a checker that never loads TLS never probes peers, so
	// it would report a permanent quorum loss. Loud on each failure; recovers when PKI heals.
	var err error
	for {
		c.tlsCfg, err = pki.PeerTLSConfig(c.pkiDir)
		if err == nil {
			break
		}
		slog.Error("health checker: failed to load TLS config; retrying (peer health checks blocked until it succeeds)", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Only a cycle that actually enumerated hosts ends warmup — a ListHosts error
			// probed nobody, so leaving probedOnce false keeps quorum Unknown (not a
			// premature No off an empty c.peers).
			if c.checkAllPeers(ctx) {
				c.mu.Lock()
				c.probedOnce = true
				c.mu.Unlock()
			}
		}
	}
}

// checkAllPeers probes every peer once. It returns true only when it actually
// ENUMERATED the host list — a ListHosts error probes nobody and returns false, so the
// caller must not treat that tick as a completed warmup cycle (else Unknown collapses to
// No with an empty c.peers on a single transient DB error).
func (c *Checker) checkAllPeers(ctx context.Context) bool {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("health check: list hosts", "error", err)
		return false
	}

	// Check local CRL version and publish it for gossip-based distribution (#49).
	// Only write when the version actually changes.
	localCRLVersion := pki.CRLVersion(c.pkiDir + "/crl.pem")
	if localCRLVersion > 0 {
		c.mu.Lock()
		changed := localCRLVersion != c.crlVer
		if changed {
			c.crlVer = localCRLVersion
		}
		c.mu.Unlock()
		if changed {
			c.db.ExecuteDeferred(ctx,
				`INSERT OR REPLACE INTO crl_versions (host, version, updated_at)
				 VALUES (?, ?, datetime('now'))`,
				c.hostName, localCRLVersion)
		}
	}

	var targets []corrosion.HostRecord
	for _, host := range hosts {
		if host.Name == c.hostName {
			continue // don't check ourselves
		}
		if host.State == "maintenance" {
			continue
		}

		// Detect CRL version mismatch (#49).
		if localCRLVersion > 0 {
			rows, qerr := c.db.Query(ctx,
				`SELECT version FROM crl_versions WHERE host = ?`, host.Name)
			if qerr != nil {
				slog.Warn("CRL version check: query failed (skipping stale-CRL detection for peer)",
					"peer", host.Name, "error", qerr)
			} else if len(rows) > 0 {
				peerVersion := rows[0].Int64("version")
				if peerVersion < localCRLVersion {
					slog.Warn("CRL version mismatch: peer has stale CRL — revoked hosts may still connect",
						"peer", host.Name, "peer_version", peerVersion, "local_version", localCRLVersion)
				}
			}
		}

		targets = append(targets, host)
	}

	// Probe peers with bounded concurrency and wait for the batch. Previously
	// this fired one goroutine per host per tick with no bound — a probe that
	// hangs longer than the tick interval would let goroutines accumulate
	// unboundedly. Now at most probeConcurrency run at once, and the next tick
	// won't start a fresh batch until this one drains.
	boundedFanout(targets, probeConcurrency, func(h corrosion.HostRecord) {
		c.checkHost(ctx, h)
	})
	return true
}

// boundedFanout runs work over items with at most `concurrency` goroutines in
// flight, blocking until all complete. It bounds both peak goroutines and the
// rate of creation (the loop blocks on the semaphore), so a hung worker can't
// accumulate unbounded goroutines.
func boundedFanout[T any](items []T, concurrency int, work func(T)) {
	if concurrency < 1 {
		concurrency = 1
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(x T) {
			defer wg.Done()
			defer func() { <-sem }()
			work(x)
		}(it)
	}
	wg.Wait()
}

func (c *Checker) checkHost(ctx context.Context, host corrosion.HostRecord) {
	addr := fmt.Sprintf("%s:%d", host.Address, host.GRPCPort)
	healthy := c.probe(addr)

	c.mu.Lock()
	prev, exists := c.peers[host.Name]
	if !exists {
		prev = &peerState{status: "", failures: 0}
		// Bootstrap from DB so we pick up pre-existing failure counts
		// (e.g. from a previous run of the checker).
		rows, qerr := c.db.Query(ctx,
			`SELECT consecutive_failures, status FROM host_health WHERE observer = ? AND target = ?`,
			c.hostName, host.Name)
		if qerr == nil && len(rows) == 1 {
			prev.failures = rows[0].Int("consecutive_failures")
			prev.status = rows[0].String("status")
		}
		c.peers[host.Name] = prev
	}

	var newStatus string
	var newFailures int

	if healthy {
		newStatus = "healthy"
		newFailures = 0
	} else {
		newFailures = prev.failures + 1
		if newFailures >= suspectThreshold {
			newStatus = "suspect"
		} else {
			newStatus = "healthy"
		}
	}

	changed := !exists || newStatus != prev.status || newFailures != prev.failures
	prev.status = newStatus
	prev.failures = newFailures
	// Local monotonic anchors updated every probe (not just on change) so Phase 2/5
	// timers measure "time since last direct contact" by our own clock.
	mono := time.Now()
	if healthy {
		prev.lastHealthyAt = mono
	} else {
		prev.lastFailureAt = mono
	}
	c.mu.Unlock()

	if !changed {
		return
	}

	now := c.db.NowTS()
	if healthy {
		c.db.ExecuteDeferred(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, 0, ?, ?)`,
			c.hostName, host.Name, "healthy", now, now,
		)
	} else {
		c.db.ExecuteDeferred(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			c.hostName, host.Name, newStatus, newFailures, nil, now,
		)
	}
}

func (c *Checker) probe(addr string) bool {
	dialer := &net.Dialer{Timeout: checkTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, c.tlsCfg)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkClockSkew compares the local clock with the peer's reported timestamp
// and logs a warning if skew exceeds 1 second. This mitigates LWW resolution
// corruption from NTP misconfiguration (#41).
func (c *Checker) checkClockSkew(ctx context.Context, peerName string, peerTimestamp time.Time) {
	skew := time.Since(peerTimestamp).Abs()
	if skew > time.Second {
		slog.Warn("clock skew detected — LWW conflict resolution may be unreliable",
			"peer", peerName, "skew", skew, "fix", "Check NTP on "+peerName)
		// Record skew for metrics + preflight. updated_at is RFC3339 (not
		// datetime('now')) so readers can apply an RFC3339 freshness cutoff —
		// a space-separated timestamp mis-sorts against a 'T'-separated cutoff
		// and would make every row read as stale (skew warnings would vanish).
		c.db.ExecuteDeferred(ctx,
			`INSERT OR REPLACE INTO clock_skew (observer, target, skew_seconds, updated_at)
			 VALUES (?, ?, ?, ?)`,
			c.hostName, peerName, skew.Seconds(), time.Now().UTC().Format(time.RFC3339),
		)
	}
}
