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
type peerState struct {
	status   string // "healthy" or "suspect"
	failures int
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
}

// NewChecker creates a new health checker.
func NewChecker(hostName, pkiDir string, db *corrosion.Client) *Checker {
	return &Checker{
		hostName: hostName,
		pkiDir:   pkiDir,
		db:       db,
		peers:    make(map[string]*peerState),
	}
}

// Start begins periodic health checking. Blocks until context is cancelled.
func (c *Checker) Start(ctx context.Context) {
	// Load TLS config for peer connections
	var err error
	c.tlsCfg, err = pki.PeerTLSConfig(c.pkiDir)
	if err != nil {
		slog.Error("health checker: failed to load TLS config", "error", err)
		return
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkAllPeers(ctx)
		}
	}
}

func (c *Checker) checkAllPeers(ctx context.Context) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("health check: list hosts", "error", err)
		return
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
