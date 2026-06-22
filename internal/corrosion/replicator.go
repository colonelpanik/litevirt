package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/pki"
)

// Replicator streams mutations from the local mutation_log to peers via gRPC.
// It implements the Crescent protocol: relay nodes fan out mutations to assigned
// leaves, while leaf nodes push only to their assigned relays. This replaces
// the previous O(n²) full-mesh with an O(n) relay-quorum topology.
type Replicator struct {
	client   *Client
	pkiDir   string
	relayCfg RelayConfig

	mu       sync.Mutex
	peers    map[string]context.CancelFunc // peer name → cancel for its goroutine
	relaySet *RelaySet                     // current relay election result
	isRelay  bool                          // cached: is this node a relay?
	wg       sync.WaitGroup

	// Fallback tracking for leaves: when was the last successful push to any relay?
	lastRelayPush  atomic.Int64 // unix millis
	fallbackActive atomic.Bool

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewReplicator creates a replicator for the given client.
func NewReplicator(client *Client, pkiDir string, cfg RelayConfig) *Replicator {
	cfg = cfg.withDefaults()
	r := &Replicator{
		client:   client,
		pkiDir:   pkiDir,
		relayCfg: cfg,
		peers:    make(map[string]context.CancelFunc),
		stopCh:   make(chan struct{}),
	}
	r.lastRelayPush.Store(time.Now().UnixMilli())
	return r
}

// Start begins the replicator. It discovers peers and starts per-peer goroutines.
// It also starts the log pruning goroutine and fallback monitor.
func (r *Replicator) Start(ctx context.Context) {
	slog.Info("replicator: starting")

	// Peer discovery loop — poll memberlist every 5s for new/departed peers.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.peerDiscoveryLoop(ctx)
	}()

	// Log pruning loop.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pruneLoop(ctx)
	}()

	// Fallback monitor — activates fallback if leaf can't reach relays.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.fallbackLoop(ctx)
	}()
}

// Stop gracefully shuts down all replicator goroutines.
func (r *Replicator) Stop() {
	r.stopOnce.Do(func() {
		slog.Info("replicator: stopping")
		close(r.stopCh)
		r.mu.Lock()
		for name, cancel := range r.peers {
			cancel()
			delete(r.peers, name)
		}
		r.mu.Unlock()
		r.wg.Wait()
		slog.Info("replicator: stopped")
	})
}

// PeerJoined starts a replicator goroutine for the named peer.
func (r *Replicator) PeerJoined(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.peers[name]; exists {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.peers[name] = cancel

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.replicateToPeer(ctx, name)
	}()

	slog.Info("replicator: started peer goroutine", "peer", name)
}

// PeerLeft stops the replicator goroutine for the named peer and schedules
// watermark cleanup after a grace period to prevent blocking log compaction.
func (r *Replicator) PeerLeft(name string) {
	r.mu.Lock()
	cancel, exists := r.peers[name]
	if exists {
		cancel()
		delete(r.peers, name)
	}
	r.mu.Unlock()

	if exists {
		slog.Info("replicator: stopped peer goroutine", "peer", name)
		// Schedule watermark cleanup after a grace period. The cleanup
		// re-checks membership before deleting, so a peer that rejoins within
		// the window (PeerJoined re-adds it) keeps its watermark instead of
		// being forced into a full re-sync by a stale timer.
		go func() {
			select {
			case <-r.stopCh:
				return
			case <-time.After(watermarkCleanupGrace):
			}
			r.cleanupDepartedWatermark(name)
		}()
	}
}

// watermarkCleanupGrace is how long PeerLeft waits before reclaiming a departed
// peer's replication watermark. A var so tests can drive the cleanup directly.
//
// pruneMutationLog already excludes watermarks not advanced within
// LiveWatermarkWindow (30m), so a departed peer stops pinning the log well
// before this fires — this grace only governs when the stale row itself is
// deleted (and thus when a returning peer is forced into a full anti-entropy
// resync instead of log replay). Kept comfortably above a brief network flap
// so a momentary blip doesn't trigger a needless re-sync, but far below the
// old 1h so a genuinely departed peer's row is reclaimed promptly.
var watermarkCleanupGrace = 10 * time.Minute

// cleanupDepartedWatermark deletes a peer's replication watermark — but only if
// the peer is still absent. If it rejoined (back in r.peers) the watermark is
// kept; deleting an active peer's watermark would trigger a needless full re-sync.
func (r *Replicator) cleanupDepartedWatermark(name string) {
	r.mu.Lock()
	_, live := r.peers[name]
	r.mu.Unlock()
	if live {
		slog.Info("replicator: peer rejoined before cleanup, keeping watermark", "peer", name)
		return
	}
	r.client.mu.Lock()
	r.client.db.ExecContext(context.Background(),
		`DELETE FROM replication_watermarks WHERE peer_name = ?`, name)
	r.client.mu.Unlock()
	slog.Info("replicator: cleaned watermark for departed peer", "peer", name)
}

// peerDiscoveryLoop periodically checks memberlist for new/departed peers.
func (r *Replicator) peerDiscoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial discovery.
	r.syncPeers()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.syncPeers()
		}
	}
}

func (r *Replicator) syncPeers() {
	members := r.client.Members()

	// Compute relay set from current membership.
	rs := ComputeRelays(members, r.client.HostName(), r.relayCfg)

	r.mu.Lock()
	oldIsRelay := r.isRelay
	r.relaySet = rs
	r.isRelay = rs.IsRelay(r.client.HostName())

	if r.isRelay != oldIsRelay {
		if r.isRelay {
			slog.Info("replicator: became relay", "relays", rs.Relays())
		} else {
			slog.Info("replicator: became leaf", "relays", rs.Relays())
		}
	}

	// Determine which peers we should replicate to based on our role.
	var extraLeaves []string
	if r.fallbackActive.Load() {
		extraLeaves = r.pickRandomLeaves(rs, 2)
	}
	targets := rs.TargetsFor(r.client.HostName(), r.fallbackActive.Load(), extraLeaves)
	targetSet := make(map[string]bool, len(targets))
	for _, t := range targets {
		targetSet[t] = true
	}

	// Start goroutines for new targets.
	for _, name := range targets {
		if _, exists := r.peers[name]; !exists {
			ctx, cancel := context.WithCancel(context.Background())
			r.peers[name] = cancel
			r.wg.Add(1)
			go func(n string) {
				defer r.wg.Done()
				r.replicateToPeer(ctx, n)
			}(name)
			slog.Debug("replicator: started peer goroutine", "peer", name)
		}
	}
	// Stop goroutines for peers no longer in our target set.
	for name, cancel := range r.peers {
		if !targetSet[name] {
			cancel()
			delete(r.peers, name)
			slog.Debug("replicator: stopped peer goroutine", "peer", name)
		}
	}
	r.mu.Unlock()
}

// pickRandomLeaves selects n random leaf nodes (not self, not relays) for fallback.
func (r *Replicator) pickRandomLeaves(rs *RelaySet, n int) []string {
	members := r.client.Members()
	var leaves []string
	for _, m := range members {
		if !rs.IsRelay(m.Name) && m.Name != r.client.HostName() {
			leaves = append(leaves, m.Name)
		}
	}
	rand.Shuffle(len(leaves), func(i, j int) { leaves[i], leaves[j] = leaves[j], leaves[i] })
	if len(leaves) > n {
		leaves = leaves[:n]
	}
	return leaves
}

const (
	// replicateBatchSize caps how many mutation_log entries are pushed to a
	// peer per round. The precise per-peer backlog depth is exported as the
	// litevirt_replication_peer_pending_entries metric.
	replicateBatchSize = 100

	// replicateDegradedRounds is how many consecutive full batches mark a peer
	// as "falling behind" — a steady stream of maxed-out pushes means it isn't
	// draining its backlog. Logged once on entry and once on recovery.
	replicateDegradedRounds = 5
)

// degradedStep advances the consecutive-full-batch counter for a peer and
// reports whether it just entered (warn) or left (recovered) the degraded
// state. Pure so the threshold logic is unit-testable without driving the
// replication loop.
func degradedStep(behindRounds, sent int) (rounds int, enteredDegraded, recovered bool) {
	if sent >= replicateBatchSize {
		rounds = behindRounds + 1
		return rounds, rounds == replicateDegradedRounds, false
	}
	return 0, false, behindRounds >= replicateDegradedRounds
}

// replicateToPeer is the per-peer replication loop with adaptive intervals.
func (r *Replicator) replicateToPeer(ctx context.Context, peerName string) {
	backoff := time.Second
	maxBackoff := 30 * time.Second
	behindRounds := 0 // consecutive full batches; drives the degraded-peer log

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		default:
		}

		sent, err := r.replicateOnce(ctx, peerName)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("replicator: error replicating to peer", "peer", peerName, "error", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			case <-time.After(backoff):
			}
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Track successful relay push for fallback monitor.
		r.mu.Lock()
		isRelayPeer := r.relaySet != nil && r.relaySet.IsRelay(peerName)
		r.mu.Unlock()
		if isRelayPeer {
			r.lastRelayPush.Store(time.Now().UnixMilli())
		}

		// Degraded-peer signal: a sustained run of maxed-out batches means this
		// peer is behind and not catching up. The exact backlog is exported per
		// peer as litevirt_replication_peer_pending_entries; here we just log the
		// transition so it's visible without a metrics stack.
		var enteredDegraded, recovered bool
		behindRounds, enteredDegraded, recovered = degradedStep(behindRounds, sent)
		if enteredDegraded {
			slog.Warn("replicator: peer is falling behind (sustained full replication batches)",
				"peer", peerName, "rounds", behindRounds, "batch", replicateBatchSize)
		} else if recovered {
			slog.Info("replicator: peer caught up on replication backlog", "peer", peerName)
		}

		// Success — reset backoff. Adaptive interval: burst if we sent
		// entries (more may be queued), otherwise wait for notification
		// or periodic tick.
		backoff = time.Second
		if sent > 0 {
			// Burst mode — check again quickly for more queued entries.
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			case <-time.After(100 * time.Millisecond):
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			case <-r.client.ReplicatorNotify():
				// New mutation available, loop immediately.
			case <-time.After(10 * time.Second):
				// Periodic check — picks up deferred writes (e.g. health data).
			}
		}
	}
}

// replicateOnce reads pending mutations and sends them to the peer.
// Returns the number of entries sent and any error.
func (r *Replicator) replicateOnce(ctx context.Context, peerName string) (int, error) {
	// Read watermark for this peer.
	lastSeq, err := r.getWatermark(ctx, peerName)
	if err != nil {
		return 0, fmt.Errorf("get watermark: %w", err)
	}

	// Read pending mutations, excluding entries that originated from this peer.
	entries, maxSeqSeen, err := r.readMutationLog(ctx, lastSeq, replicateBatchSize, peerName)
	if err != nil {
		return 0, fmt.Errorf("read mutation_log: %w", err)
	}

	// If entries were skipped (originated from peer) but nothing to send,
	// advance the watermark past the skipped entries so we don't re-read them.
	if len(entries) == 0 {
		if maxSeqSeen > lastSeq {
			if err := r.setWatermark(ctx, peerName, maxSeqSeen); err != nil {
				return 0, fmt.Errorf("set watermark: %w", err)
			}
		}
		return 0, nil
	}

	// Convert to proto entries.
	pbEntries := make([]*pb.MutationEntry, len(entries))
	for i, e := range entries {
		pbEntries[i] = &pb.MutationEntry{
			Seq:    e.Seq,
			Hlc:    e.HLC,
			Origin: e.Origin,
			Stmts:  e.Stmts,
		}
	}

	// Connect to peer and push mutations.
	client, conn, err := r.peerGRPCClient(ctx, peerName)
	if err != nil {
		return 0, fmt.Errorf("connect to peer %s: %w", peerName, err)
	}
	defer conn.Close()

	resp, err := client.PushMutations(ctx, &pb.ReplicateRequest{
		Sender:              r.client.HostName(),
		AfterSeq:            lastSeq,
		Entries:             pbEntries,
		SenderVersion:       r.client.LocalVersion(),
		SenderSchemaVersion: int32(CurrentSchemaVersion),
	})
	if err != nil {
		return 0, fmt.Errorf("push mutations: %w", err)
	}

	// Update watermark: use the highest of peer's applied seq and our maxSeqSeen
	// (to skip past filtered entries from the peer's origin).
	appliedUpTo := resp.AppliedUpTo
	if appliedUpTo == 0 {
		appliedUpTo = entries[len(entries)-1].Seq
	}
	if maxSeqSeen > appliedUpTo {
		appliedUpTo = maxSeqSeen
	}
	if appliedUpTo > lastSeq {
		if err := r.setWatermark(ctx, peerName, appliedUpTo); err != nil {
			return 0, fmt.Errorf("set watermark: %w", err)
		}
		slog.Debug("replicator: pushed to peer", "peer", peerName, "entries", len(entries), "watermark", appliedUpTo)
	}

	return len(entries), nil
}

type mutationEntry struct {
	Seq       int64
	HLC       string
	Origin    string
	Stmts     string
	CreatedAt string
}

// readMutationLog reads entries after afterSeq, filtering out entries originating
// from peerName. Returns matching entries, the max seq seen (including filtered),
// and any error.
func (r *Replicator) readMutationLog(ctx context.Context, afterSeq int64, limit int, peerName string) ([]mutationEntry, int64, error) {
	r.client.mu.RLock()
	defer r.client.mu.RUnlock()

	// Read all entries (including peer's own) so we can advance the watermark
	// past entries we skip.
	rows, err := r.client.db.QueryContext(ctx,
		`SELECT seq, hlc, origin, stmts, created_at FROM mutation_log WHERE seq > ? ORDER BY seq LIMIT ?`,
		afterSeq, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []mutationEntry
	var maxSeq int64
	for rows.Next() {
		var e mutationEntry
		if err := rows.Scan(&e.Seq, &e.HLC, &e.Origin, &e.Stmts, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
		// Skip entries that originated from the target peer — don't echo back.
		if e.Origin == peerName {
			continue
		}
		entries = append(entries, e)
	}
	return entries, maxSeq, rows.Err()
}

func (r *Replicator) getWatermark(ctx context.Context, peerName string) (int64, error) {
	r.client.mu.RLock()
	defer r.client.mu.RUnlock()

	var seq int64
	err := r.client.db.QueryRowContext(ctx,
		`SELECT last_seq FROM replication_watermarks WHERE peer_name = ?`, peerName).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return seq, err
}

func (r *Replicator) setWatermark(ctx context.Context, peerName string, seq int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	_, err := r.client.db.ExecContext(ctx,
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(peer_name) DO UPDATE SET last_seq = excluded.last_seq, updated_at = excluded.updated_at`,
		peerName, seq, now)
	return err
}

func (r *Replicator) peerGRPCClient(ctx context.Context, peerName string) (pb.LiteVirtClient, *grpc.ClientConn, error) {
	var addr string
	var port int

	host, err := GetHost(ctx, r.client, peerName)
	if err != nil {
		return nil, nil, fmt.Errorf("look up host %q: %w", peerName, err)
	}
	if host != nil {
		addr = host.Address
		port = host.GRPCPort
	} else {
		// Host not yet in DB — fall back to gossip memberlist address.
		// This handles bootstrap when a new node joins and hasn't
		// received the hosts table via replication yet.
		for _, m := range r.client.Members() {
			if m.Name == peerName {
				host, _, _ := net.SplitHostPort(m.Addr)
				if host != "" {
					addr = host
				} else {
					addr = m.Addr
				}
				break
			}
		}
		if addr == "" {
			return nil, nil, fmt.Errorf("look up host %q: not found in cluster state or gossip", peerName)
		}
		slog.Debug("replicator: using gossip address for peer", "peer", peerName, "addr", addr)
	}
	if port == 0 {
		port = 7443
	}

	tlsCfg, err := pki.PeerTLSConfig(r.pkiDir)
	if err != nil {
		return nil, nil, fmt.Errorf("peer TLS config: %w", err)
	}
	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", addr, port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial host %s: %w", peerName, err)
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}

// pruneLoop periodically deletes old mutation_log and mutation_seen entries.
func (r *Replicator) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.pruneMutationLog(ctx)
			r.pruneMutationSeen(ctx)
			r.pruneClockSkew(ctx)
		}
	}
}

// Retention knobs for mutation_log pruning. Vars (not consts) so tests can
// shrink the windows and operators could tune them later.
var (
	// PruneMinAge is the safety floor: a watermark-eligible entry must be at
	// least this old before it's pruned, so an in-flight push isn't racing a
	// delete.
	PruneMinAge = 10 * time.Minute

	// LiveWatermarkWindow bounds which peers count toward the prune watermark.
	// A peer whose watermark hasn't advanced within this window is treated as
	// dead and excluded, so a single dead/long-partitioned peer can't pin the
	// log forever. If such a peer returns, it resyncs via anti-entropy
	// (full-state merge), not log replay — so dropping its tail is safe.
	LiveWatermarkWindow = 30 * time.Minute

	// MaxLogRetention is the absolute ceiling: mutation_log entries older than
	// this are pruned regardless of any watermark. Bounds worst-case growth
	// when every watermark is stale (or there are none, e.g. a single node).
	// A peer offline longer than this recovers via anti-entropy.
	MaxLogRetention = 24 * time.Hour

	// IncrementalVacuumPages caps how many freed pages are returned to the OS
	// per prune tick, so a large reclaim is spread out instead of stalling
	// under the client lock. No-op unless the DB was created with
	// auto_vacuum=incremental (see sqliteDSN).
	IncrementalVacuumPages = 2000

	// ClockSkewRetention bounds how long a clock_skew observation is kept. The
	// metrics collector only reports rows younger than 10 min, so anything past
	// this is dead weight; without a prune the table grows without bound under
	// host churn (one row per observer×target, never deleted on its own).
	ClockSkewRetention = 1 * time.Hour
)

// pruneMutationLog trims the replication log in three steps: (1) prune up to
// the slowest *live* peer's watermark, (2) enforce an absolute age ceiling so
// a dead/forgotten peer can't keep the log growing without bound, and (3)
// return the freed pages to the OS. Steps 1+2 bound the row count; step 3
// bounds the on-disk file size.
func (r *Replicator) pruneMutationLog(ctx context.Context) {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	now := time.Now()

	// (1) Watermark-based prune over LIVE peers only. Previously this used
	// MIN(last_seq) across *all* watermark rows, so one dead or long-
	// partitioned peer (watermark never advancing) pinned the log forever.
	liveCutoff := now.Add(-LiveWatermarkWindow).UTC().Format(time.RFC3339)
	var minSeq sql.NullInt64
	if err := r.client.db.QueryRowContext(ctx,
		`SELECT MIN(last_seq) FROM replication_watermarks WHERE updated_at > ?`,
		liveCutoff).Scan(&minSeq); err == nil && minSeq.Valid {
		ageCutoff := now.Add(-PruneMinAge).UTC().Format(time.RFC3339)
		if res, derr := r.client.db.ExecContext(ctx,
			`DELETE FROM mutation_log WHERE seq <= ? AND created_at < ?`,
			minSeq.Int64, ageCutoff); derr != nil {
			slog.Warn("replicator: prune error", "error", derr)
		} else if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("replicator: pruned mutation_log", "deleted", n, "up_to_seq", minSeq.Int64)
		}
	}

	// (2) Absolute retention ceiling, independent of any watermark. This is
	// the backstop that bounds growth when the live set is empty or stuck;
	// a peer behind this window recovers via anti-entropy, not log replay.
	retentionCutoff := now.Add(-MaxLogRetention).UTC().Format(time.RFC3339)
	if res, derr := r.client.db.ExecContext(ctx,
		`DELETE FROM mutation_log WHERE created_at < ?`, retentionCutoff); derr != nil {
		slog.Warn("replicator: retention prune error", "error", derr)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Warn("replicator: pruned mutation_log past retention ceiling; lagging peers resync via anti-entropy",
			"deleted", n, "older_than", MaxLogRetention)
	}

	// (3) Return freed pages to the OS. No-op unless the DB was created with
	// auto_vacuum=incremental; bounded per tick to avoid a long stall.
	if _, err := r.client.db.ExecContext(ctx,
		fmt.Sprintf("PRAGMA incremental_vacuum(%d)", IncrementalVacuumPages)); err != nil {
		slog.Debug("replicator: incremental_vacuum", "error", err)
	}
}

// pruneMutationSeen deletes old entries from the dedup table.
// Uses HLC lexicographic ordering: entries with physical time older than 15 minutes are pruned.
func (r *Replicator) pruneMutationSeen(ctx context.Context) {
	cutoffMS := time.Now().Add(-15 * time.Minute).UnixMilli()
	cutoffHLC := fmt.Sprintf("%013d-0000-", cutoffMS)

	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	result, err := r.client.db.ExecContext(ctx,
		`DELETE FROM mutation_seen WHERE hlc < ?`, cutoffHLC)
	if err != nil {
		slog.Warn("replicator: prune mutation_seen error", "error", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		slog.Info("replicator: pruned mutation_seen", "deleted", n)
	}
}

// pruneClockSkew deletes clock_skew observations that are stale (older than
// ClockSkewRetention) or that target a host no longer in the cluster. The
// metrics collector only reads rows younger than 10 min, so without this the
// table accumulates one dead row per observer×target forever under host churn.
//
// Like the other prune helpers this is a LOCAL delete (raw ExecContext, not
// the mutation_log path), so it isn't replicated; every node prunes its own
// copy on the same age threshold, which converges. The departed-host clause is
// guarded by EXISTS(hosts) so a transiently empty hosts table (e.g. early
// startup) can't wipe every row — age-based deletion still applies then.
func (r *Replicator) pruneClockSkew(ctx context.Context) {
	cutoff := time.Now().Add(-ClockSkewRetention).UTC().Format(time.RFC3339)

	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	result, err := r.client.db.ExecContext(ctx,
		`DELETE FROM clock_skew
		 WHERE updated_at < ?
		    OR (target NOT IN (SELECT name FROM hosts)
		        AND EXISTS (SELECT 1 FROM hosts))`, cutoff)
	if err != nil {
		slog.Warn("replicator: prune clock_skew error", "error", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		slog.Info("replicator: pruned clock_skew", "deleted", n)
	}
}

// isSchemaMissingError reports whether err signals a missing table or
// column on the receiver. modernc-sqlite surfaces these as plain text
// in the error message; we match on the SQLite-canonical fragments so
// the check survives across driver versions.
//
// When this returns true, replication MUST back-pressure rather than
// silently skip — accepting a mutation with a missing target means
// losing the row forever even after the receiver is upgraded.
func isSchemaMissingError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, frag := range []string{
		"no such table",
		"no such column",
		"has no column named",
	} {
		if containsFold(msg, frag) {
			return true
		}
	}
	return false
}

// ApplyRemoteMutations applies mutation entries received from a remote peer.
// It uses LWW (Last-Writer-Wins) based on HLC timestamps for conflict resolution.
// Entries already seen (via mutation_seen dedup table) are skipped.
// If this node is a relay, applied entries are also recorded in mutation_log
// (preserving original origin) for fan-out to assigned leaves.
// Returns the highest sequence number successfully applied.
func (r *Replicator) ApplyRemoteMutations(ctx context.Context, entries []*pb.MutationEntry) (int64, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	// Filter out entries we've already processed (dedup).
	unseen := r.filterUnseen(ctx, tx, entries)

	var lastSeq int64
	for _, entry := range unseen {
		// Advance local HLC.
		if remoteTS, ok := hlc.Parse(entry.Hlc); ok {
			r.client.clock.Update(remoteTS)
		}

		// Parse statements.
		var stmts []Statement
		if err := json.Unmarshal([]byte(entry.Stmts), &stmts); err != nil {
			slog.Warn("replicator: unmarshal stmts", "seq", entry.Seq, "error", err)
			continue
		}

		// Apply each statement with LWW guard.
		for _, s := range stmts {
			if err := r.applyStatementLWW(ctx, tx, s, entry.Hlc); err != nil {
				// Schema-missing errors ("no such table", "no such
				// column") mean the receiver is behind on migrations
				// and silently dropping this row would lose data
				// after the rolling upgrade completes. Roll back
				// the whole batch and surface the error so the
				// sender stalls its watermark and retries once
				// this node is upgraded.
				if isSchemaMissingError(err) {
					_ = tx.Rollback()
					slog.Error("replicator: schema-missing on receiver — back-pressuring replication",
						"sql", s.SQL, "error", err,
						"hint", "upgrade this daemon to match the sender")
					return 0, fmt.Errorf("schema-missing on receiver (upgrade required): %w", err)
				}
				slog.Warn("replicator: apply statement", "sql", s.SQL, "hlc", entry.Hlc, "error", err)
				// Continue — partial application is better than none.
			}
		}

		lastSeq = entry.Seq
	}

	// Record all unseen entries in mutation_seen for future dedup. On failure,
	// roll back and back-pressure (stall the watermark) rather than commit
	// without the dedup rows — committing would let these mutations re-apply.
	if err := r.recordSeen(ctx, tx, unseen); err != nil {
		_ = tx.Rollback()
		slog.Error("replicator: failed to record mutation_seen — back-pressuring replication", "error", err)
		return 0, err
	}

	// If this node is a relay, record in mutation_log for fan-out.
	// Preserves original origin so readMutationLog's origin filter works correctly.
	r.mu.Lock()
	isRelay := r.isRelay
	r.mu.Unlock()
	if isRelay {
		if err := r.recordInMutationLog(ctx, tx, unseen); err != nil {
			_ = tx.Rollback()
			slog.Error("replicator: failed to record forwarded mutations — back-pressuring replication", "error", err)
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	// If relay and we recorded entries, wake the replicator to fan out.
	if isRelay && len(unseen) > 0 {
		r.client.notifyReplicator()
	}

	// Use the last seq from the original entries (not just unseen) so the
	// sender's watermark advances past duplicates too.
	if lastSeq == 0 && len(entries) > 0 {
		lastSeq = entries[len(entries)-1].Seq
	}

	return lastSeq, nil
}

// filterUnseen returns entries not yet in the mutation_seen dedup table.
func (r *Replicator) filterUnseen(ctx context.Context, tx *sql.Tx, entries []*pb.MutationEntry) []*pb.MutationEntry {
	var unseen []*pb.MutationEntry
	for _, e := range entries {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM mutation_seen WHERE origin = ? AND hlc = ?`,
			e.Origin, e.Hlc).Scan(&exists)
		if err != nil {
			// sql.ErrNoRows means not seen yet — include it.
			unseen = append(unseen, e)
		}
		// If exists == 1, skip (already applied).
	}
	return unseen
}

// recordSeen inserts entries into mutation_seen for future dedup. Returns an
// error so the caller can roll back the batch rather than commit with a missing
// dedup row (which would let the mutation be re-applied) — see F8.
func (r *Replicator) recordSeen(ctx context.Context, tx *sql.Tx, entries []*pb.MutationEntry) error {
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO mutation_seen (origin, hlc) VALUES (?, ?)`,
			e.Origin, e.Hlc); err != nil {
			return fmt.Errorf("record mutation_seen (origin=%s hlc=%s): %w", e.Origin, e.Hlc, err)
		}
	}
	return nil
}

// recordInMutationLog records forwarded mutations in the local mutation_log
// for relay fan-out. Preserves the original origin (NOT this node's hostname).
// Returns an error so the caller can roll back rather than commit a batch this
// relay then fails to fan out to its leaves (F8).
func (r *Replicator) recordInMutationLog(ctx context.Context, tx *sql.Tx, entries []*pb.MutationEntry) error {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES (?, ?, ?, ?)`,
			e.Hlc, e.Origin, e.Stmts, now); err != nil {
			return fmt.Errorf("record forwarded mutation (origin=%s hlc=%s): %w", e.Origin, e.Hlc, err)
		}
	}
	return nil
}

// applyStatementLWW applies a single SQL statement with LWW conflict resolution.
// For tables with updated_at, it only applies if the incoming HLC is newer.
func (r *Replicator) applyStatementLWW(ctx context.Context, tx *sql.Tx, s Statement, incomingHLC string) error {
	tableName := extractTableName(s.SQL)

	// For append-only tables (no updated_at), use INSERT OR IGNORE.
	if tableName == "fencing_log" || tableName == "audit_log" || tableName == "mutation_log" || tableName == "vm_events" {
		replaced := replaceInsertStrategy(s.SQL, "INSERT OR IGNORE")
		_, err := tx.ExecContext(ctx, replaced, s.Params...)
		return err
	}

	// For DELETE statements, always apply (soft-deletes use UPDATE anyway).
	if isDeleteStatement(s.SQL) {
		_, err := tx.ExecContext(ctx, s.SQL, s.Params...)
		return err
	}

	// For tables with updated_at and known PKs, check LWW.
	pkCols := tablePrimaryKeys[tableName]
	if len(pkCols) > 0 && tableName != "" {
		// Try to extract PK values and check local updated_at.
		// If local row exists and has a newer HLC, skip this mutation.
		if shouldSkipLWW(ctx, tx, tableName, pkCols, s, incomingHLC) {
			slog.Debug("replicator: LWW skip (local is newer)", "table", tableName, "hlc", incomingHLC)
			return nil
		}
	}

	// Apply with INSERT OR REPLACE for INSERT statements, or directly for UPDATE.
	applied := s.SQL
	if isInsertStatement(applied) {
		applied = replaceInsertStrategy(applied, "INSERT OR REPLACE")
	}
	_, err := tx.ExecContext(ctx, applied, s.Params...)
	return err
}

// shouldSkipLWW checks if the local row has a newer HLC than the incoming one.
func shouldSkipLWW(ctx context.Context, tx *sql.Tx, tableName string, pkCols []string, s Statement, incomingHLC string) bool {
	// Extract PK values from the statement params based on the table schema.
	// This is a best-effort approach — for UPDATE statements we can try to
	// extract the WHERE clause PK values; for INSERT we use the column order.
	pkValues := extractPKValues(tableName, pkCols, s)
	if len(pkValues) != len(pkCols) {
		return false // can't determine PK, don't skip
	}

	// Build a SELECT for the local row's updated_at.
	where := ""
	args := make([]interface{}, len(pkCols))
	for i, col := range pkCols {
		if i > 0 {
			where += " AND "
		}
		where += col + " = ?"
		args[i] = pkValues[i]
	}

	var localUpdatedAt sql.NullString
	err := tx.QueryRowContext(ctx,
		fmt.Sprintf("SELECT updated_at FROM %s WHERE %s", tableName, where),
		args...,
	).Scan(&localUpdatedAt)
	if err != nil {
		return false // no local row or error — don't skip
	}

	if !localUpdatedAt.Valid || localUpdatedAt.String == "" {
		return false
	}

	// Compare HLC timestamps. If local is an old RFC3339, incoming HLC always wins.
	localTS, localOK := hlc.Parse(localUpdatedAt.String)
	incomingTS, incomingOK := hlc.Parse(incomingHLC)
	if !localOK || !incomingOK {
		return false // can't compare, don't skip
	}

	// Skip if local is strictly newer.
	return localTS.After(incomingTS)
}

// extractPKValues attempts to extract primary key values from a Statement.
// For UPDATE... WHERE pk = ?, it extracts from the trailing params.
// For INSERT INTO table (cols) VALUES (...), it extracts by column position.
func extractPKValues(tableName string, pkCols []string, s Statement) []interface{} {
	if isInsertStatement(s.SQL) {
		return extractPKFromInsert(s, pkCols)
	}
	if isUpdateStatement(s.SQL) {
		return extractPKFromUpdate(s, pkCols)
	}
	return nil
}
