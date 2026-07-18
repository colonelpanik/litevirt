package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

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

	mu             sync.Mutex
	peers          map[string]context.CancelFunc // peer name → cancel for its goroutine
	relaySet       *RelaySet                     // current relay election result
	isRelay        bool                          // cached: is this node a relay?
	cleanupPending map[string]bool               // departed peers with a watermark-cleanup timer in flight
	wg             sync.WaitGroup

	// Fallback tracking for leaves: when was the last successful push to any relay?
	lastRelayPush  atomic.Int64 // unix millis
	fallbackActive atomic.Bool

	stopOnce sync.Once
	stopCh   chan struct{}

	// proofReplicaGate reports whether a peer advertises the split-brain gate
	// capability (token-based, fresh-Ping-cached). Injected by the daemon BEFORE
	// Start (so no replication goroutine runs with a nil gate). When nil, the WAL
	// proof filter FAILS CLOSED — proof-bearing entries are DROPPED from the stream
	// (never sent on a schema_version guess; a schema-38 peer that doesn't advertise
	// the token would otherwise wrongly receive proofs after the flip). Dropped
	// proofs reconverge via the peer-only sensitive AE net once the peer gains support.
	proofReplicaGate func(ctx context.Context, peer string) bool
}

// SetProofReplicaGate injects the per-peer capability gate for proof-table WAL
// replication (see internal/health Checker.PeerSupports).
func (r *Replicator) SetProofReplicaGate(fn func(ctx context.Context, peer string) bool) {
	r.mu.Lock()
	r.proofReplicaGate = fn
	r.mu.Unlock()
}

// peerLacksProofSupport reports whether proof-table mutations must be filtered
// from the stream to peer. Token-based (the gate is a fresh-Ping-cached capability
// check wired before Start). A nil gate FAILS CLOSED — treat the peer as lacking
// support so proof-bearing entries are DROPPED rather than leak on a schema guess
// (the schema_version fallback wrongly passed a schema-38 peer that doesn't advertise
// the token). Dropped proofs reconverge via the sensitive AE net; only proofs ever
// exist post-flip, so a nil-gate drop is a no-op pre-flip and, in the brief
// pre-wiring window, drops only the proof entries (the rest of the stream still flows).
func (r *Replicator) peerLacksProofSupport(ctx context.Context, peer string) bool {
	r.mu.Lock()
	gate := r.proofReplicaGate
	r.mu.Unlock()
	if gate == nil {
		return true // fail closed: no way to confirm support
	}
	return !gate(ctx, peer)
}

// NewReplicator creates a replicator for the given client.
func NewReplicator(client *Client, pkiDir string, cfg RelayConfig) *Replicator {
	cfg = cfg.withDefaults()
	r := &Replicator{
		client:         client,
		pkiDir:         pkiDir,
		relayCfg:       cfg,
		peers:          make(map[string]context.CancelFunc),
		cleanupPending: make(map[string]bool),
		stopCh:         make(chan struct{}),
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

// watermarkCleanupGrace is how long the discovery loop waits before reclaiming
// a departed peer's replication watermark. A var so tests can drive the cleanup
// directly.
//
// pruneMutationLog already excludes watermarks not advanced within
// LiveWatermarkWindow (30m), so a departed peer stops pinning the log well
// before this fires — this grace only governs when the stale row itself is
// deleted (and thus when a returning peer is forced into a full anti-entropy
// resync instead of log replay). Kept comfortably above a brief network flap
// so a momentary blip doesn't trigger a needless re-sync, but far below the
// old 1h so a genuinely departed peer's row is reclaimed promptly.
var watermarkCleanupGrace = 10 * time.Minute

// peerDiscoveryLoop keeps the per-peer replication goroutines and the
// replication-watermark table in sync with cluster membership. It reconverges
// on every gossip membership change (event-driven, via MembershipChanged) and
// on a slow backstop ticker that guarantees convergence even if an event is
// ever missed.
func (r *Replicator) peerDiscoveryLoop(ctx context.Context) {
	// Backstop poll — a safety net behind the membership events, not the
	// primary trigger; far slower than the old 5s busy-poll.
	const backstopInterval = 30 * time.Second
	ticker := time.NewTicker(backstopInterval)
	defer ticker.Stop()

	membership := r.client.MembershipChanged()

	reconverge := func() {
		r.syncPeers()
		r.reconcileDepartedWatermarks(ctx)
	}

	reconverge() // initial discovery

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-membership:
			reconverge()
		case <-ticker.C:
			reconverge()
		}
	}
}

// reconcileDepartedWatermarks schedules cleanup of replication_watermarks rows
// whose peer is no longer in cluster membership. This catches peers that leave
// after a relay reshuffle already dropped them from this node's target set (so
// they were never in r.peers to trigger a stop-time cleanup). The cleanup is
// delayed by watermarkCleanupGrace and re-checks membership, so a brief flap or
// a quick rejoin keeps the watermark.
func (r *Replicator) reconcileDepartedWatermarks(ctx context.Context) {
	members := map[string]bool{}
	for _, m := range r.client.Members() {
		members[m.Name] = true
	}
	// If we can't see any peers, don't reap — this is more likely a local
	// gossip outage than the whole cluster departing, and reaping would force
	// needless full re-syncs when peers reappear.
	if len(members) == 0 {
		return
	}
	r.reconcileDepartedWatermarksAgainst(ctx, members)
}

// reconcileDepartedWatermarksAgainst schedules cleanup for watermark rows whose
// peer is absent from the given live-member set. Split from the Members()-driven
// caller so tests can supply membership without a running gossip layer.
func (r *Replicator) reconcileDepartedWatermarksAgainst(ctx context.Context, members map[string]bool) {
	rows, err := r.client.Query(ctx, `SELECT DISTINCT peer_name FROM replication_watermarks`)
	if err != nil {
		slog.Warn("replicator: list watermarks for reconcile", "error", err)
		return
	}
	for _, row := range rows {
		name := row.String("peer_name")
		if name != "" && name != r.client.HostName() && !members[name] {
			r.scheduleWatermarkCleanup(name)
		}
	}
}

// scheduleWatermarkCleanup reclaims a departed peer's watermark after a grace
// period, deduping so at most one timer per peer is in flight (the discovery
// loop may observe the same departed peer many times during the grace window).
func (r *Replicator) scheduleWatermarkCleanup(name string) {
	r.mu.Lock()
	if r.cleanupPending[name] {
		r.mu.Unlock()
		return
	}
	r.cleanupPending[name] = true
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			delete(r.cleanupPending, name)
			r.mu.Unlock()
		}()
		select {
		case <-r.stopCh:
			return
		case <-time.After(watermarkCleanupGrace):
		}
		r.cleanupDepartedWatermark(name)
	}()
}

// cleanupDepartedWatermark deletes a peer's replication watermark — but only if
// the peer is gone for good. It is kept when the peer is still in cluster
// membership (rejoined during the grace) or is still one of our replication
// targets; deleting an active peer's watermark would trigger a needless full
// re-sync. Membership is authoritative for liveness (a live peer always shows
// in gossip); the target-set check is extra belt-and-suspenders.
func (r *Replicator) cleanupDepartedWatermark(name string) {
	for _, m := range r.client.Members() {
		if m.Name == name {
			slog.Info("replicator: peer back in membership before cleanup, keeping watermark", "peer", name)
			return
		}
	}
	r.mu.Lock()
	_, targeted := r.peers[name]
	r.mu.Unlock()
	if targeted {
		slog.Info("replicator: peer still a replication target, keeping watermark", "peer", name)
		return
	}

	r.client.mu.Lock()
	r.client.db.ExecContext(context.Background(),
		`DELETE FROM replication_watermarks WHERE peer_name = ?`, name)
	r.client.mu.Unlock()
	slog.Info("replicator: cleaned watermark for departed peer", "peer", name)
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

	// Per-peer capability filtering (split-brain hardening): a peer that can't honor the
	// monotone proof resolver (DB pre-v38 → no runtime_action_proofs table, or a v38 DB
	// whose binary doesn't yet advertise the token) must not receive proof mutations — it
	// would apply them as plain LWW and could resurrect a spent proof. A proof write is
	// co-batched with its marker (the vms.pending_action_id stamp) in a SINGLE mutation
	// entry, so we DROP THE WHOLE ENTRY, never split it (dropping only the proof statement
	// would leave a dangling pending_action_id, and a pre-v38 peer can't apply the marker
	// column either). Crucially we DROP, not defer: the watermark still advances PAST the
	// removed entries, so the rest of the stream — leader_election, vm_locks, everything
	// after a proof — keeps flowing instead of stalling behind a proof for up to
	// MaxLogRetention. Both halves reconverge once the peer gains support: the proof via
	// the peer-only sensitive anti-entropy net (the documented convergence safety net —
	// sync.go sensitiveTableNames) and pending_action_id via the public AE lane. Proofs are
	// only WRITTEN once the gate is cluster-wide, so nothing is dropped in steady state —
	// this only covers a mid-roll / downgraded / offline peer (that same peer surfaces as
	// the unsupported_member HA-degraded reason). The gate is TOKEN-based (fresh-Ping-cached
	// capability); a nil gate FAILS CLOSED (drops proofs) — there is no schema_version
	// fallback (a schema-38 peer that doesn't advertise the token would otherwise wrongly
	// receive proofs after the flip).
	if r.peerLacksProofSupport(ctx, peerName) {
		entries = dropUnsupportedProofEntries(entries)
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
		Sender:        r.client.HostName(),
		AfterSeq:      lastSeq,
		Entries:       pbEntries,
		SenderVersion: r.client.LocalVersion(),
		// Advertise the DB-APPLIED schema (what columns this node's DB actually
		// has), not the binary const — so during a multi-version rolling upgrade
		// a node whose DB was pre-staged forward but whose binary hasn't swapped
		// yet still reports the real (forward) schema and replication keeps flowing.
		SenderSchemaVersion: int32(r.client.EffectiveDBSchema()),
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

// dropUnsupportedProofEntries returns entries with every proof-bearing entry removed
// (order preserved). The removed proofs are intentionally NOT re-sent via the WAL — the
// caller advances the watermark past them and they reconverge via the peer-only sensitive
// anti-entropy net once the peer advertises support. Dropping the WHOLE entry (not just
// the proof statement) preserves the co-batched proof+marker atomicity; keeping every
// OTHER entry lets the stream flow instead of stalling behind a proof.
func dropUnsupportedProofEntries(entries []mutationEntry) []mutationEntry {
	kept := make([]mutationEntry, 0, len(entries))
	for _, e := range entries {
		if entryTouchesCustomMerge(e.Stmts) {
			continue // proof-bearing → drop; reconverges via the sensitive AE net
		}
		kept = append(kept, e)
	}
	return kept
}

// entryTouchesCustomMerge reports whether a serialized mutation entry contains ANY
// statement targeting a customMergeTables table (runtime_action_proofs). Such an
// entry must be replicated ATOMICALLY (proof + co-batched vms.pending_action_id
// marker together) or DROPPED WHOLE for a peer that can't yet apply the proof —
// never split (the dropped proof reconverges via the sensitive AE net). On a parse
// error it returns true (conservative: treat as proof-bearing and drop, rather than
// risk sending a partial to an unready peer).
func entryTouchesCustomMerge(stmtsJSON string) bool {
	var stmts []Statement
	if err := json.Unmarshal([]byte(stmtsJSON), &stmts); err != nil {
		return true
	}
	for _, s := range stmts {
		if customMergeTables[extractTableName(s.SQL)] != nil {
			return true
		}
	}
	return false
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
	target, err := resolvePeerTarget(ctx, r.client, peerName)
	if err != nil {
		return nil, nil, err
	}
	conn, err := pki.PeerDial(r.pkiDir, target)
	if err != nil {
		return nil, nil, err
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

// mutationSeenRetention bounds how far behind the newest dedup entry a row may
// be before it is pruned. Measured against the data (the newest stored HLC),
// not the wall clock, so an NTP step can't skew the cutoff. A var so tests can
// drive the prune directly.
var mutationSeenRetention = 15 * time.Minute

// validHLCPredicate is a SQL fragment that matches only rows whose hlc has the
// exact canonical layout "<13 digits>-<4 digits>-<node>" (hlc.Timestamp.String).
// Position/length are enforced with fixed-count GLOB digit classes — not a loose
// '[0-9]*' which would also match e.g. "12abc-…" — so a malformed/legacy row
// neither defines the max nor gets pruned by a misleading CAST(...)→0.
const validHLCPredicate = "length(hlc) >= 19 " +
	"AND substr(hlc,1,13) GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]' " +
	"AND substr(hlc,14,1) = '-' " +
	"AND substr(hlc,15,4) GLOB '[0-9][0-9][0-9][0-9]' " +
	"AND substr(hlc,19,1) = '-'"

// pruneMutationSeen deletes dedup entries whose physical time is more than
// mutationSeenRetention behind the newest valid HLC row. The cutoff is derived
// from the stored data (MAX over valid rows), so it is immune to wall-clock /
// NTP steps; an empty or all-malformed table yields a NULL max → no-op.
func (r *Replicator) pruneMutationSeen(ctx context.Context) {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	result, err := r.client.db.ExecContext(ctx,
		`DELETE FROM mutation_seen WHERE `+validHLCPredicate+
			` AND CAST(substr(hlc,1,13) AS INTEGER) <`+
			` (SELECT MAX(CAST(substr(hlc,1,13) AS INTEGER)) FROM mutation_seen WHERE `+validHLCPredicate+`) - ?`,
		mutationSeenRetention.Milliseconds())
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
	unseen, err := r.filterUnseen(ctx, tx, entries)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	for _, entry := range unseen {
		// Advance local HLC.
		if remoteTS, ok := hlc.Parse(entry.Hlc); ok {
			r.client.clock.Update(remoteTS)
		}

		// Parse statements. An undecodable entry is not silently skipped: back-pressure so
		// the sender retries rather than the row being lost with the watermark advanced.
		var stmts []Statement
		if err := json.Unmarshal([]byte(entry.Stmts), &stmts); err != nil {
			_ = tx.Rollback()
			r.client.observeMergeRejected("unknown", "wal", "decode")
			slog.Error("replicator: undecodable mutation entry — back-pressuring replication",
				"origin", entry.Origin, "seq", entry.Seq, "error", err)
			return 0, fmt.Errorf("decode mutation entry (origin=%s seq=%d): %w", entry.Origin, entry.Seq, err)
		}
		// A valid but empty statement list ([] or null) is not a legitimate mutation — a
		// correct sender never records one. Back-pressure rather than record it seen, so a
		// malformed/truncated entry surfaces instead of being silently acknowledged.
		if len(stmts) == 0 {
			_ = tx.Rollback()
			r.client.observeMergeRejected("unknown", "wal", "empty")
			slog.Error("replicator: mutation entry has no statements — back-pressuring replication",
				"origin", entry.Origin, "seq", entry.Seq)
			return 0, fmt.Errorf("mutation entry has no statements (origin=%s seq=%d)", entry.Origin, entry.Seq)
		}

		// Apply each statement fail-closed. ANY failure — schema-missing, a constraint
		// (e.g. a secondary-UNIQUE collision the PK-aware upsert now surfaces instead of
		// silently deleting), an operational fault, or an invalid/unprovable statement —
		// rolls back the whole batch and stalls the watermark so nothing is dropped or
		// recorded as seen. A permanent fault surfaces via replication backlog; the sender
		// retries. Logs carry s.SQL (never s.Params, which hold row data).
		for _, s := range stmts {
			if err := r.applyStatementLWW(ctx, tx, s, entry.Hlc); err != nil {
				_ = tx.Rollback()
				r.client.observeMergeRejected(boundedTableLabel(extractTableName(s.SQL)), "wal", walRejectReason(err))
				if isSchemaMissingError(err) {
					slog.Error("replicator: schema-missing on receiver — back-pressuring replication",
						"sql", s.SQL, "error", err,
						"hint", "upgrade this daemon to match the sender")
					return 0, fmt.Errorf("schema-missing on receiver (upgrade required): %w", err)
				}
				slog.Error("replicator: apply failed — back-pressuring replication",
					"sql", s.SQL, "origin", entry.Origin, "seq", entry.Seq, "error", err)
				return 0, fmt.Errorf("apply mutation (origin=%s seq=%d): %w", entry.Origin, entry.Seq, err)
			}
		}

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
	// sender's watermark advances past duplicates too. Otherwise a batch with
	// new entries followed by already-seen entries would replay the trailing
	// duplicates forever.
	return entries[len(entries)-1].Seq, nil
}

// filterUnseen returns entries not yet in the mutation_seen dedup table.
func (r *Replicator) filterUnseen(ctx context.Context, tx *sql.Tx, entries []*pb.MutationEntry) ([]*pb.MutationEntry, error) {
	var unseen []*pb.MutationEntry
	for _, e := range entries {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM mutation_seen WHERE origin = ? AND hlc = ?`,
			e.Origin, e.Hlc).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			unseen = append(unseen, e)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("query mutation_seen (origin=%s hlc=%s): %w", e.Origin, e.Hlc, err)
		}
		// If exists == 1, skip (already applied).
	}
	return unseen, nil
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

// applyStatementLWW applies a single replicated statement, PARSE-FIRST and fail-closed: it
// structurally validates the statement, checks its parameter arity, and authorizes its shape
// against the compatibility ledger BEFORE anything touches the database. An unparseable,
// arity-mismatched, or unregistered shape is rejected (the caller back-pressures) — never
// dispatched by a table-name guess or executed on a best-effort basis. It then applies the
// statement by the ledger's disposition, using the parsed shape (not positional heuristics)
// for every last-writer-wins decision.
func (r *Replicator) applyStatementLWW(ctx context.Context, tx *sql.Tx, s Statement, incomingHLC string) error {
	// A bounded legacy transformer runs BEFORE parsing: a supported prior release emits a few
	// shapes the strict parser rejects (crl_versions datetime('now'), the spent-proof-GC tsMs
	// predicate). Each exact-matched shape is normalized into the current safe apply so a
	// not-yet-upgraded peer's stream isn't back-pressured during a rolling upgrade.
	if lt, ok := legacyTransformerFor(s.SQL); ok {
		return r.applyLegacy(ctx, tx, lt, s, incomingHLC)
	}

	tableName := extractTableName(s.SQL)
	pkCols := tablePrimaryKeys[tableName]

	sh, err := parseStmtShape(s.SQL, pkCols)
	if err != nil {
		return err
	}
	if err := sh.ValidateParamArity(len(s.Params)); err != nil {
		return err
	}
	entry, ok := LedgerLookup(stmtFingerprint(sh))
	if !ok {
		// Fail closed: the fingerprint is absent from BOTH this build's ledger and the
		// checked-in historical ledger (prior-release shapes still in the supported horizon).
		// There is NO runtime derivation — checked-in ledger membership IS the authorization
		// decision, so an unknown shape always back-pressures. A genuinely-new shape must be
		// added to the ledger (with an explicit compatibility decision) before it can apply.
		return invalidf("unregistered replicated statement shape (table %s, kind %s)", tableName, sh.Kind)
	}

	switch entry.Disposition {
	case DispAppendOnly:
		// Immutable append-only INSERT (fencing_log/audit_log/mutation_log/vm_events):
		// INSERT OR IGNORE, so it only creates the row when absent and never overwrites.
		replaced := replaceInsertStrategy(s.SQL, "INSERT OR IGNORE")
		_, execErr := tx.ExecContext(ctx, replaced, s.Params...)
		return execErr

	case DispCustomMerge:
		// Monotone lifecycle / immutable journal (runtime_action_proofs, operations, …): an
		// INSERT uses INSERT OR IGNORE so it can only create a row when absent and never
		// clobbers one that has progressed; a guarded UPDATE travels with its WHERE clause
		// and is applied verbatim, so it no-ops on a peer whose row is already terminal or
		// ahead (terminal-beats-non-terminal without a timestamp compare). A completed⊕failed
		// split stays divergent here (statement-level apply can't compare full rows); the
		// periodic anti-entropy full-row compare raises the safety-fault signal. Mixed-version
		// safety is enforced on the SEND side (proof-bearing entries are dropped to peers that
		// don't advertise split_brain_gate_v1), so this receive side just stays monotone.
		sqlStmt := s.SQL
		if sh.Kind == KindInsert {
			sqlStmt = replaceInsertStrategy(sqlStmt, "INSERT OR IGNORE")
		}
		_, execErr := tx.ExecContext(ctx, sqlStmt, s.Params...)
		return execErr

	case DispDeleteRetention:
		// A registered retention DELETE (its presence in the ledger IS the registration).
		res, execErr := tx.ExecContext(ctx, s.SQL, s.Params...)
		if execErr == nil && rowsChanged(res) {
			r.client.clearUnresolvedFromStmt(s)
		}
		return execErr

	case DispBulkUpdate:
		// Dispatch explicitly by the ledger's concurrency category — the categories are
		// distinct contracts, not interchangeable. Only per-row-LWW is applied by expansion; a
		// provably-monotonic bulk is safe verbatim; anything else (including a future
		// unsupported entry) back-pressures.
		switch entry.Category {
		case CatPerRowLWW:
			return r.applyBulkPerRowLWW(ctx, tx, s, sh, tableName, pkCols)
		case CatMonotonic:
			res, execErr := tx.ExecContext(ctx, s.SQL, s.Params...)
			if execErr == nil && rowsChanged(res) {
				r.client.clearUnresolvedFromStmt(s)
			}
			return execErr
		default:
			return invalidf("bulk update on %s has unsupported concurrency category %q", tableName, entry.Category)
		}

	case DispFullPKUpdateNoClock:
		// A full-PK UPDATE with no bound updated_at, authorized by an explicit audited policy.
		// A monotonic-timestamp update is applied with a guard so it only ADVANCES the column
		// (never regresses on an out-of-order write); an idempotent/terminal one (audit reseal,
		// guarded revoke) applies verbatim by PK.
		if entry.MonotoneColumn != "" {
			return r.applyMonotoneTimestamp(ctx, tx, s, sh, entry.MonotoneColumn)
		}
		res, execErr := tx.ExecContext(ctx, s.SQL, s.Params...)
		if execErr == nil && rowsChanged(res) {
			r.client.clearUnresolvedFromStmt(s)
		}
		return execErr

	case DispPlainInsert, DispExplicitUpsert, DispFullPKUpdate:
		return r.applyLWWGated(ctx, tx, s, sh, tableName, pkCols, incomingHLC)
	}
	return invalidf("unhandled disposition %q for %s", entry.Disposition, tableName)
}

// applyLWWGated applies a full-PK INSERT/upsert or full-PK UPDATE under last-writer-wins: it
// LWW-gates by the row's updated_at (using the parsed shape's PK/updated_at parameter
// indices), then applies. An INSERT is rewritten to a PK-aware upsert so a behind sender's
// omitted columns keep their local value (never a whole-row replace); an UPDATE runs verbatim
// so its guards (deleted_at IS NULL, CAS) are retained.
func (r *Replicator) applyLWWGated(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, tableName string, pkCols []string, incomingHLC string) error {
	// Under canonical_identity_v1, a replicated INSERT into a natural-key identity table
	// (snapshots/container_snapshots) is resolved by its UNIQUE natural key rather than the
	// minted random id — two nodes can independently create DIFFERENT ids for one logical
	// object, and gating by id alone would let the incoming row collide on the secondary UNIQUE
	// and back-pressure forever. Only INSERTs are resolved this way; an UPDATE by id keeps the
	// normal LWW path (it converges once the ids have collapsed).
	if sh.Kind == KindInsert && r.client.canonicalIdentityOn() && hasIdentityKey(tableName) {
		return r.applyIdentityInsert(ctx, tx, s, sh, tableName, pkCols)
	}
	skip, err := r.shouldSkipLWW(ctx, tx, tableName, pkCols, s, sh, incomingHLC)
	if err != nil {
		return err
	}
	if skip {
		slog.Debug("replicator: LWW skip (local is newer)", "table", tableName, "hlc", incomingHLC)
		return nil
	}
	applied := s.SQL
	if sh.Kind == KindInsert {
		hasUpdatedAt, uerr := tableHasUpdatedAt(ctx, tx, tableName)
		if uerr != nil {
			return uerr // schema metadata unavailable ⇒ fail closed
		}
		rewritten, rerr := insertUpsertRewrite(s, pkCols, hasUpdatedAt)
		if rerr != nil {
			return rerr
		}
		applied = rewritten
	}
	res, err := tx.ExecContext(ctx, applied, s.Params...)
	if err == nil && rowsChanged(res) {
		// A strictly-newer / resolver-chosen incoming write that actually CHANGED the row
		// clears any stale unresolved-tie tracking. A guarded zero-row UPDATE is excluded.
		r.client.clearUnresolvedFromStmt(s)
	}
	return err
}

// applyIdentityInsert resolves a replicated INSERT into a natural-key identity table by its
// UNIQUE natural key under canonical_identity_v1 (the WAL analogue of mergeIdentityRow). It finds
// the local row with the same natural key (whatever its id) and either keeps local (deterministic
// identityWinner) or adopts the incoming row — DELETING the local row first when the ids differ so
// the two independently-minted ids collapse to the single winner without colliding on the
// secondary UNIQUE. The incoming row is then applied as a PK-aware upsert so receiver-only columns
// are preserved. It fails closed on a non-null self-reference (provably unused today), and honours
// the same skew quarantine as shouldSkipLWW. All within the caller's tx; any operational error is
// returned so the caller rolls back and back-pressures.
func (r *Replicator) applyIdentityInsert(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, tableName string, pkCols []string) error {
	cols, vals, ok := insertRowFromShape(sh, s)
	if !ok {
		return invalidf("identity insert on %s: cannot resolve row image", tableName)
	}
	colIdx := make(map[string]int, len(cols))
	for i, c := range cols {
		colIdx[strings.ToLower(c)] = i
	}

	// The self-reference class (snapshots.parent_id) is provably unused: a non-null value would
	// need reference rewrite on collapse, which we don't do — fail closed rather than orphan.
	for _, ref := range identityReferenceColumns[tableName] {
		if j, has := colIdx[strings.ToLower(ref)]; has && cellNonEmpty(vals[j]) {
			return invalidf("identity table %s: non-null reference %s under canonical_identity_v1 is unsupported", tableName, ref)
		}
	}

	idIdx, hasID := colIdx["id"]
	if !hasID {
		return invalidf("identity insert on %s: no id column", tableName)
	}
	incomingID := coerceString(vals[idIdx])
	incomingTS := ""
	if j, has := colIdx["updated_at"]; has {
		incomingTS = coerceString(vals[j])
	}

	// Local row for this natural key (any id).
	natCols := tableIdentityKeys[tableName]
	where := make([]string, len(natCols))
	args := make([]interface{}, len(natCols))
	for i, col := range natCols {
		j, has := colIdx[strings.ToLower(col)]
		if !has {
			return invalidf("identity insert on %s: missing natural-key column %s", tableName, col)
		}
		where[i] = col + " = ?"
		args[i] = vals[j]
	}
	var localID, localUpdatedAt sql.NullString
	selErr := tx.QueryRowContext(ctx, "SELECT id, updated_at FROM "+tableName+" WHERE "+strings.Join(where, " AND "), args...).Scan(&localID, &localUpdatedAt)
	if selErr != nil && !errors.Is(selErr, sql.ErrNoRows) {
		return selErr // operational read failure ⇒ back-pressure
	}
	localTS := ""
	if selErr == nil && localUpdatedAt.Valid {
		localTS = localUpdatedAt.String
	}

	// Future-skew quarantine (same as the LWW path): a skewed incoming clock must not poison
	// even a first-seen natural key.
	if incomingTS != "" && r.client.skewQuarantinesIncoming(r.client.hlcSkewGuardOn(), localTS, incomingTS, time.Now()) {
		slog.Warn("replicator: quarantined future-skewed identity row (not applied)",
			"table", tableName, "incoming_updated_at", incomingTS, "first_seen", selErr != nil)
		return nil
	}

	if selErr == nil { // a local row shares this natural key
		if identityWinner(localTS, localID.String, incomingTS, incomingID) == 1 {
			return nil // local wins → keep local
		}
		if localID.String != incomingID {
			// Incoming wins with a different id → collapse: remove the local row so the
			// incoming id lands without a natural-key collision.
			if _, dErr := tx.ExecContext(ctx, "DELETE FROM "+tableName+" WHERE id = ?", localID.String); dErr != nil {
				return dErr // operational failure ⇒ back-pressure
			}
		}
	}

	// Apply the incoming as a PK-aware upsert so receiver-only columns are preserved.
	hasUpdatedAt, uerr := tableHasUpdatedAt(ctx, tx, tableName)
	if uerr != nil {
		return uerr // schema metadata unavailable ⇒ fail closed
	}
	rewritten, rerr := insertUpsertRewrite(s, pkCols, hasUpdatedAt)
	if rerr != nil {
		return rerr
	}
	res, err := tx.ExecContext(ctx, rewritten, s.Params...)
	if err == nil && rowsChanged(res) {
		r.client.clearUnresolvedFromStmt(s)
	}
	return err
}

// applyMonotoneTimestamp applies a no-clock full-PK UPDATE that only ADVANCES a timestamp
// column (session/token last_used_at). It reads the local value and gates with lwwOrder — the
// SAME instant-based comparison anti-entropy uses — rather than a lexical SQL `col < ?`, which
// would mis-order valid RFC3339 representations (e.g. a fractional-second value sorts before a
// whole-second one that is actually earlier). The write is applied verbatim (respecting its own
// WHERE) only when the incoming value is strictly newer, or when there is no local value yet.
func (r *Replicator) applyMonotoneTimestamp(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, col string) error {
	incomingTS, err := monotoneIncomingValue(sh, s, col)
	if err != nil {
		return err
	}
	pkCols := tablePrimaryKeys[sh.Table]
	pkVals, ok := pkValuesFromShape(sh, s)
	if !ok || len(pkVals) != len(pkCols) || len(pkCols) == 0 {
		return invalidf("monotone update on %s: cannot resolve primary key", sh.Table)
	}
	where := ""
	args := make([]interface{}, len(pkCols))
	for i, c := range pkCols {
		if i > 0 {
			where += " AND "
		}
		where += c + " = ?"
		args[i] = pkVals[i]
	}
	var local sql.NullString
	selErr := tx.QueryRowContext(ctx, "SELECT "+col+" FROM "+sh.Table+" WHERE "+where, args...).Scan(&local)
	if selErr != nil && !errors.Is(selErr, sql.ErrNoRows) {
		return selErr // operational read failure ⇒ back-pressure
	}
	localTS := ""
	if selErr == nil && local.Valid {
		localTS = local.String
	}
	// Instant-based monotone gate: skip when the local value is newer OR an exact tie.
	if localTS != "" && lwwOrder(localTS, incomingTS) >= 0 {
		return nil
	}
	res, err := tx.ExecContext(ctx, s.SQL, s.Params...)
	if err == nil && rowsChanged(res) {
		r.client.clearUnresolvedFromStmt(s)
	}
	return err
}

// monotoneIncomingValue returns the incoming value the SET assigns to the monotone column, as a
// string (it must be a single bound parameter).
func monotoneIncomingValue(sh StmtShape, s Statement, col string) (string, error) {
	for _, a := range sh.SetAssigns {
		if !strings.EqualFold(a.Column, col) {
			continue
		}
		if len(a.Expr.ParamIdx) != 1 {
			return "", invalidf("monotone update on %s: %s is not a single bound parameter", sh.Table, col)
		}
		idx := a.Expr.ParamIdx[0]
		if idx < 0 || idx >= len(s.Params) {
			return "", invalidf("monotone update on %s: %s parameter out of range", sh.Table, col)
		}
		return coerceString(s.Params[idx]), nil
	}
	return "", invalidf("monotone update on %s: SET does not assign %s", sh.Table, col)
}

// applyBulkPerRowLWW applies a bulk (non-full-PK) UPDATE as an atomic per-row LWW expansion:
// enumerate the rows matching the ORIGINAL predicate (subqueries and all), then re-apply the
// original SET to each one ONLY where the incoming clock strictly beats that row's local
// updated_at, scoped to the exact primary key. This gives per-row last-writer-wins for a
// cascade that a single bulk UPDATE would apply un-gated (clobbering a concurrently-newer row
// on a peer). The whole expansion runs in the caller's transaction under the write lock, so
// the enumerate→apply window has no concurrent local writer; any operational error propagates
// so the caller rolls back and back-pressures.
func (r *Replicator) applyBulkPerRowLWW(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, tableName string, pkCols []string) error {
	if len(pkCols) == 0 {
		return invalidf("bulk update on %s has no known primary key", tableName)
	}
	if sh.UpdatedAtParamIdx < 0 || sh.UpdatedAtParamIdx >= len(s.Params) {
		return invalidf("bulk update on %s has no bound updated_at", tableName)
	}
	incomingTS := coerceString(s.Params[sh.UpdatedAtParamIdx])
	if incomingTS == "" {
		return invalidf("bulk update on %s has empty updated_at", tableName)
	}
	if sh.SetClauseStart <= 0 || sh.SetClauseEnd <= sh.SetClauseStart || sh.SetClauseEnd > len(s.SQL) {
		return invalidf("bulk update on %s: could not locate SET clause", tableName)
	}
	setSQL := s.SQL[sh.SetClauseStart:sh.SetClauseEnd]
	whereSQL := ""
	if sh.WhereEnd > sh.WhereStart && sh.WhereEnd <= len(s.SQL) {
		whereSQL = s.SQL[sh.WhereStart:sh.WhereEnd]
	}

	// Split params into SET (leading) and WHERE (trailing) by the SET clause's param count.
	setParamCount := 0
	for _, a := range sh.SetAssigns {
		setParamCount += len(a.Expr.ParamIdx)
	}
	if setParamCount > len(s.Params) {
		return invalidf("bulk update on %s: SET param count exceeds params", tableName)
	}
	setParams := s.Params[:setParamCount]
	whereParams := s.Params[setParamCount:]

	// 1. Enumerate matching rows' PK + local updated_at with the ORIGINAL predicate.
	sel := "SELECT " + strings.Join(pkCols, ", ") + ", updated_at FROM " + tableName
	if whereSQL != "" {
		sel += " WHERE " + whereSQL
	}
	rows, err := tx.QueryContext(ctx, sel, whereParams...)
	if err != nil {
		return err
	}
	type match struct {
		pk      []interface{}
		localTS string
	}
	var matches []match
	for rows.Next() {
		dst := make([]interface{}, len(pkCols)+1)
		ptrs := make([]interface{}, len(pkCols)+1)
		for i := range dst {
			ptrs[i] = &dst[i]
		}
		if scanErr := rows.Scan(ptrs...); scanErr != nil {
			rows.Close()
			return scanErr
		}
		// SQLite text scans as []byte; bind PK values back as string so `col = ?` compares.
		pk := dst[:len(pkCols)]
		for i, v := range pk {
			if b, isBytes := v.([]byte); isBytes {
				pk[i] = string(b)
			}
		}
		matches = append(matches, match{pk: pk, localTS: coerceString(dst[len(pkCols)])})
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		rows.Close()
		return rowsErr
	}
	rows.Close()

	// 2. Per-row: apply the SET only where the incoming clock wins (skew-guarded), scoped to
	//    the exact PK.
	skewOn := r.client.hlcSkewGuardOn()
	now := time.Now()
	pkWhere := make([]string, len(pkCols))
	for i, c := range pkCols {
		pkWhere[i] = c + " = ?"
	}
	upd := "UPDATE " + tableName + " SET " + setSQL + " WHERE " + strings.Join(pkWhere, " AND ")
	changed := false
	for _, m := range matches {
		if r.client.skewQuarantinesIncoming(skewOn, m.localTS, incomingTS, now) {
			continue
		}
		if m.localTS != "" && lwwOrder(m.localTS, incomingTS) >= 0 {
			continue // local newer OR an exact tie → keep local (a bulk SET is a partial
			// projection, not a full row image, so an equal-clock write must not overwrite)
		}
		params := make([]interface{}, 0, len(setParams)+len(m.pk))
		params = append(params, setParams...)
		params = append(params, m.pk...)
		res, execErr := tx.ExecContext(ctx, upd, params...)
		if execErr != nil {
			return execErr
		}
		if rowsChanged(res) {
			changed = true
		}
	}
	if changed {
		r.client.clearUnresolvedFromStmt(s)
	}
	return nil
}

// boundedTableLabel clamps a metric table label to a known replicated table or "unknown", so a
// malformed peer statement (extractTableName accepts an arbitrary second token) can't grow the
// Prometheus label cardinality.
func boundedTableLabel(table string) string {
	if _, ok := tablePrimaryKeys[table]; ok {
		return table
	}
	return "unknown"
}

// walRejectReason maps a WAL apply error to a BOUNDED metric reason label (never SQL/params):
// schema_missing, invalid_shape (any ErrInvalidStmt — unregistered / no-PK / arity / parse /
// unknown-kind), a specific constraint kind (unique/not_null/check/foreign_key/constraint),
// operational, or other.
func walRejectReason(err error) string {
	switch {
	case isSchemaMissingError(err):
		return "schema_missing"
	case errors.Is(err, ErrInvalidStmt):
		return "invalid_shape"
	}
	switch class, kind := classifySQLiteError(err); class {
	case classConstraint:
		return string(kind)
	case classOperational:
		return "operational"
	default:
		return "other"
	}
}

// rowsChanged reports whether a SQL result provably affected at least one row.
// Used to gate the unresolved-tie clear so a guarded zero-row statement
// (WHERE … matched nothing) doesn't drop a still-valid tie. SQLite always
// reports RowsAffected; an unavailable count is treated as "no change" (don't
// clear) so the clear is never based on a guess.
func rowsChanged(res sql.Result) bool {
	n, err := res.RowsAffected()
	return err == nil && n > 0
}

// insertUpsertRewrite turns a replicated INSERT into a PK-aware upsert that preserves
// receiver-only columns, failing closed (returning an error that wraps ErrInvalidStmt) on
// anything it can't prove safe — the caller back-pressures on that error rather than
// applying a statement that could lose data.
//
// A plain INSERT gains ON CONFLICT(pk) DO UPDATE SET nonpk = excluded.nonpk built from the
// parsed column list, so the original VALUES tuple (params and literals alike) is left
// untouched and only the sender-supplied non-PK columns are updated on conflict. An INSERT
// that already carries an explicit ON CONFLICT clause keeps it verbatim, with only a leading
// OR REPLACE/OR IGNORE normalized to a plain INSERT.
//
// Invariants (fail closed): the statement parses as an INSERT; its bound-parameter count
// matches the supplied params; it carries a full bound primary key to conflict on. When the
// target is an LWW table (hasUpdatedAt), it must bind updated_at (so a new row carries a
// clock) AND — for an explicit upsert — assign updated_at in DO UPDATE SET (so the row clock
// actually advances on conflict; otherwise a winning write would mutate other columns while
// leaving a stale clock, corrupting later LWW comparisons).
func insertUpsertRewrite(s Statement, pkCols []string, hasUpdatedAt bool) (string, error) {
	if len(pkCols) == 0 {
		return "", invalidf("INSERT target has no known primary key")
	}
	sh, err := parseStmtShape(s.SQL, pkCols)
	if err != nil {
		return "", err // already wraps ErrInvalidStmt
	}
	if sh.Kind != KindInsert {
		return "", invalidf("expected INSERT, got %s", sh.Kind)
	}
	if err := sh.ValidateParamArity(len(s.Params)); err != nil {
		return "", err
	}
	if !sh.HasFullPKIdentity {
		return "", invalidf("INSERT into %s lacks a full bound primary key", sh.Table)
	}
	if hasUpdatedAt {
		if sh.UpdatedAtParamIdx < 0 {
			return "", invalidf("INSERT into %s omits a bound updated_at (LWW clock would not advance)", sh.Table)
		}
		if sh.OnConflict != nil && !conflictAdvancesUpdatedAt(sh.OnConflict) {
			return "", invalidf("explicit upsert into %s does not advance updated_at (need updated_at = excluded.updated_at)", sh.Table)
		}
	}
	// An explicit upsert already scopes exactly which columns it touches; just normalize a
	// leading algo (INSERT OR REPLACE/IGNORE → plain INSERT) and apply it verbatim.
	if sh.OnConflict != nil {
		return stripLeadingAlgo(s.SQL, sh), nil
	}
	pkSet := lowerStringSet(pkCols)
	sets := make([]string, 0, len(sh.InsertCols))
	for _, c := range sh.InsertCols {
		if pkSet[strings.ToLower(c)] {
			continue // never reassign the conflict key
		}
		sets = append(sets, c+" = excluded."+c)
	}
	// Splice the tail at the end of the VALUES tuple (InsertValuesEnd), not the raw string
	// end, so any trailing comment or semicolon after VALUES can't swallow the ON CONFLICT
	// clause. The leading OR REPLACE/IGNORE span (if any) sits before InsertValuesEnd, so
	// stripLeadingAlgo still applies to the truncated head.
	if sh.InsertValuesEnd <= 0 || sh.InsertValuesEnd > len(s.SQL) {
		return "", invalidf("INSERT into %s: could not locate VALUES tuple end", sh.Table)
	}
	base := stripLeadingAlgo(s.SQL[:sh.InsertValuesEnd], sh)
	conflict := " ON CONFLICT(" + strings.Join(pkCols, ", ") + ") "
	if len(sets) == 0 {
		return base + conflict + "DO NOTHING", nil
	}
	return base + conflict + "DO UPDATE SET " + strings.Join(sets, ", "), nil
}

// conflictAdvancesUpdatedAt reports whether a DO UPDATE SET makes the row clock ADVANCE on
// conflict — i.e. it assigns exactly `updated_at = excluded.updated_at`. Merely mentioning
// updated_at (updated_at = updated_at, ”, NULL, or any transformed expression) does NOT
// advance it and would let a winning write mutate other columns while retaining/corrupting
// the clock; such a special monotonic/transformed shape must instead carry an exact ledger
// disposition. ExcludedRef is the parser's proof the RHS is exactly `excluded.<col>`.
func conflictAdvancesUpdatedAt(cc *ConflictClause) bool {
	for _, a := range cc.Assignments {
		if strings.EqualFold(a.Column, "updated_at") {
			return a.Expr.ExcludedRef == "updated_at"
		}
	}
	return false
}

// tableHasUpdatedAt reports whether a known table has an updated_at column, read through the
// open tx (PRAGMA) so it needs no client lock — ApplyRemoteMutations already holds the write
// lock, which readTableColumns would deadlock on. Only known tables (in tablePrimaryKeys)
// are queried, so the interpolated name is never peer-controlled. It fails CLOSED: any
// metadata error (query, scan, or rows iteration) is returned so the caller back-pressures
// rather than silently disabling the LWW clock invariants.
func tableHasUpdatedAt(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	if _, known := tablePrimaryKeys[table]; !known {
		return false, nil
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, fmt.Errorf("table_info(%s): %w", table, err)
	}
	defer rows.Close()
	has := false
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             interface{}
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("scan table_info(%s): %w", table, err)
		}
		if strings.EqualFold(name, "updated_at") {
			has = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate table_info(%s): %w", table, err)
	}
	return has, nil
}

// shouldSkipLWW reports whether to skip applying the incoming mutation under
// last-writer-wins. A strict timestamp order is decided by lwwOrder. On an EXACT
// tie it defers to the table-aware resolver — but only for repaired tables and
// only when the statement is a full-image INSERT (the dominant upsert shape),
// resolving over the full row with the SAME engine anti-entropy uses, so the two
// paths can never disagree. A tied partial UPDATE, or any AE-excluded table,
// keeps local: the divergence is left for anti-entropy to converge (or, for
// excluded lease tables, for the existing self-correcting write to overwrite),
// never resolved from a partial local⊕SET image (which could differ from the
// source's full row and make AE and WAL diverge).
func (r *Replicator) shouldSkipLWW(ctx context.Context, tx *sql.Tx, tableName string, pkCols []string, s Statement, sh StmtShape, incomingHLC string) (bool, error) {
	// PK values come from the PARSED shape's parameter indices, not positional heuristics, so
	// a mixed literal/parameter tuple (e.g. VALUES (?,0,?,NULL,?)) maps correctly. The
	// disposition guarantees full-PK identity here, so a failure is an invariant violation ⇒
	// fail closed (no best-effort "apply anyway").
	pkValues, ok := pkValuesFromShape(sh, s)
	if !ok {
		return false, invalidf("cannot resolve primary key for LWW on %s", tableName)
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
	selErr := tx.QueryRowContext(ctx,
		fmt.Sprintf("SELECT updated_at FROM %s WHERE %s", tableName, where),
		args...,
	).Scan(&localUpdatedAt)
	if selErr != nil && !errors.Is(selErr, sql.ErrNoRows) {
		return false, selErr // operational failure ⇒ back-pressure, never treated as "no row"
	}
	localTS := ""
	if selErr == nil && localUpdatedAt.Valid {
		localTS = localUpdatedAt.String
	}

	// Prefer the row's own updated_at (from the shape's updated_at parameter); fall back to
	// the entry HLC only when the statement carries no bound updated_at.
	incomingTS := incomingHLC
	if ts, has := incomingUpdatedAtFromShape(sh, s); has && ts != "" {
		incomingTS = ts
	}

	// Skew quarantine runs BEFORE the no-local-row early return: a future-skewed incoming
	// value must be dropped even for a PK this node has not seen.
	if r.client.skewQuarantinesIncoming(r.client.hlcSkewGuardOn(), localTS, incomingTS, time.Now()) {
		slog.Warn("replicator: quarantined future-skewed incoming statement (not applied)",
			"table", tableName, "incoming_updated_at", incomingTS, "first_seen", localTS == "")
		return true, nil // skip incoming
	}

	// No local row → nothing to compare; apply incoming.
	if errors.Is(selErr, sql.ErrNoRows) || localTS == "" {
		return false, nil
	}

	switch ord := lwwOrder(localTS, incomingTS); {
	case ord > 0:
		return true, nil // local strictly newer → skip incoming
	case ord < 0:
		return false, nil // incoming strictly newer → apply
	}
	// Exact tie. AE-excluded tables keep local (existing lease/self-correcting semantics).
	if _, repaired := capabilityMap[tableName]; !repaired {
		return true, nil
	}
	// Full-image eligibility for tie resolution: a plain INSERT (all supplied columns), or an
	// explicit upsert PROVEN full-image (every non-PK column assigned c = excluded.c). A
	// partial/transformed upsert or any UPDATE keeps local — resolving from a partial image
	// could disagree with anti-entropy's full-row resolution.
	fullImage := sh.Kind == KindInsert && (sh.OnConflict == nil || sh.OnConflict.IsFullImage)
	if fullImage {
		if cols, vals, okRow := insertRowFromShape(sh, s); okRow {
			pkIdx := columnIndexes(cols, pkCols)
			localRow, found, fErr := fetchLocalRowCells(tx, tableName, cols, pkCols, pkIdx, vals)
			if fErr != nil {
				return false, fErr // operational read failure ⇒ back-pressure
			}
			if !found {
				return false, nil // no local row → apply incoming
			}
			keepLocal, _ := r.client.resolveTie(tableName, cols, localRow, vals, pkIdx, pathWAL)
			return keepLocal, nil
		}
	}
	// A tied partial UPDATE / non-full-image upsert: keep local; anti-entropy converges it.
	return true, nil
}

// pkValuesFromShape returns the primary-key values a full-PK statement binds, from the shape's
// resolved PK parameter indices. ok=false when the shape has no full-PK identity.
func pkValuesFromShape(sh StmtShape, s Statement) ([]interface{}, bool) {
	if !sh.HasFullPKIdentity || len(sh.PKParamIdx) == 0 {
		return nil, false
	}
	vals := make([]interface{}, len(sh.PKParamIdx))
	for i, idx := range sh.PKParamIdx {
		if idx < 0 || idx >= len(s.Params) {
			return nil, false
		}
		vals[i] = s.Params[idx]
	}
	return vals, true
}

// incomingUpdatedAtFromShape returns the updated_at value the statement binds, from the
// shape's resolved updated_at parameter index.
func incomingUpdatedAtFromShape(sh StmtShape, s Statement) (string, bool) {
	if sh.UpdatedAtParamIdx < 0 || sh.UpdatedAtParamIdx >= len(s.Params) {
		return "", false
	}
	return coerceString(s.Params[sh.UpdatedAtParamIdx]), true
}

// insertRowFromShape reconstructs the full column list and row values of an INSERT from the
// parsed shape, mapping each cell to its bound parameter or canonical literal. This handles
// mixed literal/parameter tuples that the positional heuristic could not. ok=false for a
// non-INSERT or a column/value count mismatch.
func insertRowFromShape(sh StmtShape, s Statement) (cols []string, vals []interface{}, ok bool) {
	if sh.Kind != KindInsert || len(sh.InsertCols) != len(sh.InsertVals) || len(sh.InsertCols) == 0 {
		return nil, nil, false
	}
	vals = make([]interface{}, len(sh.InsertVals))
	for i, v := range sh.InsertVals {
		if v.isParam() {
			if v.ParamIndex < 0 || v.ParamIndex >= len(s.Params) {
				return nil, nil, false
			}
			vals[i] = s.Params[v.ParamIndex]
			continue
		}
		switch v.Literal.Kind {
		case LitNull:
			vals[i] = nil
		case LitInt:
			vals[i] = v.Literal.Int
		case LitString:
			vals[i] = v.Literal.Str
		default:
			return nil, nil, false
		}
	}
	return sh.InsertCols, vals, true
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
