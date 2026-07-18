package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	_ "modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

// SyncMetrics is the optional, nil-safe observability sink for anti-entropy
// dump/digest/merge timing. It is defined here (not imported from
// internal/metrics) so the corrosion package stays free of a Prometheus
// dependency and the metrics package — which already imports corrosion — can
// implement it without an import cycle. *metrics.AntiEntropyMetrics satisfies it
// structurally.
type SyncMetrics interface {
	ObserveDump(d time.Duration, bytes int)
	ObserveDigest(d time.Duration)
	ObserveMerge(d time.Duration, merged, skipped int)
	// ObserveMergeRejected records a replicated row/statement the apply path rejected but did
	// NOT apply — path ∈ {ae, wal}; reason ∈ {constraint, …}. Bounded labels only (never SQL
	// or parameter values). Counts ATTEMPTS, so a permanent collision increments every cycle;
	// alert on rate, not absolute value.
	ObserveMergeRejected(table, path, reason string)
	// ObserveLegacyTransformed records a prior-release statement the WAL apply path normalized
	// through a bounded legacy transformer (transformer = the transformer id). A nonzero rate
	// means a not-yet-upgraded peer is still emitting a legacy shape.
	ObserveLegacyTransformed(transformer string)
	// ObserveTieBreak records an exact-timestamp tie that a resolver converged:
	// resolver ∈ {content_max, numeric_max, timestamp_max, non_null_wins,
	// lb_generation}; winner ∈ {local, incoming}. (Tombstone ties go to
	// ObserveTombstoneTie instead.)
	ObserveTieBreak(table, resolver, winner string)
	// ObserveTieUnresolved records a DISTINCT unresolved tie (counted once per
	// (table,PK,content-pair), not per cycle): path ∈ {ae, wal}; category ∈
	// {runtime_owned, opaque, tenancy, policy, control_plane, auth_factor,
	// auth_pointer, lb_token}.
	ObserveTieUnresolved(table, path, category string)
	// ObserveIdentityCollapseOrphan records a natural-key identity collapse whose losing physical
	// row referenced a DIFFERENT host/artifact than the winner, so that host's snapshot file may
	// now be unreferenced. NOT auto-deleted — the losing id/host/path is logged (WARN) for
	// operator cleanup; this metric (bounded, per-table) is the alert signal.
	ObserveIdentityCollapseOrphan(table string)
	// ObserveTombstoneTie records a tie a one-sided soft-delete settled. Tracked
	// separately because it is a benign, expected outcome (a delete racing a
	// write) — counting it in the tie-break series would muddy the "steady ties ⇒
	// colliding timestamps" signal.
	ObserveTombstoneTie(table string)
	// ObserveUnresolvedTieCurrent reports the CURRENT count of distinct
	// unresolved ties this node is tracking — a gauge, not the monotonic
	// lww_tie_unresolved_total counter. It drops back to 0 when the rows are
	// repaired (clearUnresolved), so it's the right signal for a "something is
	// divergent right now" alert (the counter would page forever after one tie).
	ObserveUnresolvedTieCurrent(n int)
}

// Config holds configuration for the embedded state store.
type Config struct {
	HostName  string   // identity of this node
	DataDir   string   // SQLite file at DataDir/state.db
	BindAddr  string   // gossip bind address (default "0.0.0.0")
	BindPort  int      // gossip port (default 7946)
	JoinPeers []string // initial peers to join
}

// Client is the embedded state store with WAL-based replication.
type Client struct {
	db       *sql.DB
	mu       sync.RWMutex
	list     *memberlist.Memberlist
	hostName string
	clock    *hlc.Clock
	version  string // local litevirtd binary version, for skew checks

	// dataDir is where the durable monotonic-clock high-water lives
	// (<dataDir>/nowts.hwm). Empty ⇒ no persistence (in-memory monotonic only:
	// throwaway/legacy clients with no data dir).
	dataDir string
	// nowFn is the wall-clock source behind NowTS, injectable for tests (default
	// time.Now). The HLC clock has its own nowFn seam.
	nowFn func() time.Time

	// replicator is notified when new mutations are written to mutation_log.
	// Set via SetReplicator after construction.
	replicatorNotify chan struct{}

	// membershipNotify is a coalescing wake (cap 1) for the replicator's
	// peer-discovery loop, fired by the memberlist EventDelegate on peer
	// join/leave/update. Never fires for a local client (no gossip).
	membershipNotify chan struct{}

	// effectiveDBSchema caches this node's effective DB-applied schema version =
	// max(ledger-derived, stored schema_state.version). It is the single source
	// for the replication handshake (both the version this node advertises as a
	// sender and the version it compares against as a receiver), so a multi-
	// version rolling upgrade keys off what the DB ACTUALLY has (equalized by the
	// pre-stage pass) rather than the lagging binary const. Seeded at the end of
	// InitSchema and refreshed by RefreshDBSchemaVersion after a pre-stage
	// migrate. 0 = not yet seeded → EffectiveDBSchema() falls back to the const.
	effectiveDBSchema atomic.Int32

	// syncMetrics is the optional, nil-safe anti-entropy timing sink, set once at
	// daemon startup via SetSyncMetrics. It lives on the Client (not the
	// AntiEntropy loop) so dumps served directly through grpcapi (DumpStateBytes /
	// StreamStateDump) are observed too.
	syncMetrics SyncMetrics

	// tsMu guards lastTS + durableTS, the monotonic source behind NowTS(). Kept
	// separate from mu so timestamp generation (called before a write acquires mu)
	// never contends with or re-enters the main lock.
	tsMu   sync.Mutex
	lastTS time.Time
	// durableTS is the LWW-key ceiling durably persisted to <dataDir>/nowts.hwm:
	// NowTS never emits a value beyond it without first persisting a higher one
	// (persist-ahead), so a restart-after-clock-rollback cannot regress below what
	// this node already emitted. Zero when there's no dataDir (no persistence).
	durableTS time.Time
	// hwm persists the monotonic high-waters (LWW-key + HLC physical). nil ⇒ no
	// dataDir ⇒ in-memory monotonic only.
	hwm *hwmStore
	// durableHLCMS is the HLC physical-ms ceiling persisted to nowts.hwm (paired
	// with durableTS in the same file). Advanced by the HLC clock's persist hook.
	// Guarded by tsMu.
	durableHLCMS int64
	// onPersistFatal is invoked when NowTS cannot persist a higher ceiling AND has no
	// headroom left below the durable one (sustained disk-write failure). Production
	// logs + exits — a node that can't durably advance its LWW clock must not keep
	// emitting timestamps that could regress on the next restart. Overridable in tests.
	onPersistFatal func(err error)

	// tieMu guards the equal-timestamp-tie tracking state below. Separate from mu
	// so the resolver (called while mu is held during a merge) records without
	// re-entrancy.
	tieMu sync.Mutex
	// unresolvedTies records, per (table,PK), the sorted content-hash pair of the
	// last classified-unresolved tie. It makes lww_tie_unresolved count DISTINCT
	// rows (re-observing the same divergence is a no-op) and drives the alert.
	// Cleared when the row converges or is repaired (a newer write to the PK).
	unresolvedTies map[string]string
	// unresolvedLen mirrors len(unresolvedTies) for a lock-free fast path: the
	// clear-on-write hooks (which run on every applied/local row) skip the lock
	// entirely when nothing is tracked — the overwhelmingly common case.
	unresolvedLen atomic.Int64

	// txEffects holds side effects (tracker mutations, orphan alerts/metrics) that must run only
	// AFTER a merge/apply transaction COMMITS — so a later row/statement or commit failure that
	// rolls back the DB can't leave a cleared tracker or a false orphan alert behind. Keyed by the
	// *sql.Tx pointer so concurrent apply transactions never mix effects; the batch/chunk driver
	// runs (runDeferredEffects) or drops (dropDeferredEffects) its tx's effects. See deferAfterCommit.
	txEffectsMu sync.Mutex
	txEffects   map[*sql.Tx][]func()

	// hlcSkewGuard, when non-nil and returning true, enables LWW skew quarantine:
	// an incoming row whose updated_at is beyond hlc.MaxSkewMS into the
	// future (relative to local wall clock) is NOT allowed to win a conflict —
	// kept-local and counted — so a clock-corrupted peer can't dominate LWW. Gated
	// on the LWWSkewGuardV1 latch (injected via SetHLCSkewGuard) so a mixed-version
	// roll doesn't start quarantining before the whole cluster enforces it. Nil/false
	// = legacy behavior (no skew check). Read once per merge batch, not per row.
	// Only the FUTURE-skew case — NowTS still emits wall-clock, so backward-clock
	// regression on restart is not covered here (deferred).
	hlcSkewGuard func() bool
	// skewQuarantined counts rows kept-local by the skew guard, for the metrics
	// layer (mirrors hlc.Clock.Rejected()). Lock-free.
	skewQuarantined atomic.Uint64

	// hlcEmit, when non-nil and returning true, makes NowTS emit the LWW conflict key
	// (updated_at) as an HLC string instead of RFC3339Nano — the backward-clock fix.
	// Gated on `enforcement.hlc_lww && HLCLwwV1 latched` (injected via SetHLCEmit),
	// so a mixed-version roll only starts emitting HLC once every node can parse it.
	// Cheap in-memory read (no ping/I/O) — safe on the per-write path. Nil/false =
	// legacy RFC3339 emission.
	hlcEmit func() bool

	// digestV2Enabled, when non-nil and returning true, makes the state digest + the
	// divergence scanner ALSO emit the order-invariant digest_v2 hashes (TableDigest.HashV2
	// / RowMeta.RowHashV2). Gated on `enforcement.digest_v2` alone (injected via
	// SetDigestV2Enabled) — no cluster latch: v2 is negotiated PAIRWISE by field presence,
	// so a node only emits v2 when locally enabled and comparison uses v2 only when both
	// peers emitted it. Cheap in-memory read. Nil/false = v1-only emission (unchanged).
	digestV2Enabled func() bool

	// canonicalIdentity, when non-nil and returning true, makes the merge paths resolve the
	// natural-key-identity tables (tableIdentityKeys) by their natural key instead of the
	// minted random id. Gated on `enforcement.canonical_identity && CanonicalIdentityV1
	// latched` (injected via SetCanonicalIdentity) — a CLUSTER latch, not pairwise, because
	// identity resolution mutates shared state (a per-sender flip would be non-convergent).
	// Nil/false = legacy behavior (a natural-key collision back-pressures). Read once per
	// merge batch.
	canonicalIdentity func() bool

	// canonicalRegistry, when non-nil and returning true, selects the CANONICAL registry-credential
	// writer: one stable deterministic-id row per (scope,owner,registry), upserted for
	// create/rotate/revoke/revive — instead of the legacy mint-new-id tombstone+insert whose
	// concurrent logins collide on the partial UNIQUE (Part H2). Gated on the H2 activation
	// predicate (capability latch + WAL-drain/consolidation), injected via SetCanonicalRegistry.
	// Nil/false = legacy writer. Activated only AFTER legacy rows are consolidated to their
	// deterministic ids, so the two writers never produce two live rows for one triple.
	canonicalRegistry func() bool

	// canonicalRegistryLatched, when non-nil and returning true, means canonical_registry_v1 is
	// LATCHED cluster-wide (every node can apply the canonical shape). It gates ACCEPTANCE of a
	// replicated canonical upsert (DispCanonicalRegistry), which is DECOUPLED from originating one
	// (canonicalRegistry, the writer): the one-time legacy-row consolidation emits canonical
	// upserts that peers must accept once latched, BEFORE the writer switches. Nil/false ⇒ reject
	// the canonical shape (a premature/buggy peer write fails closed).
	canonicalRegistryLatched func() bool
}

// SetCanonicalIdentity injects the predicate that enables natural-key identity resolution.
// Wired at daemon start to `enforcement.canonical_identity && checker.Latched(CanonicalIdentityV1)`.
// Nil-safe: an unset predicate keeps legacy behavior (a natural-key collision back-pressures).
func (c *Client) SetCanonicalIdentity(fn func() bool) { c.canonicalIdentity = fn }

// canonicalIdentityOn reports whether natural-key identity resolution is currently enforced.
func (c *Client) canonicalIdentityOn() bool {
	return c.canonicalIdentity != nil && c.canonicalIdentity()
}

// SetCanonicalRegistry injects the predicate that activates the canonical registry-credential
// WRITER (Part H2 — originate canonical writes). Nil-safe: unset keeps the legacy mint-new-id writer.
func (c *Client) SetCanonicalRegistry(fn func() bool) { c.canonicalRegistry = fn }

// canonicalRegistryOn reports whether the canonical (deterministic-id) registry writer is active.
func (c *Client) canonicalRegistryOn() bool {
	return c.canonicalRegistry != nil && c.canonicalRegistry()
}

// SetCanonicalRegistryLatched injects the predicate that reports canonical_registry_v1 latched
// cluster-wide (gates ACCEPTANCE of a replicated canonical upsert). Nil-safe: unset ⇒ reject.
func (c *Client) SetCanonicalRegistryLatched(fn func() bool) { c.canonicalRegistryLatched = fn }

// canonicalRegistryLatchedOn reports whether the canonical shape may be applied on this receiver.
func (c *Client) canonicalRegistryLatchedOn() bool {
	return c.canonicalRegistryLatched != nil && c.canonicalRegistryLatched()
}

// capabilityActive reports whether a ledger-named capability (RequiresCapability) is active on THIS
// receiver, so the apply path can resolve a capability-gated shape's effective disposition. For
// canonical_registry_v1 this is the LATCH (accept the shape), NOT the writer gate — the two are
// decoupled so consolidation's canonical writes are accepted before the writer switches. An
// unknown capability returns false (fail closed — a gated shape stays rejected).
func (c *Client) capabilityActive(name string) bool {
	switch name {
	case capabilities.CanonicalRegistryV1:
		return c.canonicalRegistryLatchedOn()
	case capabilities.CanonicalIdentityV1:
		return c.canonicalIdentityOn()
	default:
		return false
	}
}

// SetHLCEmit injects the predicate that switches NowTS to HLC conflict keys. Wired at
// daemon start to `enforcement.hlc_lww && checker.Latched(HLCLwwV1)`. Nil-safe: an unset
// predicate keeps legacy RFC3339 emission.
func (c *Client) SetHLCEmit(fn func() bool) { c.hlcEmit = fn }

// SetDigestV2Enabled injects the predicate that makes the digest + scanner emit the
// order-invariant digest_v2 hashes. Wired at daemon start to `enforcement.digest_v2`.
// Nil-safe: an unset predicate keeps v1-only emission.
func (c *Client) SetDigestV2Enabled(fn func() bool) { c.digestV2Enabled = fn }

// digestV2On reports whether digest_v2 emission is enabled on this node (nil-safe).
func (c *Client) digestV2On() bool { return c.digestV2Enabled != nil && c.digestV2Enabled() }

// SetHLCSkewGuard injects the predicate that enables LWW future-skew quarantine.
// Wired at daemon start to the LWWSkewGuardV1 enforcement latch. Nil-safe: an unset
// guard leaves the legacy no-skew-check behavior, so an old-binary node in a
// mixed-version roll is unaffected.
func (c *Client) SetHLCSkewGuard(fn func() bool) { c.hlcSkewGuard = fn }

// SkewQuarantinedCount returns the cumulative number of incoming rows kept-local
// by the LWW skew guard. Exposed so the metrics layer can publish it.
func (c *Client) SkewQuarantinedCount() uint64 { return c.skewQuarantined.Load() }

// hlcSkewGuardOn reports whether skew quarantine is currently enforced. Cheap;
// read once per merge batch.
func (c *Client) hlcSkewGuardOn() bool {
	return c.hlcSkewGuard != nil && c.hlcSkewGuard()
}

// SetSyncMetrics installs the anti-entropy timing sink. Nil-safe; call once at
// daemon startup before the replicator / anti-entropy loops start.
func (c *Client) SetSyncMetrics(m SyncMetrics) { c.syncMetrics = m }

// observeDump / observeDigest / observeMerge are nil-safe wrappers so the
// dump/digest/merge paths can record unconditionally.
func (c *Client) observeDump(d time.Duration, bytes int) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveDump(d, bytes)
	}
}

func (c *Client) observeDigest(d time.Duration) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveDigest(d)
	}
}

func (c *Client) observeMerge(d time.Duration, merged, skipped int) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveMerge(d, merged, skipped)
	}
}

func (c *Client) observeMergeRejected(table, path, reason string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveMergeRejected(table, path, reason)
	}
}

func (c *Client) observeLegacyTransformed(transformer string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveLegacyTransformed(transformer)
	}
}

func (c *Client) observeIdentityCollapseOrphan(table string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveIdentityCollapseOrphan(table)
	}
}

func (c *Client) observeTieBreak(table, resolver, winner string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveTieBreak(table, resolver, winner)
	}
}

func (c *Client) observeTieUnresolved(table, path, category string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveTieUnresolved(table, path, category)
	}
}

func (c *Client) observeTombstoneTie(table string) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveTombstoneTie(table)
	}
}

func (c *Client) observeUnresolvedTieCurrent(n int) {
	if c.syncMetrics != nil {
		c.syncMetrics.ObserveUnresolvedTieCurrent(n)
	}
}

// nowTSLayout is fixed-width RFC3339 with 9 fractional digits so values sort
// lexically == chronologically (no bare-second vs fractional ambiguity among
// NowTS outputs). time.Parse(time.RFC3339, …) still accepts it.
const nowTSLayout = "2006-01-02T15:04:05.000000000Z07:00"

// nowRFC3339 is the bare second-resolution UTC timestamp for NON-LWW columns
// (created_at, deleted_at markers, enrolled_at, allocated_at, last_*). These are
// displayed or ordered by value, so they must stay bare — a fixed-width
// fractional value sorts lexically BEFORE a bare same-second one, which would
// mis-order mixed old/new rows. Only updated_at (the LWW key) uses NowTS.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// NowWall returns a bare-second RFC3339 UTC wall-clock timestamp for NON-LWW columns
// (created_at, deleted_at, last_seen, and other *_at display/expiry/age markers). It is
// the Client-method form of nowRFC3339 for callers outside this package (e.g. the
// health checker). CRUCIAL vs NowTS: this is NOT the LWW conflict key and NEVER becomes
// an HLC string, so any column read as wall time — display, age math, GC cutoffs,
// timeout parsing — MUST use NowWall, not NowTS. (NowTS becomes HLC once hlc_lww is
// enabled; a wall column stamped with NowTS would then hold an unparseable HLC string.)
func (c *Client) NowWall() string { return c.now().Format(time.RFC3339) }

const (
	// nowTSPersistAhead is how far ahead of the last-emitted LWW timestamp we commit
	// the durable ceiling, so persistence I/O happens ~once per this interval, not per
	// write. Well under hlc.MaxSkewMS (5 min) so our own slightly-ahead emission is
	// never skew-quarantined by peers.
	nowTSPersistAhead = 2 * time.Second
	// nowTSPersistRetries bounds the in-line retry when crossing the ceiling.
	nowTSPersistRetries = 3
)

// now returns the current wall time via the injectable seam (default time.Now).
func (c *Client) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn().UTC()
	}
	return time.Now().UTC()
}

// NowTS returns a strictly-monotonic, fixed-width RFC3339Nano UTC timestamp for
// this Client. It is the timestamp source for replicated rows' updated_at (the
// LWW conflict key): two writes from the same node in the same wall-clock
// nanosecond still get distinct, ordered values, so a same-second burst (e.g. the
// host boot sequence) can't produce a last-writer-wins tie that strands the later
// write on a peer. Per-Client (not a package global) so independent in-process
// test nodes keep independent clocks. NOT used for HLC physical time.
//
// The monotonic high-water is PERSISTED to <dataDir>/nowts.hwm (persist-ahead), so a
// restart after a wall-clock step-back can't emit an OLDER key than this node already
// replicated — the backward-clock lost-update. Clients with no dataDir (throwaway
// tools) keep the in-memory-only monotonic behavior.
//
// This is the LWW CONFLICT KEY ONLY: it is destined to emit an HLC string once the
// hlc_lww migration is enabled, so it must be used ONLY for `updated_at`. Any NON-LWW
// column (created_at, deleted_at, last_seen, display/age/expiry markers) must use
// NowWall — a value read as wall time would break when this starts emitting HLC.
func (c *Client) NowTS() string {
	// HLC conflict-key emission (gated). The HLC clock is itself monotonic + persisted
	// (SetPersistence, PR 1A), so it carries the same backward-clock protection; its
	// physical is current wall-ms, instant-comparable with any RFC3339 key still in
	// flight (per lwwOrder), so the RFC3339↔HLC switch — and a flag-off rollback — never
	// regress. Off the RFC3339 persist-ahead path below.
	if c.hlcEmit != nil && c.clock != nil && c.hlcEmit() {
		return c.clock.Now().String()
	}
	// Bridge floor from the HLC physical high-water — read BEFORE taking tsMu (lock
	// order: persistHLCCeiling takes tsMu while holding the clock lock, so NowTS must
	// never acquire the clock lock while holding tsMu). After HLC emission or a
	// skewed-peer HLC adoption, the HLC physical can be AHEAD of wall; a rollback to
	// RFC3339 must not emit below it, or a fresh RFC key would sort older than existing
	// HLC rows and silently lose LWW. Zero when there's no clock.
	var hlcFloor time.Time
	if c.clock != nil {
		hlcFloor = time.UnixMilli(c.clock.PhysicalMS())
	}
	c.tsMu.Lock()
	defer c.tsMu.Unlock()
	t := c.now()
	if !t.After(c.lastTS) {
		t = c.lastTS.Add(time.Nanosecond)
	}
	// Strictly after the HLC physical instant, so the instant comparator ranks a
	// rollback RFC key ABOVE an equal-millisecond HLC key (an exact-instant tie goes to
	// HLC, which would lose the fresh RFC write).
	if !t.After(hlcFloor) {
		t = hlcFloor.Add(time.Nanosecond)
	}
	if c.hwm != nil && t.After(c.durableTS) {
		t = c.advanceDurableLWWLocked(t)
	}
	c.lastTS = t
	return t.Format(nowTSLayout)
}

// advanceDurableLWWLocked commits a new LWW ceiling (t + persist-ahead) BEFORE NowTS
// returns a value beyond the last durable one, then returns the timestamp NowTS may
// safely emit. On a persistence failure it FAILS CLOSED: it never returns a value past
// the last durably-committed ceiling (so a crash can't regress); it uses any headroom
// left below that ceiling from a prior persist-ahead, and calls onPersistFatal only
// when headroom is exhausted AND persistence is still failing. Called with tsMu held.
func (c *Client) advanceDurableLWWLocked(t time.Time) time.Time {
	newCeil := t.Add(nowTSPersistAhead)
	var err error
	for i := 0; i < nowTSPersistRetries; i++ {
		if err = c.hwm.store(newCeil, c.durableHLCMS); err == nil {
			c.durableTS = newCeil
			return t
		}
	}
	slog.Error("nowts: failed to persist monotonic high-water; clamping to durable ceiling (fail-closed)",
		"error", err, "durable", c.durableTS.Format(nowTSLayout), "want", t.Format(nowTSLayout))
	if t.After(c.durableTS) {
		t = c.durableTS
	}
	if !t.After(c.lastTS) {
		// Headroom exhausted AND persistence failing: advancing would exceed the
		// durable ceiling; not advancing would collide/regress. Refuse.
		if c.onPersistFatal != nil {
			c.onPersistFatal(err)
		}
		// Only reached in tests (production onPersistFatal exits). Return a
		// monotonic +1ns so the caller doesn't spin; this is past the durable
		// ceiling, but the fatal hook has already fired.
		t = c.lastTS.Add(time.Nanosecond)
	}
	return t
}

// persistHLCCeiling durably records a new HLC physical-ms ceiling (paired with the
// current LWW ceiling in nowts.hwm). Wired as the HLC clock's persist hook; the clock
// calls it (under its own lock) when it advances past its last committed ceiling and
// fails closed if this returns an error. No-op without a dataDir.
func (c *Client) persistHLCCeiling(ms int64) error {
	c.tsMu.Lock()
	defer c.tsMu.Unlock()
	if c.hwm == nil {
		return nil
	}
	if err := c.hwm.store(c.durableTS, ms); err != nil {
		return err
	}
	c.durableHLCMS = ms
	return nil
}

// initClockPersistence loads the persisted high-waters (if a dataDir is set) and wires
// durable persistence into NowTS + the HLC clock. A corrupt hwm file is a hard error
// (fail closed + loud) — the caller refuses to start rather than silently reset to
// wall clock. Sets the default onPersistFatal (exit) unless a test already set one.
func (c *Client) initClockPersistence() error {
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.onPersistFatal == nil {
		// DELIBERATE fail-closed decision: when the monotonic ceiling can't be
		// persisted AND the in-memory headroom is exhausted, exit rather than emit an
		// LWW key below the last durable ceiling (which would silently lose updates
		// after a restart). Sustained failure (e.g. a full dataDir disk) therefore
		// crash-loops the daemon — an accepted trade-off: the SQLite state DB lives on
		// the SAME filesystem, so a full disk already fails authoritative writes; a loud
		// crash surfaces it instead of silently corrupting LWW ordering. Recovery = free
		// space (or, as a last resort, delete <dataDir>/nowts.hwm to reset the ceiling,
		// re-opening the regression window until wall time passes the old ceiling).
		c.onPersistFatal = func(err error) {
			slog.Error("nowts: monotonic clock persistence failing and headroom exhausted — exiting to avoid a silent lost update", "error", err)
			os.Exit(1)
		}
	}
	if c.dataDir == "" {
		return nil // no persistence (throwaway client)
	}
	c.hwm = newHWMStore(c.dataDir)
	lww, hlcMS, found, err := c.hwm.load()
	if err != nil {
		return fmt.Errorf("load monotonic high-water: %w (inspect or remove %s to reset — accepts a monotonicity gap)", err, c.hwm.path)
	}
	if found {
		c.lastTS, c.durableTS, c.durableHLCMS = lww, lww, hlcMS
	}
	if c.clock != nil {
		// The HLC clock shares nowts.hwm; a sustained persist failure there is the same
		// fail-closed condition as the RFC path, so route its fatal through onPersistFatal.
		c.clock.SetPersistence(hlcMS, c.persistHLCCeiling, func() {
			c.onPersistFatal(fmt.Errorf("hlc clock: cannot persist physical ceiling"))
		})
	}
	return nil
}

// LocalVersion returns the binary version this Client was created with.
// Empty string if not set; safe to call from peer-handshake paths.
func (c *Client) LocalVersion() string { return c.version }

// SetLocalVersion records the binary version for inclusion in peer
// handshakes. Called once at daemon start; safe-but-pointless to set
// later because the value is read from a stable copy.
func (c *Client) SetLocalVersion(v string) { c.version = v }

// sqliteDSN builds the connection string for the on-disk state store.
//
// auto_vacuum=incremental lets freed pages (e.g. from mutation_log pruning)
// be returned to the OS via `PRAGMA incremental_vacuum`, which the replicator
// runs in its prune loop. Without it (SQLite's default of NONE) deleted rows
// leave free pages that are reused but never shrink the file, so it only ever
// grows to its high-water mark.
//
// NOTE: auto_vacuum only takes effect on a freshly-created database. An
// existing DB adopts it only after a one-time VACUUM (see the upgrade/
// maintenance runbook).
func sqliteDSN(path string) string {
	return fmt.Sprintf(
		"file:%s?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=auto_vacuum(incremental)",
		path)
}

// NewClient creates an embedded SQLite store and joins the gossip cluster.
func NewClient(cfg Config, clock *hlc.Clock) (*Client, error) {
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0"
	}
	if cfg.BindPort == 0 {
		cfg.BindPort = 7946
	}

	// Open SQLite with WAL mode
	dbPath := filepath.Join(cfg.DataDir, "state.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	c := &Client{
		db:               db,
		hostName:         cfg.HostName,
		clock:            clock,
		dataDir:          cfg.DataDir,
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
	}
	if err := c.initClockPersistence(); err != nil {
		db.Close()
		return nil, err
	}

	// Set up memberlist (used for membership detection only — no data replication)
	mlCfg := memberlist.DefaultLANConfig()
	mlCfg.Name = cfg.HostName
	mlCfg.BindAddr = cfg.BindAddr
	mlCfg.BindPort = cfg.BindPort
	mlCfg.AdvertisePort = cfg.BindPort
	mlCfg.LogOutput = &slogWriter{}

	del := &delegate{client: c}
	mlCfg.Delegate = del
	// EventDelegate wakes the replicator's discovery loop on membership changes
	// (separate from Delegate, which carries gossip metadata) — set before Create.
	mlCfg.Events = &membershipEvents{client: c}

	list, err := memberlist.Create(mlCfg)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create memberlist: %w", err)
	}
	c.list = list

	// Join existing peers
	if len(cfg.JoinPeers) > 0 {
		n, err := list.Join(cfg.JoinPeers)
		if err != nil {
			slog.Warn("gossip: partial join", "joined", n, "error", err)
		} else {
			slog.Info("gossip: joined cluster", "peers", n)
		}
	}

	return c, nil
}

// NewLocalClient opens the SQLite database directly without gossip.
// Use this for local admin operations (e.g. password reset).
// When hostName is non-empty, mutations are logged to mutation_log so they
// get picked up by the running daemon's replicator and broadcast to peers.
func NewLocalClient(dataDir string, hostName ...string) (*Client, error) {
	dbPath := filepath.Join(dataDir, "state.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	c := &Client{
		db:               db,
		dataDir:          dataDir,
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
	}
	if len(hostName) > 0 && hostName[0] != "" {
		c.hostName = hostName[0]
		c.clock = hlc.NewClock(hostName[0])
	}
	if err := c.initClockPersistence(); err != nil {
		db.Close()
		return nil, err
	}
	return c, nil
}

// Close leaves the gossip cluster and closes the database.
func (c *Client) Close() error {
	if c.list != nil {
		c.list.Leave(5 * time.Second)
		c.list.Shutdown()
	}
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Row represents a result row.
type Row struct {
	Columns []string
	Values  []interface{}
}

// Statement represents a SQL statement with parameters.
type Statement struct {
	SQL    string
	Params []interface{}
}

// Query executes a read query against the local SQLite database.
func (c *Client) Query(ctx context.Context, sqlStr string, params ...interface{}) ([]Row, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rows, err := c.db.QueryContext(ctx, sqlStr, params...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("columns: %w", err)
	}

	var result []Row
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		// Convert []byte to string for consistency
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		result = append(result, Row{Columns: cols, Values: vals})
	}

	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

// Execute runs a write mutation locally and logs it for replication.
// Execute runs a mutation, logs it to mutation_log, and immediately notifies
// the replicator to push it to peers.
func (c *Client) Execute(ctx context.Context, sqlStr string, params ...interface{}) error {
	_, err := c.executeBatchInternal(ctx, []Statement{{SQL: sqlStr, Params: params}}, true)
	return err
}

// ExecuteRows is Execute that also reports how many rows the application
// statement changed. Use it when a no-op UPDATE must be distinguished from a
// real one — e.g. consuming a single-use token, where a guarded WHERE matching
// zero rows means "not consumed" and the caller must NOT treat it as success.
func (c *Client) ExecuteRows(ctx context.Context, sqlStr string, params ...interface{}) (int64, error) {
	return c.executeBatchInternal(ctx, []Statement{{SQL: sqlStr, Params: params}}, true)
}

// ExecuteDeferred runs a mutation and logs it to mutation_log, but does NOT
// wake the replicator immediately. The mutation is picked up on the next
// periodic replication tick (~10s). Use this for high-frequency, low-priority
// writes like health checks that don't need instant replication.
func (c *Client) ExecuteDeferred(ctx context.Context, sqlStr string, params ...interface{}) error {
	_, err := c.executeBatchInternal(ctx, []Statement{{SQL: sqlStr, Params: params}}, false)
	return err
}

// ExecuteBatch runs multiple mutations in a transaction, atomically writing
// them to the mutation_log for replication to peers.
func (c *Client) ExecuteBatch(ctx context.Context, stmts []Statement) error {
	_, err := c.executeBatchInternal(ctx, stmts, true)
	return err
}

// ExecuteBatchGuarded runs stmts in ONE transaction ONLY IF guard — evaluated
// INSIDE that transaction against a consistent snapshot — returns true. It is the
// compare-and-swap primitive for a repair that must not race its own
// read→probe→write window: the guard re-reads the preconditions atomically with
// the writes. Returns applied=false (no error) when the guard declines, so the
// caller treats that as "preconditions no longer hold — skip and retry later".
func (c *Client) ExecuteBatchGuarded(ctx context.Context, guard func(tx *sql.Tx) (bool, error), stmts []Statement) (bool, error) {
	c.mu.Lock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		c.mu.Unlock()
		return false, fmt.Errorf("begin tx: %w", err)
	}
	ok, gerr := guard(tx)
	if gerr != nil {
		tx.Rollback()
		c.mu.Unlock()
		return false, fmt.Errorf("guard: %w", gerr)
	}
	if !ok {
		tx.Rollback()
		c.mu.Unlock()
		return false, nil
	}
	var mutated []Statement
	for _, s := range stmts {
		res, err := tx.ExecContext(ctx, s.SQL, s.Params...)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return false, fmt.Errorf("exec guarded batch: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil && n > 0 {
			mutated = append(mutated, s)
		}
	}
	if c.clock != nil {
		stmtsJSON, err := json.Marshal(stmts)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return false, fmt.Errorf("marshal stmts: %w", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES (?, ?, ?, ?)`,
			c.clock.Now().String(), c.hostName, string(stmtsJSON), now,
		); err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return false, fmt.Errorf("write mutation_log: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		c.mu.Unlock()
		return false, fmt.Errorf("commit: %w", err)
	}
	c.mu.Unlock()

	if c.anyUnresolved() {
		for _, s := range mutated {
			c.clearUnresolvedFromStmt(s)
		}
	}
	c.notifyReplicator()
	return true, nil
}

func (c *Client) executeBatchInternal(ctx context.Context, stmts []Statement, notify bool) (int64, error) {
	c.mu.Lock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		c.mu.Unlock()
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	var affected int64
	var mutated []Statement // statements that changed ≥1 row (for unresolved-clear)
	for _, s := range stmts {
		res, err := tx.ExecContext(ctx, s.SQL, s.Params...)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return 0, fmt.Errorf("exec batch: %w", err)
		}
		if n, e := res.RowsAffected(); e == nil {
			affected += n
			if n > 0 {
				mutated = append(mutated, s)
			}
		}
	}

	// Write to mutation_log atomically with the application statements.
	if c.clock != nil {
		hlcTS := c.clock.Now()
		stmtsJSON, err := json.Marshal(stmts)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return 0, fmt.Errorf("marshal stmts: %w", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES (?, ?, ?, ?)`,
			hlcTS.String(), c.hostName, string(stmtsJSON), now,
		); err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return 0, fmt.Errorf("write mutation_log: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		c.mu.Unlock()
		return 0, fmt.Errorf("commit: %w", err)
	}
	c.mu.Unlock()

	// A local write that actually CHANGED a row clears any stale unresolved-tie
	// tracking for that PK — the remediation path (e.g. repair-owner's
	// UpdateVMHost). A guarded zero-row statement (WHERE … matched nothing) is
	// excluded: it changed no content, so the tie must stay tracked. Lock-free
	// when nothing is tracked.
	if c.anyUnresolved() {
		for _, s := range mutated {
			c.clearUnresolvedFromStmt(s)
		}
	}

	if notify {
		c.notifyReplicator()
	}
	return affected, nil
}

// execLocal runs a statement locally without logging to mutation_log (used for DDL, replication).
func (c *Client) execLocal(ctx context.Context, sqlStr string, params ...interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.ExecContext(ctx, sqlStr, params...)
	return err
}

// execLocalRows is execLocal that also reports rows affected. Like execLocal it
// is LOCAL-only (no mutation_log row, not replicated) — for deterministic
// per-node maintenance (e.g. GC of superseded rows) where the caller wants a
// deleted-row count for metrics/logging.
func (c *Client) execLocalRows(ctx context.Context, sqlStr string, params ...interface{}) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, err := c.db.ExecContext(ctx, sqlStr, params...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// execBatchLocal runs multiple statements in ONE transaction locally, WITHOUT
// writing a mutation_log row or notifying the replicator. It is the
// non-replicating sibling of executeBatchInternal, for DDL/schema work that
// must be atomic (e.g. a healing ALTER + its applied_migrations ledger insert)
// but must stay local to this host (schema is per-host, never broadcast).
func (c *Client) execBatchLocal(ctx context.Context, stmts []Statement) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s.SQL, s.Params...); err != nil {
			tx.Rollback()
			return fmt.Errorf("exec batch local: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// notifyReplicator sends a non-blocking signal to the replicator.
func (c *Client) notifyReplicator() {
	select {
	case c.replicatorNotify <- struct{}{}:
	default:
	}
}

// ReplicatorNotify returns the channel that fires when new mutations are available.
func (c *Client) ReplicatorNotify() <-chan struct{} {
	return c.replicatorNotify
}

// Clock returns the HLC clock for this client.
func (c *Client) Clock() *hlc.Clock {
	return c.clock
}

// HostName returns the node identity.
func (c *Client) HostName() string {
	return c.hostName
}

// Members returns the current memberlist members (for peer discovery).
// kickMembership wakes the replicator's peer-discovery loop after a gossip
// membership change. Non-blocking and coalescing: a kick already pending covers
// this one, so it's safe to call from memberlist's event goroutines.
func (c *Client) kickMembership() {
	select {
	case c.membershipNotify <- struct{}{}:
	default:
	}
}

// MembershipChanged returns a channel that receives a coalesced signal whenever
// the gossip layer reports a peer join/leave/update. For a local client (no
// gossip) the channel never fires, so selecting on it is always safe.
func (c *Client) MembershipChanged() <-chan struct{} {
	return c.membershipNotify
}

func (c *Client) Members() []PeerInfo {
	if c.list == nil {
		return nil
	}
	var peers []PeerInfo
	for _, m := range c.list.Members() {
		if m.Name == c.hostName {
			continue
		}
		peers = append(peers, PeerInfo{Name: m.Name, Addr: m.Address()})
	}
	return peers
}

// PeerInfo holds basic peer identity from memberlist.
type PeerInfo struct {
	Name string
	Addr string
}

// DB returns the underlying sql.DB for direct access (used by replicator).
func (c *Client) DB() *sql.DB {
	return c.db
}

// Mu returns the RWMutex for callers that need to coordinate with the client.
func (c *Client) Mu() *sync.RWMutex {
	return &c.mu
}

// Helper methods on Row for typed access.

func (r Row) String(col string) string {
	v := r.get(col)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func (r Row) Int(col string) int {
	v := r.get(col)
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func (r Row) Int64(col string) int64 {
	v := r.get(col)
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	default:
		return 0
	}
}

func (r Row) get(col string) interface{} {
	for i, c := range r.Columns {
		if c == col && i < len(r.Values) {
			return r.Values[i]
		}
	}
	return nil
}

// slogWriter adapts slog for memberlist's io.Writer log output.
type slogWriter struct{}

func (w *slogWriter) Write(p []byte) (int, error) {
	slog.Debug(string(p))
	return len(p), nil
}
