package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	_ "modernc.org/sqlite"

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
	// ObserveTieBreak records an exact-timestamp tie that a resolver converged:
	// resolver ∈ {tombstone, content_max, numeric_max, timestamp_max,
	// non_null_wins, lb_generation}; winner ∈ {local, incoming}.
	ObserveTieBreak(table, resolver, winner string)
	// ObserveTieUnresolved records a DISTINCT unresolved tie (counted once per
	// (table,PK,content-pair), not per cycle): path ∈ {ae, wal}; category ∈
	// {runtime_owned, tenancy, policy, auth_factor, auth_pointer, lb_token}.
	ObserveTieUnresolved(table, path, category string)
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

	// tsMu guards lastTS, the monotonic source behind NowTS(). Kept separate from
	// mu so timestamp generation (called before a write acquires mu) never
	// contends with or re-enters the main lock.
	tsMu   sync.Mutex
	lastTS time.Time

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

// NowTS returns a strictly-monotonic, fixed-width RFC3339Nano UTC timestamp for
// this Client. It is the timestamp source for replicated rows' updated_at (the
// LWW conflict key): two writes from the same node in the same wall-clock
// nanosecond still get distinct, ordered values, so a same-second burst (e.g. the
// host boot sequence) can't produce a last-writer-wins tie that strands the later
// write on a peer. Per-Client (not a package global) so independent in-process
// test nodes keep independent clocks. NOT used for HLC physical time.
func (c *Client) NowTS() string {
	c.tsMu.Lock()
	defer c.tsMu.Unlock()
	t := time.Now().UTC()
	if !t.After(c.lastTS) {
		t = c.lastTS.Add(time.Nanosecond)
	}
	c.lastTS = t
	return t.Format(nowTSLayout)
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
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
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
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
	}
	if len(hostName) > 0 && hostName[0] != "" {
		c.hostName = hostName[0]
		c.clock = hlc.NewClock(hostName[0])
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
