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
	return c.executeBatchInternal(ctx, []Statement{{SQL: sqlStr, Params: params}}, true)
}

// ExecuteDeferred runs a mutation and logs it to mutation_log, but does NOT
// wake the replicator immediately. The mutation is picked up on the next
// periodic replication tick (~10s). Use this for high-frequency, low-priority
// writes like health checks that don't need instant replication.
func (c *Client) ExecuteDeferred(ctx context.Context, sqlStr string, params ...interface{}) error {
	return c.executeBatchInternal(ctx, []Statement{{SQL: sqlStr, Params: params}}, false)
}

// ExecuteBatch runs multiple mutations in a transaction, atomically writing
// them to the mutation_log for replication to peers.
func (c *Client) ExecuteBatch(ctx context.Context, stmts []Statement) error {
	return c.executeBatchInternal(ctx, stmts, true)
}

func (c *Client) executeBatchInternal(ctx context.Context, stmts []Statement, notify bool) error {
	c.mu.Lock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("begin tx: %w", err)
	}

	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s.SQL, s.Params...); err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return fmt.Errorf("exec batch: %w", err)
		}
	}

	// Write to mutation_log atomically with the application statements.
	if c.clock != nil {
		hlcTS := c.clock.Now()
		stmtsJSON, err := json.Marshal(stmts)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return fmt.Errorf("marshal stmts: %w", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES (?, ?, ?, ?)`,
			hlcTS.String(), c.hostName, string(stmtsJSON), now,
		); err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return fmt.Errorf("write mutation_log: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("commit: %w", err)
	}
	c.mu.Unlock()

	if notify {
		c.notifyReplicator()
	}
	return nil
}

// execLocal runs a statement locally without logging to mutation_log (used for DDL, replication).
func (c *Client) execLocal(ctx context.Context, sqlStr string, params ...interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.ExecContext(ctx, sqlStr, params...)
	return err
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
