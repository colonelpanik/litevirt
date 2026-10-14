package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"

	_ "modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/hlc"
)

var testDBCounter atomic.Int64

// NewTestClient creates an in-memory SQLite client with no gossip.
// Intended for use in tests across packages.
func NewTestClient() (*Client, error) {
	// Each test client gets a unique in-memory DB
	id := testDBCounter.Add(1)
	// busy_timeout matches the production DSN (client.go): shared-cache
	// in-memory DBs serve every fleet node from one pool, and under full-suite
	// load a concurrent read can otherwise hit SQLITE_BUSY instantly — which
	// the fail-closed admission paths correctly refuse on, turning raw lock
	// contention into spurious test-only refusals.
	dsn := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared&_pragma=busy_timeout(5000)", id)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	return &Client{
		db:               db,
		hostName:         "test-node",
		clock:            hlc.NewClock("test-node"),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}, nil
}

// testLeaseTermLedgerOpen is what the test constructors wire into
// Client.leaseTermLedger. The real gate is DurablyLatched(lease_term_ledger_v1),
// which answers "is any peer still on a build that cannot resolve the mint's
// statement shape" — a question a single-version test cluster cannot pose. A
// test that wants the CLOSED side calls SetLeaseTermLedgerGate itself.
func testLeaseTermLedgerOpen() bool { return true }

// NewSharedTestClient opens a shared in-memory SQLite database identified by
// dsnSuffix. Multiple calls with the same dsnSuffix return clients pointing
// at the same DB — a reasonable proxy for "all hosts converged via CRDT
// replication" in cross-package tests, without needing the full replicator.
//
// Use distinct suffixes when you want to simulate a network partition.
//
// Test-only. The returned client is not started (no replicator, no gossip).
func NewSharedTestClient(dsnSuffix, hostName string) (*Client, error) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=busy_timeout(5000)", dsnSuffix)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Client{
		db:               db,
		hostName:         hostName,
		clock:            hlc.NewClock(hostName),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}, nil
}

// RefoundTableForTest rebuilds table, keeping its rows, in the physical column
// order a database FOUNDED at schema version foundedAt and then upgraded to
// this build would hold: the columns no later ALTER added stay where a fresh
// CREATE TABLE declares them, and every column an ALTER after foundedAt added
// is appended, in schemaMigrations order, by running that real ALTER.
//
// It returns the table's columns in their new physical order. A table no ALTER
// after foundedAt touches comes back unchanged.
//
// It reproduces the one way two replicas of one build hold identical rows in
// different column orders. SELECT * — the positional v1 digest — sees that;
// the merge, which works by column name, does not.
func (c *Client) RefoundTableForTest(ctx context.Context, table string, foundedAt int) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type colDef struct {
		name, typ string
		notNull   bool
		dflt      sql.NullString
		pk        int
	}
	rows, err := c.db.QueryContext(ctx, `SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, err
	}
	var defs []colDef
	for rows.Next() {
		var d colDef
		if err := rows.Scan(&d.name, &d.typ, &d.notNull, &d.dflt, &d.pk); err != nil {
			rows.Close()
			return nil, err
		}
		defs = append(defs, d)
	}
	rows.Close()
	if len(defs) == 0 {
		return nil, fmt.Errorf("RefoundTableForTest: no table %q", table)
	}
	late := map[string]bool{}
	var alters []string
	for i, stmt := range schemaMigrations {
		t, col := parseAddColumn(stmt)
		if t == table && alterVersions[i] > foundedAt {
			late[col] = true
			alters = append(alters, stmt)
		}
	}
	var early, all []string
	pks := map[int]string{}
	for _, d := range defs {
		all = append(all, d.name)
		if d.pk > 0 {
			pks[d.pk] = d.name
		}
		if late[d.name] {
			continue
		}
		def := d.name + " " + d.typ
		if d.notNull {
			def += " NOT NULL"
		}
		if d.dflt.Valid {
			def += " DEFAULT " + d.dflt.String
		}
		early = append(early, def)
	}
	if len(pks) > 0 {
		pkCols := make([]string, 0, len(pks))
		for i := 1; i <= len(pks); i++ {
			pkCols = append(pkCols, pks[i])
		}
		early = append(early, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}
	var indexes []string
	irows, err := c.db.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL`, table)
	if err != nil {
		return nil, err
	}
	for irows.Next() {
		var s string
		if err := irows.Scan(&s); err != nil {
			irows.Close()
			return nil, err
		}
		indexes = append(indexes, s)
	}
	irows.Close()

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	old := table + "__refound_old"
	colList := strings.Join(all, ", ")
	stmts := []string{
		"ALTER TABLE " + table + " RENAME TO " + old,
		"CREATE TABLE " + table + " (" + strings.Join(early, ", ") + ")",
	}
	stmts = append(stmts, alters...)
	stmts = append(stmts,
		"INSERT INTO "+table+" ("+colList+") SELECT "+colList+" FROM "+old,
		"DROP TABLE "+old)
	stmts = append(stmts, indexes...)
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return nil, fmt.Errorf("RefoundTableForTest %s: %q: %w", table, s, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	crow, err := c.db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, err
	}
	defer crow.Close()
	var order []string
	for crow.Next() {
		var n string
		if err := crow.Scan(&n); err != nil {
			return nil, err
		}
		order = append(order, n)
	}
	return order, crow.Err()
}
