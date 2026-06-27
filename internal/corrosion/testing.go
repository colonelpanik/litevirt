package corrosion

import (
	"database/sql"
	"fmt"
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
	dsn := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared", id)

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
	}, nil
}

// NewSharedTestClient opens a shared in-memory SQLite database identified by
// dsnSuffix. Multiple calls with the same dsnSuffix return clients pointing
// at the same DB — a reasonable proxy for "all hosts converged via CRDT
// replication" in cross-package tests, without needing the full replicator.
//
// Use distinct suffixes when you want to simulate a network partition.
//
// Test-only. The returned client is not started (no replicator, no gossip).
func NewSharedTestClient(dsnSuffix, hostName string) (*Client, error) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", dsnSuffix)
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
	}, nil
}
