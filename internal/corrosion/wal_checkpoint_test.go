package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWALCheckpointSurvivesCancelledReads pins the SQLite driver's handling of a
// cancelled read.
//
// A driver that does not end the read transaction when a query's context is
// cancelled leaves the read snapshot open on the pooled connection. The WAL
// checkpointer can then never advance past that snapshot for the life of the
// process: the WAL grows without bound while the main database stays frozen,
// and once the WAL index is large enough every statement fails with
// SQLITE_BUSY. Only a restart clears it.
//
// The failure needs concurrency — cancelling reads one at a time never trips it —
// so this drives concurrent readers whose contexts expire mid-scan against a
// steady writer, quiesces, and then requires a checkpoint to drain the whole WAL.
// Every *sql.Rows here is closed correctly: the assertion is about the driver,
// not about row handling.
//
// Mutation-verified: fails on modernc.org/sqlite <= v1.40.0, passes on v1.41.0+.
func TestWALCheckpointSurvivesCancelledReads(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive concurrency test")
	}

	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := db.Exec(`INSERT INTO t(id, v) VALUES(?, ?)`, i, fmt.Sprintf("seed-%d", i)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	var wg sync.WaitGroup
	deadline := time.Now().Add(3 * time.Second)

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(int64(seed)))
			for time.Now().Before(deadline) {
				func() {
					// Expire mid-scan: long enough to start reading, far too
					// short to drain 2000 rows.
					ctx, cancel := context.WithTimeout(context.Background(),
						time.Duration(rnd.Intn(800))*time.Microsecond)
					defer cancel()
					rows, err := db.QueryContext(ctx, `SELECT id, v FROM t`)
					if err != nil {
						return
					}
					defer rows.Close()
					for rows.Next() {
						var id int
						var v string
						if err := rows.Scan(&id, &v); err != nil {
							return
						}
					}
				}()
			}
		}(g)
	}
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				db.Exec(`INSERT INTO t(id, v) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET v = excluded.v`,
					(seed*100000)+i%500, "w")
			}
		}(g)
	}
	wg.Wait()

	// Quiesce, and drop idle connections so nothing is merely parked in the
	// pool — only a genuinely pinned read snapshot survives this.
	db.SetMaxIdleConns(0)
	time.Sleep(500 * time.Millisecond)

	var busy, logPages, checkpointed int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &checkpointed); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	var walBytes int64
	if fi, statErr := os.Stat(path + "-wal"); statErr == nil {
		walBytes = fi.Size()
	}

	if busy != 0 || checkpointed < logPages {
		t.Fatalf("checkpoint blocked after cancelled reads: busy=%d checkpointed=%d of %d pages (WAL %d bytes) — "+
			"the driver is leaking a read snapshot on context cancellation",
			busy, checkpointed, logPages, walBytes)
	}
	if walBytes > 64*1024 {
		t.Fatalf("WAL not truncated after checkpoint: %d bytes — a read snapshot is still pinned", walBytes)
	}
}
