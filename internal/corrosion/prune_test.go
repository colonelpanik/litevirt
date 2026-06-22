package corrosion

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ── helpers ──────────────────────────────────────────────────────────────

func tsAgo(d time.Duration) string {
	return time.Now().Add(-d).UTC().Format(time.RFC3339)
}

func insertLogRow(t *testing.T, c *Client, createdAt string) {
	t.Helper()
	if _, err := c.db.ExecContext(context.Background(),
		`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES (?, ?, ?, ?)`,
		"0", "n", "x", createdAt); err != nil {
		t.Fatalf("insert mutation_log: %v", err)
	}
}

func countLog(t *testing.T, c *Client) int {
	t.Helper()
	var n int
	if err := c.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM mutation_log`).Scan(&n); err != nil {
		t.Fatalf("count mutation_log: %v", err)
	}
	return n
}

func setWatermark(t *testing.T, c *Client, peer string, seq int64, updatedAt string) {
	t.Helper()
	if _, err := c.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)`,
		peer, seq, updatedAt); err != nil {
		t.Fatalf("set watermark: %v", err)
	}
}

type pruneVars struct{ minAge, liveWin, maxRet time.Duration }

func saveVars() pruneVars {
	return pruneVars{PruneMinAge, LiveWatermarkWindow, MaxLogRetention}
}
func restoreVars(v pruneVars) {
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = v.minAge, v.liveWin, v.maxRet
}

func newPruneTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.db.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// ── tests ────────────────────────────────────────────────────────────────

// A dead/long-silent peer's watermark must not pin the log: pruning advances
// to the slowest LIVE peer. (This is the parked-node bug: one parked node
// holding the whole cluster's mutation_log from compacting.)
func TestPruneMutationLog_DeadPeerDoesNotPin(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ { // seqs 1..10, all old enough to clear PruneMinAge
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "live-peer", 8, tsAgo(10*time.Second)) // fresh
	setWatermark(t, c, "dead-peer", 2, tsAgo(2*time.Hour))    // stale, excluded

	NewReplicator(c, "", RelayConfig{}).pruneMutationLog(context.Background())

	// Old behavior (MIN over all watermarks = 2) would leave 8 rows; new
	// behavior prunes to the live peer's seq 8, leaving seqs 9,10.
	if got := countLog(t, c); got != 2 {
		t.Fatalf("after prune: %d rows remain, want 2 (dead peer must not pin the log)", got)
	}
}

// A slow-but-live peer is still protected: the log never prunes past what the
// slowest LIVE peer has acked.
func TestPruneMutationLog_LivePeerProtected(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 10; i++ {
		insertLogRow(t, c, tsAgo(30*time.Minute))
	}
	setWatermark(t, c, "fast-peer", 9, tsAgo(5*time.Second))
	setWatermark(t, c, "slow-peer", 3, tsAgo(2*time.Minute)) // live (within window), behind

	NewReplicator(c, "", RelayConfig{}).pruneMutationLog(context.Background())

	// MIN over live peers = 3 → only seqs 1..3 prune, 7 remain.
	if got := countLog(t, c); got != 7 {
		t.Fatalf("after prune: %d rows remain, want 7 (slow live peer must be protected)", got)
	}
}

// The PruneMinAge floor protects very recent entries even when a watermark
// already covers them (avoids racing an in-flight push).
func TestPruneMutationLog_MinAgeFloor(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 240*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 5; i++ {
		insertLogRow(t, c, tsAgo(1*time.Minute)) // newer than PruneMinAge
	}
	setWatermark(t, c, "live-peer", 5, tsAgo(5*time.Second))

	NewReplicator(c, "", RelayConfig{}).pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 5 {
		t.Fatalf("after prune: %d rows remain, want 5 (recent entries below the age floor must survive)", got)
	}
}

// The absolute retention ceiling bounds growth even with no usable watermark
// (peerless node, or all watermarks stale).
func TestPruneMutationLog_RetentionCeiling(t *testing.T) {
	defer restoreVars(saveVars())
	PruneMinAge, LiveWatermarkWindow, MaxLogRetention = 10*time.Minute, 30*time.Minute, 24*time.Hour

	c := newPruneTestClient(t)
	for i := 0; i < 3; i++ {
		insertLogRow(t, c, tsAgo(48*time.Hour)) // older than ceiling
	}
	for i := 0; i < 2; i++ {
		insertLogRow(t, c, tsAgo(1*time.Minute)) // recent
	}
	// No watermarks at all → step 1 is a no-op; the ceiling must still bound it.

	NewReplicator(c, "", RelayConfig{}).pruneMutationLog(context.Background())

	if got := countLog(t, c); got != 2 {
		t.Fatalf("after prune: %d rows remain, want 2 (ceiling should drop the 3 stale rows)", got)
	}
}

// degradedStep marks a peer degraded only after replicateDegradedRounds
// consecutive full batches, and signals recovery exactly once when a
// previously-degraded peer drains below a full batch.
func TestDegradedStep(t *testing.T) {
	// Ramp up: full batches accumulate; degraded fires once at the threshold.
	rounds := 0
	for i := 1; i < replicateDegradedRounds; i++ {
		var entered, recovered bool
		rounds, entered, recovered = degradedStep(rounds, replicateBatchSize)
		if entered || recovered {
			t.Fatalf("round %d: entered=%v recovered=%v, want both false before threshold", i, entered, recovered)
		}
		if rounds != i {
			t.Fatalf("round %d: rounds=%d, want %d", i, rounds, i)
		}
	}
	rounds, entered, recovered := degradedStep(rounds, replicateBatchSize)
	if !entered || recovered {
		t.Fatalf("at threshold: entered=%v recovered=%v, want entered only", entered, recovered)
	}
	// Staying degraded doesn't re-fire entered.
	rounds, entered, _ = degradedStep(rounds, replicateBatchSize)
	if entered {
		t.Fatalf("past threshold: entered re-fired, want false (rounds=%d)", rounds)
	}
	// A short batch drains the counter and signals recovery once.
	rounds, entered, recovered = degradedStep(rounds, replicateBatchSize-1)
	if entered || !recovered || rounds != 0 {
		t.Fatalf("recovery: entered=%v recovered=%v rounds=%d, want recovered only + reset", entered, recovered, rounds)
	}
	// A non-degraded short batch is silent.
	_, entered, recovered = degradedStep(0, 0)
	if entered || recovered {
		t.Fatalf("idle: entered=%v recovered=%v, want both false", entered, recovered)
	}
}

func insertClockSkew(t *testing.T, c *Client, observer, target, updatedAt string) {
	t.Helper()
	if _, err := c.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES (?, ?, ?, ?)`,
		observer, target, 1.5, updatedAt); err != nil {
		t.Fatalf("insert clock_skew: %v", err)
	}
}

func insertHostRow(t *testing.T, c *Client, name string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := c.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		name, "10.0.0.1", "root", "00", now, now); err != nil {
		t.Fatalf("insert host: %v", err)
	}
}

func countClockSkew(t *testing.T, c *Client) int {
	t.Helper()
	var n int
	if err := c.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM clock_skew`).Scan(&n); err != nil {
		t.Fatalf("count clock_skew: %v", err)
	}
	return n
}

// pruneClockSkew drops stale rows (older than ClockSkewRetention) and rows whose
// target is no longer a known host, but keeps fresh rows for live hosts.
func TestPruneClockSkew(t *testing.T) {
	defer func(orig time.Duration) { ClockSkewRetention = orig }(ClockSkewRetention)
	ClockSkewRetention = 1 * time.Hour

	c := newPruneTestClient(t)
	insertHostRow(t, c, "self")
	insertHostRow(t, c, "live-peer")

	insertClockSkew(t, c, "self", "live-peer", tsAgo(30*time.Second)) // fresh + known → keep
	insertClockSkew(t, c, "self", "old-peer", tsAgo(2*time.Hour))     // stale → drop on age
	insertClockSkew(t, c, "self", "departed", tsAgo(10*time.Second))  // fresh but unknown → drop

	NewReplicator(c, "", RelayConfig{}).pruneClockSkew(context.Background())

	if got := countClockSkew(t, c); got != 1 {
		t.Fatalf("after prune: %d rows remain, want 1 (only the fresh known-host row)", got)
	}
	var target string
	if err := c.db.QueryRowContext(context.Background(),
		`SELECT target FROM clock_skew`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if target != "live-peer" {
		t.Fatalf("survivor target = %q, want live-peer", target)
	}
}

// With an empty hosts table the departed-host clause is suppressed (guarded by
// EXISTS(hosts)), so a fresh row survives and only age-based deletion applies —
// a transiently empty hosts table at startup must not wipe live observations.
func TestPruneClockSkew_EmptyHostsKeepsFresh(t *testing.T) {
	defer func(orig time.Duration) { ClockSkewRetention = orig }(ClockSkewRetention)
	ClockSkewRetention = 1 * time.Hour

	c := newPruneTestClient(t)
	insertClockSkew(t, c, "self", "peer", tsAgo(30*time.Second)) // fresh, no hosts rows at all

	NewReplicator(c, "", RelayConfig{}).pruneClockSkew(context.Background())

	if got := countClockSkew(t, c); got != 1 {
		t.Fatalf("after prune with empty hosts: %d rows remain, want 1 (fresh row must survive)", got)
	}
}

// The production DSN enables incremental auto_vacuum so freed pages can be
// returned to the OS by PRAGMA incremental_vacuum.
func TestSqliteDSN_EnablesIncrementalAutoVacuum(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatal(err)
	}
	var av int
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil {
		t.Fatal(err)
	}
	if av != 2 { // 0=NONE, 1=FULL, 2=INCREMENTAL
		t.Fatalf("auto_vacuum = %d, want 2 (incremental)", av)
	}
}
