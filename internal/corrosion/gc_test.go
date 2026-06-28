package corrosion

import (
	"context"
	"testing"
	"time"
)

func gcRC(t *testing.T, c *Client, username, hash, setID, updatedAt string) {
	t.Helper()
	if err := c.execLocal(context.Background(),
		`INSERT INTO recovery_codes (username, code_hash, created_at, set_id, updated_at) VALUES (?, ?, ?, ?, ?)`,
		username, hash, updatedAt, setID, updatedAt); err != nil {
		t.Fatalf("insert recovery_code: %v", err)
	}
}

func gcRCSet(t *testing.T, c *Client, username, activeSetID, updatedAt string) {
	t.Helper()
	if err := c.execLocal(context.Background(),
		`INSERT INTO recovery_code_sets (username, active_set_id, updated_at) VALUES (?, ?, ?)`,
		username, activeSetID, updatedAt); err != nil {
		t.Fatalf("insert recovery_code_set: %v", err)
	}
}

func gcLBConfig(t *testing.T, c *Client, name, generation, updatedAt string, tombstoned bool) {
	t.Helper()
	del := ""
	if tombstoned {
		del = updatedAt
	}
	if err := c.execLocal(context.Background(),
		`INSERT INTO lb_configs (name, vip, algorithm, hosts, ports, enabled, updated_at, generation, deleted_at)
		 VALUES (?, '10.0.0.1', 'rr', '[]', '[]', 1, ?, ?, NULLIF(?, ''))`,
		name, updatedAt, generation, del); err != nil {
		t.Fatalf("insert lb_config: %v", err)
	}
}

func gcLBBackend(t *testing.T, c *Client, lbName, name, generation, updatedAt string) {
	t.Helper()
	if err := c.execLocal(context.Background(),
		`INSERT INTO lb_backends (lb_name, name, address, enabled, updated_at, generation) VALUES (?, ?, '10.0.0.9', 1, ?, ?)`,
		lbName, name, updatedAt, generation); err != nil {
		t.Fatalf("insert lb_backend: %v", err)
	}
}

func rcExists(t *testing.T, c *Client, hash string) bool {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT 1 FROM recovery_codes WHERE code_hash = ?`, hash)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows) > 0
}

func lbBackendExists(t *testing.T, c *Client, lbName, name string) bool {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT 1 FROM lb_backends WHERE lb_name = ? AND name = ?`, lbName, name)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows) > 0
}

// TestGCSupersededRows is the core GC behavior: superseded rows past the core
// cutoff are deleted; current-active-set / current-generation rows are NEVER
// deleted (even when old); orphaned rows use the LONGER orphan retention; and
// rows younger than the cutoff are kept.
func TestGCSupersededRows(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	old := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)          // > coreRetention, < orphanRetention
	recent := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339Nano)      // younger than any cutoff
	ancient := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano) // > orphanRetention

	// ── recovery_codes ──────────────────────────────────────────────
	gcRCSet(t, c, "alice", "set-NEW", recent)                  // alice's live active set
	gcRC(t, c, "alice", "$rc_current_old", "set-NEW", old)     // current set, OLD → KEEP (active)
	gcRC(t, c, "alice", "$rc_super_old", "set-OLD", old)       // superseded, OLD → DELETE (core)
	gcRC(t, c, "alice", "$rc_super_recent", "set-OLD", recent) // superseded but young → KEEP
	// bob: no live pointer (orphaned codes).
	gcRC(t, c, "bob", "$rc_orphan_24h", "set-X", old)         // orphan, 72h old (< 7d) → KEEP under orphan retention
	gcRC(t, c, "bob", "$rc_orphan_ancient", "set-X", ancient) // orphan, 30d old → DELETE

	// ── lb_backends ─────────────────────────────────────────────────
	gcLBConfig(t, c, "lb-live", "gen-NEW", recent, false)          // live config, current gen NEW
	gcLBBackend(t, c, "lb-live", "be_current_old", "gen-NEW", old) // matches live gen, OLD → KEEP
	gcLBBackend(t, c, "lb-live", "be_stale_old", "gen-OLD", old)   // stale gen under live config, OLD → DELETE
	gcLBConfig(t, c, "lb-dead", "gen-D", recent, true)             // tombstoned config
	gcLBBackend(t, c, "lb-dead", "be_tombstoned", "gen-D", old)    // config tombstoned, OLD → DELETE (core)
	gcLBBackend(t, c, "lb-orphan", "be_orphan_24h", "gen-Z", old)  // no config row, 72h old → KEEP under orphan retention

	deleted, err := GCSupersededRows(ctx, c, time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// recovery_codes assertions.
	if rcExists(t, c, "$rc_super_old") {
		t.Error("superseded old recovery code not GC'd (core)")
	}
	if !rcExists(t, c, "$rc_current_old") {
		t.Error("CURRENT active-set code was GC'd — must never happen")
	}
	if !rcExists(t, c, "$rc_super_recent") {
		t.Error("young superseded code GC'd before the core cutoff")
	}
	if !rcExists(t, c, "$rc_orphan_24h") {
		t.Error("72h-old orphan GC'd under the core cutoff — orphans must use the longer orphan retention")
	}
	if rcExists(t, c, "$rc_orphan_ancient") {
		t.Error("30d-old orphan not GC'd under the orphan retention")
	}

	// lb_backends assertions.
	if lbBackendExists(t, c, "lb-live", "be_stale_old") {
		t.Error("stale-generation backend under a live config not GC'd (core)")
	}
	if !lbBackendExists(t, c, "lb-live", "be_current_old") {
		t.Error("CURRENT-generation backend was GC'd — must never happen")
	}
	if lbBackendExists(t, c, "lb-dead", "be_tombstoned") {
		t.Error("backend under a tombstoned config not GC'd (core)")
	}
	if !lbBackendExists(t, c, "lb-orphan", "be_orphan_24h") {
		t.Error("72h-old orphan backend GC'd under the core cutoff — should use orphan retention")
	}

	if deleted["recovery_codes"] != 2 || deleted["lb_backends"] != 2 {
		t.Errorf("delete counts = %v, want recovery_codes=2, lb_backends=2", deleted)
	}
}

// TestGCSupersededRows_NoMutationLog pins the LOCAL-only invariant: GC must not
// write any mutation_log rows (a replicated DELETE would be union-unsafe).
func TestGCSupersededRows_NoMutationLog(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	old := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)
	gcRCSet(t, c, "alice", "set-NEW", old)
	gcRC(t, c, "alice", "$rc", "set-OLD", old) // superseded → will be deleted

	before := mutationLogCount(t, c)
	if _, err := GCSupersededRows(ctx, c, time.Hour, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if rcExists(t, c, "$rc") {
		t.Fatal("precondition: the superseded code should have been deleted")
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("GC wrote %d mutation_log row(s); must be local-only (0)", after-before)
	}
}

func mutationLogCount(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	return int(rows[0].Int("n"))
}
