package corrosion

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// buildLegacyV28DB simulates a pre-ledger DB at schema v28: it runs schemaDDL
// (CREATE TABLE IF NOT EXISTS already includes every current column) and stamps
// schema_state.version=28, but creates NO applied_migrations table — exactly
// the shape of a live cluster node before this change.
func buildLegacyV28DB(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	for _, ddl := range schemaDDL {
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatalf("legacy DDL: %v", err)
		}
	}
	if err := c.execLocal(ctx,
		`INSERT OR REPLACE INTO schema_state (id, version, updated_at) VALUES (1, ?, datetime('now'))`,
		CurrentSchemaVersion); err != nil {
		t.Fatalf("seed schema_state: %v", err)
	}
}

func appliedCount(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM applied_migrations`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("count applied_migrations: err=%v rows=%d", err, len(rows))
	}
	return rows[0].Int("n")
}

func storedVersion(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT version FROM schema_state WHERE id = 1`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read schema_state: err=%v rows=%d", err, len(rows))
	}
	return rows[0].Int("version")
}

// ── ledger structural invariants ───────────────────────────────────────────

// The addColumn ledger units must mirror schemaMigrations 1:1, in order — the
// anti-drift guard.
func TestLedger_AddColumnParityWithSchemaMigrations(t *testing.T) {
	if len(alterVersions) != len(schemaMigrations) {
		t.Fatalf("alterVersions=%d schemaMigrations=%d", len(alterVersions), len(schemaMigrations))
	}
	for i := range schemaMigrations {
		m := schemaMigrationLedger[i]
		if m.Kind != kindAddColumn {
			t.Fatalf("ledger[%d] kind=%d, want addColumn", i, m.Kind)
		}
		if m.SQL != schemaMigrations[i] {
			t.Errorf("ledger[%d].SQL=%q, want %q", i, m.SQL, schemaMigrations[i])
		}
	}
}

// Every schema version in 1..CurrentSchemaVersion must have at least one ledger
// unit, so derivedSchemaVersion advances for table-only versions too. This is
// what forces a future table-only version to add a ledger entry.
func TestLedger_CoversEveryVersion(t *testing.T) {
	have := map[int]bool{}
	ids := map[string]bool{}
	for _, m := range schemaMigrationLedger {
		if m.ID == "" {
			t.Fatal("ledger unit with empty ID")
		}
		if ids[m.ID] {
			t.Fatalf("duplicate ledger ID %q", m.ID)
		}
		ids[m.ID] = true
		if m.Version < 1 || m.Version > CurrentSchemaVersion {
			t.Errorf("ledger %q version %d out of range 1..%d", m.ID, m.Version, CurrentSchemaVersion)
		}
		have[m.Version] = true
	}
	for v := 1; v <= CurrentSchemaVersion; v++ {
		if !have[v] {
			t.Errorf("no ledger unit covers schema version %d", v)
		}
	}
}

// ── InitSchema behavior ─────────────────────────────────────────────────────

// Fresh DB: CREATE TABLE includes every column, so every ledger unit is present
// (mark-only, zero ALTERs run); ledger fully populated, version == current.
func TestInitSchema_FreshDB(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if n := appliedCount(t, c); n != len(schemaMigrationLedger) {
		t.Errorf("applied_migrations rows=%d, want %d", n, len(schemaMigrationLedger))
	}
	if v := storedVersion(t, c); v != CurrentSchemaVersion {
		t.Errorf("schema_state.version=%d, want %d", v, CurrentSchemaVersion)
	}
}

func TestInitSchema_RebuildsTheEarlierV47ClusterCRLShape(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := c.execLocal(ctx, `CREATE TABLE cluster_crl (
		id TEXT PRIMARY KEY,
		crl_pem TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT
	)`); err != nil {
		t.Fatalf("create earlier v47 shape: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	got, err := primaryKeyColumns(ctx, c.db, "cluster_crl")
	if err != nil {
		t.Fatalf("read rebuilt primary key: %v", err)
	}
	if !slices.Equal(got, []string{"id", "crl_pem"}) {
		t.Fatalf("cluster_crl primary key = %v, want [id crl_pem]", got)
	}
}

// Bootstrap: a legacy v28 DB (no ledger) gets the ledger seeded by mark-only
// (nothing re-run), version stays 28.
func TestInitSchema_SeedsLedgerOnExistingDB(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	buildLegacyV28DB(t, c)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema on legacy DB: %v", err)
	}
	if n := appliedCount(t, c); n != len(schemaMigrationLedger) {
		t.Errorf("applied_migrations rows=%d, want %d", n, len(schemaMigrationLedger))
	}
	if v := storedVersion(t, c); v != CurrentSchemaVersion {
		t.Errorf("schema_state.version=%d, want %d", v, CurrentSchemaVersion)
	}
}

// The scary edge: a legacy v28 DB with a silently-missing column AND table (the
// drift the old swallow-benign loop could leave) must be HEALED, not falsely
// marked — proving mark-applied is gated on presence, never the version number.
func TestInitSchema_HealsSilentGap(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	buildLegacyV28DB(t, c)
	// Introduce a silent gap: drop a v28 column and a v27 table, leave version 28.
	if err := c.execLocal(ctx, `ALTER TABLE containers DROP COLUMN on_host_failure`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := c.execLocal(ctx, `DROP TABLE container_snapshots`); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema (should heal): %v", err)
	}

	// Column re-added (heal path) and table re-created (schemaDDL) — both present.
	if ok, _ := columnExists(ctx, c.db, "containers", "on_host_failure"); !ok {
		t.Error("containers.on_host_failure not healed")
	}
	if ok, _ := tableExists(ctx, c, "container_snapshots"); !ok {
		t.Error("container_snapshots not re-created")
	}
	if n := appliedCount(t, c); n != len(schemaMigrationLedger) {
		t.Errorf("applied_migrations rows=%d, want %d", n, len(schemaMigrationLedger))
	}
}

// An applied migration whose recorded checksum no longer matches the code (the
// SQL was edited after shipping) aborts loudly.
func TestInitSchema_ChecksumDriftAborts(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := c.execLocal(ctx,
		`UPDATE applied_migrations SET checksum = 'bogus' WHERE id = ?`,
		schemaMigrationLedger[0].ID); err != nil {
		t.Fatalf("corrupt checksum: %v", err)
	}
	err = InitSchema(ctx, c)
	if err == nil || !containsFold(err.Error(), "checksum drift") {
		t.Fatalf("want checksum drift abort, got: %v", err)
	}
}

// InitSchema must not write a single mutation_log row — proving the ledger +
// DDL are local-only and never replicate to peers.
func TestInitSchema_NoReplication(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Run again with a healable gap to exercise the execBatchLocal path too.
	if err := c.execLocal(ctx, `ALTER TABLE vms DROP COLUMN project`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := c.execLocal(ctx, `DELETE FROM applied_migrations WHERE id LIKE 'a%vms_project'`); err != nil {
		t.Fatalf("clear ledger row: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema (heal): %v", err)
	}
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatalf("count mutation_log: %v", err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("InitSchema wrote %d mutation_log rows; schema must be local-only", n)
	}
}

// TestInitSchema_IdempotentOnSecondCall: running InitSchema twice (the on-restart
// case) is a clean no-op — every ledger unit is already recorded, checksums match.
func TestInitSchema_IdempotentOnSecondCall(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("second InitSchema (idempotent): %v", err)
	}
}

// TestInitSchema_AllowsForwardDB: a DB forward-migrated past this binary
// (an old binary on a newer additive DB — the steady mid-rolling-upgrade state)
// now STARTS instead of refusing (PR B). The stored forward version is NOT
// regressed, and EffectiveDBSchema reports the DB's real (forward) level via
// max(derived, stored) — so this node still advertises the true schema to peers.
func TestInitSchema_AllowsForwardDB(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	forward := CurrentSchemaVersion + 5
	if err := c.execLocal(ctx,
		`UPDATE schema_state SET version = ?, updated_at = datetime('now') WHERE id = 1`,
		forward); err != nil {
		t.Fatalf("simulate forward-migrate: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema must start on a forward (additive) DB, got: %v", err)
	}
	if v := storedVersion(t, c); v != forward {
		t.Errorf("stored version regressed to %d; must stay %d", v, forward)
	}
	if e := c.EffectiveDBSchema(); e != forward {
		t.Errorf("EffectiveDBSchema = %d, want forward %d (max of derived, stored)", e, forward)
	}
}

// buildV42DB shapes a DB exactly as upstream schema v42 left it: every table
// from a version ≤42, WITHOUT the columns v43+ ALTERs added and WITHOUT the
// v45+ tables, stamped schema_state.version=42. This is the upgrade-horizon
// fixture the v50 release must migrate: a cluster coming straight from the
// last pre-consolidation upstream schema.
func buildV42DB(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	for _, ddl := range schemaDDL {
		// Strip line comments: SQLite stores the CREATE text verbatim, and
		// ALTER TABLE … DROP COLUMN re-parses it — a trailing “-- …” comment
		// makes that re-parse fail with “incomplete input”. The fixture needs
		// droppable tables, so it executes comment-free DDL.
		if err := c.execLocal(ctx, stripLineComments(ddl)); err != nil {
			t.Fatalf("v42 DDL: %v", err)
		}
	}
	// Remove everything newer than v42, so healing has real work to do.
	post42Tables := map[string]bool{}
	for _, ct := range createTableUnits {
		if ct.version > 42 {
			post42Tables[ct.table] = true
		}
	}
	for table := range post42Tables {
		if err := c.execLocal(ctx, `DROP TABLE `+table); err != nil {
			t.Fatalf("drop post-v42 table %s: %v", table, err)
		}
	}
	for i, sql := range schemaMigrations {
		if alterVersions[i] <= 42 {
			continue
		}
		table, col := parseAddColumn(sql)
		// Skip columns on tables that no longer exist in the fixture.
		if post42Tables[table] {
			continue
		}
		if err := c.execLocal(ctx, `ALTER TABLE `+table+` DROP COLUMN `+col); err != nil {
			t.Fatalf("drop post-v42 column %s.%s: %v", table, col, err)
		}
	}
	if err := c.execLocal(ctx,
		`INSERT OR REPLACE INTO schema_state (id, version, updated_at) VALUES (1, 42, datetime('now'))`); err != nil {
		t.Fatalf("stamp v42: %v", err)
	}
}

// TestInitSchema_MigratesV42ToV50 is the release upgrade path in one test: a DB
// at the last pre-consolidation upstream schema must come out of InitSchema at
// v50 with every intervening table and column present and the whole ledger
// recorded — and with pre-existing data intact.
func TestInitSchema_MigratesV42ToV50(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	buildV42DB(t, c)

	// Pre-existing v42-era data that must survive the migration untouched.
	if err := c.execLocal(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES ('h1', '10.0.0.1', 'root', '', 'active', datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed host: %v", err)
	}

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema v42→v50: %v", err)
	}

	if v := storedVersion(t, c); v != 50 {
		t.Fatalf("stored version after migration = %d, want 50", v)
	}
	// Every post-42 table healed, including the three v50 health tables.
	for _, table := range []string{
		"audit_signing_keys", "audit_chain_heads", "audit_key_lifecycle",
		"cluster_crl", "host_networks",
		"health_conditions", "health_evaluator_status", "host_capacity_observations",
	} {
		if ok, _ := tableExists(ctx, c, table); !ok {
			t.Errorf("table %s missing after v42→v50 migration", table)
		}
	}
	// Every post-42 column healed (spot-check one per version class).
	for _, tc := range []struct{ table, col string }{
		{"hosts", "capacity_policy_hash"},   // v44
		{"audit_log", "seq"},                // v45
		{"hosts", "isolation_epoch"},        // v49
		{"containers", "owner_epoch"},       // v44
	} {
		if ok, _ := columnExists(ctx, c.db, tc.table, tc.col); !ok {
			t.Errorf("column %s.%s missing after migration", tc.table, tc.col)
		}
	}
	if n := appliedCount(t, c); n != len(schemaMigrationLedger) {
		t.Errorf("applied_migrations rows=%d, want the full ledger %d", n, len(schemaMigrationLedger))
	}
	// The v42 data is still there.
	rows, err := c.Query(ctx, `SELECT name FROM hosts WHERE name = 'h1'`)
	if err != nil || len(rows) != 1 {
		t.Errorf("pre-migration host row lost: err=%v rows=%d", err, len(rows))
	}
	// And the healed DB is fully usable at v50: a health condition round-trips.
	if err := UpsertHealthCondition(ctx, c, seedCondition("post-migration")); err != nil {
		t.Errorf("health write on migrated DB: %v", err)
	}
}

// stripLineComments removes “-- …” line comments from a SQL statement.
func stripLineComments(sql string) string {
	var out []string
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
