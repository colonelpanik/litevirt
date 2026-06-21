package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestMigrateTool_KeepsParityWithSchema is a guardrail against schema
// drift: any addition to schemaDDL or schemaMigrations must be in a
// form the SchemaDryRun parser can recognize. If you add a new DDL
// idiom (DROP TABLE, RENAME COLUMN, multi-statement, etc.) and this
// test starts failing, EITHER extend the parser OR find another way
// to express the migration — silent dry-run misreporting means
// litevirt-migrate would tell operators "schema is current" while
// silently skipping the new change, defeating the rolling-upgrade
// safety guarantee that motivated the tool.
func TestMigrateTool_KeepsParityWithSchema(t *testing.T) {
	for i, ddl := range schemaDDL {
		if name := tableNameFromCreate(ddl); name == "" {
			// Allow non-CREATE-TABLE DDL (currently none) — but if
			// schemaDDL grows views or pragmas, the dry-run report
			// will be silently incomplete. Force a conscious choice.
			if strings.Contains(ddl, "CREATE TABLE") {
				t.Errorf("schemaDDL[%d]: looks like a CREATE TABLE but parser can't extract a name:\n%s", i, ddl)
			}
		}
	}
	for i, alter := range schemaMigrations {
		table, col := parseAddColumn(alter)
		if table == "" || col == "" {
			t.Errorf("schemaMigrations[%d]: parser couldn't extract (table, column) — extend parseAddColumn or change the migration form:\n%s", i, alter)
		}
	}
}

// TestSchemaDryRun_CurrentSchemaReportsCurrent confirms the round-trip
// works on a freshly-initialized DB: after InitSchema, the dry-run
// must report "schema is current". If this breaks, parseAddColumn or
// tableNameFromCreate misclassified something — operators would see
// spurious "Tables to create" entries that would no-op in practice.
func TestSchemaDryRun_CurrentSchemaReportsCurrent(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	report, err := SchemaDryRun(context.Background(), c.db)
	if err != nil {
		t.Fatalf("SchemaDryRun: %v", err)
	}
	if !strings.Contains(report, "schema is current") {
		t.Errorf("dry-run against a freshly-initialised DB should report 'schema is current', got:\n%s", report)
	}
}

// TestSchemaDryRun_FindsMissingTableAndColumn reproduces the
// production-upgrade scenario in miniature: a DB with one missing
// table and one missing column. The dry-run must list both so
// litevirt-migrate's output matches what the daemon's InitSchema
// would actually do.
func TestSchemaDryRun_FindsMissingTableAndColumn(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Drop one of the new tables to simulate an old-DB upgrade. Pick
	// service_endpoints because it has no FK pressure on other rows.
	if err := c.Execute(context.Background(), "DROP TABLE service_endpoints"); err != nil {
		t.Fatalf("DROP TABLE: %v", err)
	}
	// Drop a column. SQLite supports DROP COLUMN since 3.35; modernc
	// ships a recent enough version.
	if err := c.Execute(context.Background(), "ALTER TABLE hosts DROP COLUMN region"); err != nil {
		t.Fatalf("DROP COLUMN: %v", err)
	}

	report, err := SchemaDryRun(context.Background(), c.db)
	if err != nil {
		t.Fatalf("SchemaDryRun: %v", err)
	}
	if !strings.Contains(report, "service_endpoints") {
		t.Errorf("dry-run should list missing table service_endpoints, got:\n%s", report)
	}
	if !strings.Contains(report, "hosts.region") {
		t.Errorf("dry-run should list missing column hosts.region, got:\n%s", report)
	}
}

// TestParseAddColumn_HappyPath pins the exact forms the parser supports
// so future ALTER syntax changes get caught.
func TestParseAddColumn_HappyPath(t *testing.T) {
	cases := []struct {
		in    string
		table string
		col   string
	}{
		{`ALTER TABLE hosts ADD COLUMN region TEXT NOT NULL DEFAULT 'default'`, "hosts", "region"},
		{`ALTER TABLE vm_interfaces ADD COLUMN security_groups TEXT`, "vm_interfaces", "security_groups"},
		{`  ALTER TABLE host_pci_devices ADD COLUMN pcie_root_port TEXT`, "host_pci_devices", "pcie_root_port"},
	}
	for _, tc := range cases {
		gotT, gotC := parseAddColumn(tc.in)
		if gotT != tc.table || gotC != tc.col {
			t.Errorf("parseAddColumn(%q) = (%q, %q), want (%q, %q)", tc.in, gotT, gotC, tc.table, tc.col)
		}
	}
}

// TestTableNameFromCreate_HappyPath pins the CREATE TABLE parser.
func TestTableNameFromCreate_HappyPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`CREATE TABLE IF NOT EXISTS hosts (name TEXT PRIMARY KEY, ...)`, "hosts"},
		{`CREATE TABLE IF NOT EXISTS backup_schedules (vm_name TEXT NOT NULL, ...)`, "backup_schedules"},
		{`CREATE TABLE IF NOT EXISTS service_endpoints (
		service_name TEXT NOT NULL,
		ip           TEXT NOT NULL)`, "service_endpoints"},
		// Non-CREATE-TABLE DDL must return empty so callers can skip it.
		{`CREATE INDEX idx_x ON hosts(name)`, ""},
		{`-- comment`, ""},
	}
	for _, tc := range cases {
		got := tableNameFromCreate(tc.in)
		if got != tc.want {
			t.Errorf("tableNameFromCreate(...) = %q, want %q", got, tc.want)
		}
	}
}

// Compile-time guard: ensure NewClientForMigration returns a *Client
// whose db field is usable by InitSchema. Just a constructor-shape
// smoke test, not a behaviour check.
func TestNewClientForMigration_Shape(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	c2 := NewClientForMigration(c.db, "migrate-tool", c.clock)
	if c2 == nil || c2.db == nil {
		t.Fatal("NewClientForMigration returned an unusable Client")
	}
	if err := InitSchema(context.Background(), c2); err != nil {
		t.Fatalf("InitSchema via migration-tool client: %v", err)
	}
}

// columnExists is a private helper; lock its contract with a tiny test
// so future refactors don't change semantics silently.
func TestColumnExists(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	// Go straight to the underlying *sql.DB: c.Execute() writes a
	// replication mutation_log row on every statement, which the
	// no-init test client doesn't have a table for.
	if _, err := c.db.ExecContext(context.Background(),
		"CREATE TABLE t (a TEXT, b INTEGER)"); err != nil {
		t.Fatalf("CREATE: %v", err)
	}
	for _, tc := range []struct {
		col  string
		want bool
	}{{"a", true}, {"b", true}, {"missing", false}} {
		got, err := columnExists(context.Background(), c.db, "t", tc.col)
		if err != nil {
			t.Fatalf("columnExists(%q): %v", tc.col, err)
		}
		if got != tc.want {
			t.Errorf("columnExists(%q) = %v, want %v", tc.col, got, tc.want)
		}
	}
}

// Compile guard: we shadow database/sql in this file via the corrosion
// package's *sql.DB usage. The blank import below keeps go.mod tidy.
var _ = sql.ErrNoRows
