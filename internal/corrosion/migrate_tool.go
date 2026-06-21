package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/hlc"
)

// NewClientForMigration wraps an already-opened *sql.DB into a minimal
// Client suitable for calling InitSchema. The wrapper deliberately
// leaves the gossip layer / replicator / HLC defaults — they're not
// touched by InitSchema and the migration tool doesn't replicate.
//
// This is exported for `cmd/litevirt-migrate`, not for daemon code.
// Production daemons use NewClient.
func NewClientForMigration(db *sql.DB, hostName string, clock *hlc.Clock) *Client {
	return &Client{
		db:               db,
		hostName:         hostName,
		clock:            clock,
		replicatorNotify: make(chan struct{}, 1),
	}
}

// SchemaDryRun reports which CREATE / ALTER statements InitSchema
// would issue against db (which must be opened read-only by the
// caller for safety). It introspects sqlite_master / PRAGMA
// table_info — it never writes.
//
// Output is a human-readable multi-line string, one entry per
// missing table / column. Exit status of the caller tool maps
// directly: empty output (or "schema is current") = nothing to do.
func SchemaDryRun(ctx context.Context, db *sql.DB) (string, error) {
	var missingTables []string
	var missingCols []string

	// 1) CREATE TABLE IF NOT EXISTS — flag any table from schemaDDL
	//    not currently present.
	existing := map[string]bool{}
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type IN ('table','view')`)
	if err != nil {
		return "", fmt.Errorf("read sqlite_master: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return "", err
		}
		existing[n] = true
	}

	for _, ddl := range schemaDDL {
		name := tableNameFromCreate(ddl)
		if name == "" {
			continue // not a CREATE TABLE we recognize
		}
		if !existing[name] {
			missingTables = append(missingTables, name)
		}
	}

	// 2) ALTER TABLE ADD COLUMN — for each migration, parse out
	//    target table + new column and check PRAGMA table_info.
	for _, alter := range schemaMigrations {
		table, col := parseAddColumn(alter)
		if table == "" || col == "" {
			continue
		}
		if !existing[table] {
			// Whole table is missing; covered by [1]. Don't double-list.
			continue
		}
		has, err := columnExists(ctx, db, table, col)
		if err != nil {
			return "", fmt.Errorf("PRAGMA table_info(%s): %w", table, err)
		}
		if !has {
			missingCols = append(missingCols, fmt.Sprintf("%s.%s", table, col))
		}
	}

	if len(missingTables) == 0 && len(missingCols) == 0 {
		return "schema is current (no migrations would run)", nil
	}
	var b strings.Builder
	if len(missingTables) > 0 {
		b.WriteString("Tables to create:\n")
		for _, t := range missingTables {
			fmt.Fprintf(&b, "  + %s\n", t)
		}
	}
	if len(missingCols) > 0 {
		b.WriteString("Columns to add:\n")
		for _, c := range missingCols {
			fmt.Fprintf(&b, "  + %s\n", c)
		}
	}
	return b.String(), nil
}

func columnExists(ctx context.Context, db *sql.DB, table, col string) (bool, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, nil
}

// tableNameFromCreate extracts the table name from a `CREATE TABLE IF
// NOT EXISTS <name> (...)` statement. Returns "" for anything else.
func tableNameFromCreate(ddl string) string {
	trimmed := strings.TrimSpace(ddl)
	prefix := "CREATE TABLE IF NOT EXISTS "
	if !strings.HasPrefix(trimmed, prefix) {
		return ""
	}
	rest := trimmed[len(prefix):]
	// Stop at first whitespace, '(' or '"'.
	end := strings.IndexAny(rest, " \t\n(")
	if end < 0 {
		return ""
	}
	return strings.Trim(rest[:end], `"`)
}

// parseAddColumn extracts (table, column) from `ALTER TABLE <t> ADD
// COLUMN <c>...`. Returns "" / "" for non-ADD-COLUMN ALTERs.
func parseAddColumn(alter string) (string, string) {
	trimmed := strings.TrimSpace(alter)
	prefix := "ALTER TABLE "
	if !strings.HasPrefix(trimmed, prefix) {
		return "", ""
	}
	rest := trimmed[len(prefix):]
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		return "", ""
	}
	table := strings.Trim(rest[:end], `"`)
	rest = strings.TrimSpace(rest[end:])
	addCol := "ADD COLUMN "
	if !strings.HasPrefix(rest, addCol) {
		return "", ""
	}
	rest = rest[len(addCol):]
	end = strings.IndexAny(rest, " \t")
	if end < 0 {
		return "", ""
	}
	return table, strings.Trim(rest[:end], `"`)
}
