package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
)

// newSchemaMigrateCmd fast-forwards a state.db to this binary's schema
// (CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN — idempotent). Run it on
// each node, while the OLD daemon is still up, to pre-stage schema ahead of a
// rolling upgrade across a large schema gap (e.g. rejoining a long-offline
// node) so the rolling restart never observes a missing-schema receiver.
// Folded in from the former standalone `litevirt-migrate` binary. (Named
// schema-migrate to avoid clashing with `litevirt migrate <vm> <host>`, which
// live-migrates a VM.)
func newSchemaMigrateCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "schema-migrate [--dry-run] <state.db>",
		Short: "Fast-forward a state.db to this binary's schema (pre-stage before a rolling upgrade)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if _, err := os.Stat(path); err != nil {
				return err
			}
			// WAL + busy timeout match the daemon's open so concurrent writes
			// from the live daemon don't lock us out.
			dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)", path)
			if dryRun {
				dsn += "&mode=ro"
			}
			db, err := sql.Open("sqlite", dsn)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()
			if err := db.Ping(); err != nil {
				return fmt.Errorf("ping db: %w", err)
			}

			if dryRun {
				report, err := corrosion.SchemaDryRun(cmd.Context(), db)
				if err != nil {
					return fmt.Errorf("dry-run: %w", err)
				}
				fmt.Println(report)
				return nil
			}

			client := corrosion.NewClientForMigration(db, "migrate-tool", hlc.NewClock("migrate-tool"))
			start := time.Now()
			slog.Info("running schema migration", "db", path)
			if err := corrosion.InitSchema(cmd.Context(), client); err != nil {
				return fmt.Errorf("InitSchema: %w", err)
			}
			slog.Info("schema migration complete",
				"db", path, "elapsed", time.Since(start), "version", corrosion.CurrentSchemaVersion)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"open read-only, print what migrations would run, exit without writing")
	return cmd
}
