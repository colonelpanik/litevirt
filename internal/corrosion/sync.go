package corrosion

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/litevirt/litevirt/internal/hlc"
)

// localWinsLWW decides whether the existing local row should be kept over an
// incoming one under last-writer-wins.
//
// Two HLC values compare lexically (their String() form is zero-padded, so
// lexical order == chronological). The hazard the plain `>=` missed is MIXED
// formats during the RFC3339→HLC migration: a leftover RFC3339 string
// ("2026-…") sorts lexically GREATER than any HLC value ("17…"), so a stale
// pre-migration row would wrongly win and suppress newer HLC writes. HLC values
// are newer by construction, so when only one side is HLC, the HLC side wins.
func localWinsLWW(localTS, incomingTS string) bool {
	localHLC, incomingHLC := hlc.IsHLC(localTS), hlc.IsHLC(incomingTS)
	switch {
	case localHLC && !incomingHLC:
		return true // local HLC beats a legacy RFC3339 incoming
	case !localHLC && incomingHLC:
		return false // incoming HLC beats a legacy RFC3339 local
	default:
		return localTS >= incomingTS // same format → lexical (==chronological for HLC)
	}
}

// syncPayload is the full-state dump sent to joining nodes.
type syncPayload struct {
	Tables []syncTable `json:"tables"`
}

type syncTable struct {
	Name    string          `json:"name"`
	Columns []string        `json:"cols"`
	Rows    [][]interface{} `json:"rows"`
}

// tableNames are the tables we replicate during full-state sync.
// Extracted from schemaDDL by parsing the CREATE TABLE statements.
var tableNames = []string{
	"cluster", "hosts", "host_labels", "host_health",
	"images", "image_hosts", "networks", "volumes", "stacks",
	"vms", "vm_interfaces", "vm_disks", "snapshots",
	"lb_configs", "lb_backends", "users", "tokens", "dns_records",
	"fencing_log", "audit_log",
	"network_vteps", "bgp_peers", "ip_allocations", "security_groups", "sg_rules",
	"containers",
}

// dumpState serializes all tables as gzipped JSON for push/pull sync.
func (c *Client) dumpState() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var payload syncPayload
	for _, table := range tableNames {
		st := syncTable{Name: table}

		rows, err := c.db.Query("SELECT * FROM " + table)
		if err != nil {
			// Table might not exist yet
			continue
		}

		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			continue
		}
		st.Columns = cols

		for rows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}
			// Convert []byte to string
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			st.Rows = append(st.Rows, vals)
		}
		rows.Close()

		if len(st.Rows) > 0 {
			payload.Tables = append(payload.Tables, st)
		}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("sync: marshal state", "error", err)
		return nil
	}

	// Gzip compress
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()

	slog.Info("sync: state dump", "tables", len(payload.Tables), "bytes", buf.Len())
	return buf.Bytes()
}

// DumpStateBytes is the public wrapper for dumpState, used by the gRPC sync RPC.
func (c *Client) DumpStateBytes() []byte {
	return c.dumpState()
}

// MergeStateBytes is the public wrapper for mergeState, used by the gRPC sync RPC.
func (c *Client) MergeStateBytes(buf []byte) {
	c.mergeState(buf)
}

// decompressPayload decompresses and unmarshals a gzipped sync payload.
func decompressPayload(buf []byte) (*syncPayload, error) {
	gz, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	data, err := io.ReadAll(gz)
	gz.Close()
	if err != nil {
		return nil, fmt.Errorf("read decompressed: %w", err)
	}
	var payload syncPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &payload, nil
}

// mergeState applies a full-state dump from a peer.
// Uses INSERT OR REPLACE so rows with newer updated_at win via LWW.
func (c *Client) mergeState(buf []byte) {
	if len(buf) == 0 {
		return
	}

	// Decompress
	gz, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		slog.Error("sync: decompress", "error", err)
		return
	}
	data, err := io.ReadAll(gz)
	gz.Close()
	if err != nil {
		slog.Error("sync: read decompressed", "error", err)
		return
	}

	var payload syncPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		slog.Error("sync: unmarshal state", "error", err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.Begin()
	if err != nil {
		slog.Error("sync: begin tx", "error", err)
		return
	}

	merged := 0
	skipped := 0
	for _, table := range payload.Tables {
		// Find updated_at column index and primary key column(s) for LWW comparison.
		updatedAtIdx := -1
		for i, col := range table.Columns {
			if col == "updated_at" {
				updatedAtIdx = i
				break
			}
		}

		// Identify primary key columns for this table so we can look up existing rows.
		pkCols := tablePrimaryKeys[table.Name]

		for _, row := range table.Rows {
			placeholders := make([]string, len(table.Columns))
			for i := range placeholders {
				placeholders[i] = "?"
			}

			// LWW: if the table has updated_at and we know the PK, only
			// replace when the incoming row is strictly newer.
			if updatedAtIdx >= 0 && len(pkCols) > 0 {
				incomingTS, _ := row[updatedAtIdx].(string)
				if incomingTS != "" {
					// Build WHERE clause from PK columns.
					var whereParts []string
					var whereArgs []interface{}
					for _, pk := range pkCols {
						for ci, col := range table.Columns {
							if col == pk {
								whereParts = append(whereParts, col+" = ?")
								whereArgs = append(whereArgs, row[ci])
								break
							}
						}
					}
					if len(whereParts) == len(pkCols) {
						var localTS *string
						_ = tx.QueryRow(
							"SELECT updated_at FROM "+table.Name+
								" WHERE "+strings.Join(whereParts, " AND "),
							whereArgs...,
						).Scan(&localTS)
						if localTS != nil && localWinsLWW(*localTS, incomingTS) {
							skipped++
							continue
						}
					}
				}
			}

			sql := "INSERT OR REPLACE INTO " + table.Name +
				" (" + strings.Join(table.Columns, ", ") + ") VALUES (" +
				strings.Join(placeholders, ", ") + ")"

			if _, err := tx.Exec(sql, row...); err != nil {
				slog.Warn("sync: merge row", "table", table.Name, "error", err)
			} else {
				merged++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("sync: commit", "error", err)
	}

	slog.Info("sync: merged remote state (LWW)", "tables", len(payload.Tables), "merged", merged, "skipped", skipped)
}

// TableDigest holds the row count and content hash for a single table.
type TableDigest struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Hash  string `json:"hash"` // truncated SHA-256 of sorted rowids
}

// StateDigest returns a lightweight fingerprint of each replicated table.
// Two nodes with identical digests are in sync; mismatched tables indicate drift.
func (c *Client) StateDigest(ctx context.Context) ([]TableDigest, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var digests []TableDigest
	for _, table := range tableNames {
		var count int
		err := c.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+table).Scan(&count)
		if err != nil {
			continue
		}

		// Deterministic hash of rowids for cheap comparison.
		var concat *string
		_ = c.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT GROUP_CONCAT(rowid, ',') FROM (SELECT rowid FROM %s ORDER BY rowid)", table)).Scan(&concat)

		h := sha256.New()
		if concat != nil {
			h.Write([]byte(*concat))
		}

		digests = append(digests, TableDigest{
			Name:  table,
			Count: count,
			Hash:  fmt.Sprintf("%x", h.Sum(nil))[:16],
		})
	}
	return digests, nil
}
