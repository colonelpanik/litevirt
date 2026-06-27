package corrosion

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
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

// MergeStateBytesLWW merges a full-state dump from a peer with HLC-aware
// last-writer-wins conflict resolution. It is the live anti-entropy merge path
// (AntiEntropy.checkPeer → fetchStateDump → here).
func (c *Client) MergeStateBytesLWW(buf []byte) {
	if len(buf) == 0 {
		return
	}
	payload, err := decompressPayload(buf)
	if err != nil {
		slog.Error("sync: decompress", "error", err)
		return
	}
	c.mergeStatePayloadLWW(payload)
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

// replicatedTableSet is tableNames as a set for O(1) allowlist checks during
// merge — table names in a peer's dump feed dynamic SQL and must be validated.
var replicatedTableSet = func() map[string]bool {
	m := make(map[string]bool, len(tableNames))
	for _, n := range tableNames {
		m[n] = true
	}
	return m
}()

// mergeStatePayloadLWW applies a decoded full-state dump with HLC-aware LWW.
// It is the single merge engine behind MergeStateBytesLWW.
//
// Per table it (1) validates the peer-supplied table name and columns against
// the local schema before building any dynamic SQL, (2) batch-prefetches the
// existing rows' updated_at keyed by primary key, and (3) keeps the local row
// when localWinsLWW says so, otherwise INSERT OR REPLACEs the incoming row.
func (c *Client) mergeStatePayloadLWW(payload *syncPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.Begin()
	if err != nil {
		slog.Error("sync: begin tx", "error", err)
		return
	}

	merged, skipped := 0, 0
	for _, table := range payload.Tables {
		// Defense-in-depth: table.Name and table.Columns come from a peer and
		// are interpolated into SQL. Only touch known tables/columns.
		if !replicatedTableSet[table.Name] {
			slog.Warn("sync: skipping unknown table in dump", "table", table.Name)
			continue
		}
		localCols, err := tableColumns(tx, table.Name)
		if err != nil {
			slog.Warn("sync: read local columns", "table", table.Name, "error", err)
			continue
		}
		if len(table.Columns) == 0 || !columnsKnown(table.Columns, localCols) {
			slog.Warn("sync: skipping dump table with unexpected columns", "table", table.Name)
			continue
		}

		pkCols := tablePrimaryKeys[table.Name]
		pkIdx := columnIndexes(table.Columns, pkCols)
		// A dump for a table with a known PK that omits a PK column can't be
		// LWW-merged (we couldn't identify the row); refuse it rather than blindly
		// inserting PK-less rows. Normal dumps always carry every column.
		if len(pkCols) > 0 && len(pkIdx) != len(pkCols) {
			slog.Warn("sync: skipping dump table missing primary-key column(s)", "table", table.Name)
			continue
		}
		updatedAtIdx := indexOf(table.Columns, "updated_at")

		// Batch-prefetch existing updated_at by PK so LWW needs no per-row SELECT.
		var existing map[string]string
		if updatedAtIdx >= 0 && len(pkCols) > 0 {
			existing = c.prefetchUpdatedAt(tx, table.Name, pkCols, table.Rows, pkIdx)
		}

		insertSQL := "INSERT OR REPLACE INTO " + table.Name +
			" (" + strings.Join(table.Columns, ", ") + ") VALUES (" +
			strings.Join(repeatPlaceholders(len(table.Columns)), ", ") + ")"

		for _, row := range table.Rows {
			if existing != nil {
				incomingTS, _ := row[updatedAtIdx].(string)
				if incomingTS != "" {
					if localTS, ok := existing[pkKeyAt(row, pkIdx)]; ok && localWinsLWW(localTS, incomingTS) {
						skipped++
						continue
					}
				}
			}
			if _, err := tx.Exec(insertSQL, row...); err != nil {
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

// mergePrefetchMaxParams caps bind variables per prefetch query, kept under
// SQLite's limit; per-tuple cost is len(pkCols). A var so tests can shrink it to
// force multi-chunk prefetches.
var mergePrefetchMaxParams = 900

// prefetchUpdatedAt batch-loads the existing updated_at for the dump's rows,
// keyed by canonical PK, using row-value IN queries chunked under SQLite's
// bind-variable limit (composite PKs spend len(pkCols) params per tuple).
func (c *Client) prefetchUpdatedAt(tx *sql.Tx, table string, pkCols []string, rows [][]interface{}, pkIdx []int) map[string]string {
	out := make(map[string]string)

	// Collect distinct PK tuples present in the dump.
	seen := make(map[string]bool)
	var keys []string
	var tuples [][]interface{}
	for _, row := range rows {
		vals := make([]interface{}, len(pkIdx))
		ok := true
		for i, idx := range pkIdx {
			if idx >= len(row) {
				ok = false
				break
			}
			vals[i] = row[idx]
		}
		if !ok {
			continue
		}
		k := pkKey(vals)
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
		tuples = append(tuples, vals)
	}
	if len(tuples) == 0 {
		return out
	}

	chunkSize := mergePrefetchMaxParams / len(pkCols)
	if chunkSize < 1 {
		chunkSize = 1
	}
	pkColList := "(" + strings.Join(pkCols, ", ") + ")"
	selectCols := strings.Join(pkCols, ", ") + ", updated_at"
	tuplePlaceholder := "(" + strings.Join(repeatPlaceholders(len(pkCols)), ", ") + ")"

	for start := 0; start < len(tuples); start += chunkSize {
		end := start + chunkSize
		if end > len(tuples) {
			end = len(tuples)
		}
		chunk := tuples[start:end]
		valueList := make([]string, len(chunk))
		args := make([]interface{}, 0, len(chunk)*len(pkCols))
		for i, vals := range chunk {
			valueList[i] = tuplePlaceholder
			args = append(args, vals...)
		}
		q := "SELECT " + selectCols + " FROM " + table +
			" WHERE " + pkColList + " IN (" + strings.Join(valueList, ", ") + ")"
		rs, err := tx.Query(q, args...)
		if err != nil {
			slog.Warn("sync: prefetch updated_at", "table", table, "error", err)
			continue
		}
		for rs.Next() {
			cells := make([]interface{}, len(pkCols)+1)
			ptrs := make([]interface{}, len(cells))
			for i := range cells {
				ptrs[i] = &cells[i]
			}
			if err := rs.Scan(ptrs...); err != nil {
				continue
			}
			out[pkKey(cells[:len(pkCols)])] = coerceString(cells[len(pkCols)])
		}
		rs.Close()
	}
	return out
}

// pkKey canonicalizes primary-key values into a collision-free string. Values
// are normalized ([]byte→string) into a []string and JSON-encoded, so a PK
// value containing any separator byte can't alias another key, and a []byte
// vs string representation of the same PK maps identically.
func pkKey(vals []interface{}) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = coerceString(v)
	}
	b, _ := json.Marshal(parts)
	return string(b)
}

// pkKeyAt builds a pkKey from the PK columns of a single dump row.
func pkKeyAt(row []interface{}, pkIdx []int) string {
	vals := make([]interface{}, len(pkIdx))
	for i, idx := range pkIdx {
		if idx < len(row) {
			vals[i] = row[idx]
		}
	}
	return pkKey(vals)
}

// coerceString normalizes a SQL/JSON scalar to a string. Replicated PKs are all
// TEXT, so this is exact for them; other types use a stable fmt fallback.
func coerceString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// tableColumns returns the set of column names of a local table via PRAGMA.
// The caller must have already validated tableName against the allowlist.
func tableColumns(tx *sql.Tx, tableName string) (map[string]bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + tableName + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notnull    int
			dfltValue  interface{}
			pk         int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// columnsKnown reports whether every incoming column exists in the local table.
func columnsKnown(incoming []string, local map[string]bool) bool {
	for _, col := range incoming {
		if !local[col] {
			return false
		}
	}
	return true
}

// indexOf returns the index of col in cols, or -1.
func indexOf(cols []string, col string) int {
	for i, c := range cols {
		if c == col {
			return i
		}
	}
	return -1
}

// columnIndexes maps each name in want to its index in cols, preserving the
// order of want. Returns nil if any name is missing.
func columnIndexes(cols, want []string) []int {
	idx := make([]int, 0, len(want))
	for _, w := range want {
		i := indexOf(cols, w)
		if i < 0 {
			return nil
		}
		idx = append(idx, i)
	}
	return idx
}

// repeatPlaceholders returns n "?" placeholders.
func repeatPlaceholders(n int) []string {
	ph := make([]string, n)
	for i := range ph {
		ph[i] = "?"
	}
	return ph
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
