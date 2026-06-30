package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Scanner gatherer support (Phase 0). Turns a node's rows — read locally, or
// parsed from a peer's gzipped state dump — into the engine's TableSnapshot
// (per-row metadata keyed by a composed PK label). The per-row meta computation
// is shared by the local and peer paths so both produce comparable hashes, and it
// lives here next to tablePrimaryKeys + encodeRowCells.

// pkSep separates PK column values in a composed PK label. 0x1f (unit separator)
// can't appear in a name/host/timestamp, so the label is unambiguous.
const pkSep = "\x1f"

// semanticTables are the non-sensitive tables the cluster-wide semantic-invariant
// checks read full content from (cross-host container names, duplicate IP owners).
var semanticTables = map[string]bool{
	"containers":           true,
	"ip_allocations":       true,
	"vm_interfaces":        true,
	"container_interfaces": true,
}

// colIndex maps column name → position for one table shape.
func colIndex(cols []string) map[string]int {
	m := make(map[string]int, len(cols))
	for i, c := range cols {
		m[c] = i
	}
	return m
}

func cellString(v interface{}) string {
	if v == nil {
		return ""
	}
	return coerceString(v)
}

// pkLabel composes the PK label for a row from the table's declared PK columns.
// Returns "" if the table has no known PK or a PK column is missing from cols.
func pkLabel(table string, idx map[string]int, vals []interface{}) string {
	pkCols := tablePrimaryKeys[table]
	if len(pkCols) == 0 {
		return ""
	}
	parts := make([]string, len(pkCols))
	for i, c := range pkCols {
		j, ok := idx[c]
		if !ok || j >= len(vals) {
			return ""
		}
		parts[i] = cellString(vals[j])
	}
	return strings.Join(parts, pkSep)
}

// rowMeta builds the operator-safe per-row metadata: a SHA-256 of the canonical
// row encoding plus the updated_at / deleted_at / state markers (read by name).
func rowMeta(idx map[string]int, vals []interface{}) RowMeta {
	sum := sha256.Sum256([]byte(encodeRowCells(vals)))
	m := RowMeta{RowHash: hex.EncodeToString(sum[:])}
	if j, ok := idx["updated_at"]; ok && j < len(vals) {
		m.UpdatedAt = cellString(vals[j])
	}
	if j, ok := idx["deleted_at"]; ok && j < len(vals) {
		m.Deleted = vals[j] != nil && cellString(vals[j]) != ""
	}
	if j, ok := idx["state"]; ok && j < len(vals) {
		m.State = cellString(vals[j])
	}
	return m
}

// tableSnapshotFromRows builds a TableSnapshot (and, for semantic tables, owned
// rows) from a table's columns + rows. labelKey wraps the PK label so the
// sensitive lane can substitute an HMAC; pass nil for the operator-safe identity.
func tableSnapshotFromRows(table string, cols []string, rows [][]interface{}) (TableSnapshot, []OwnedRow) {
	idx := colIndex(cols)
	ts := TableSnapshot{Columns: cols, Rows: make(map[string]RowMeta, len(rows))}
	var owned []OwnedRow
	for _, vals := range rows {
		if len(vals) != len(cols) {
			continue // malformed dump row
		}
		label := pkLabel(table, idx, vals)
		if label == "" {
			continue
		}
		ts.Rows[label] = rowMeta(idx, vals)
		if semanticTables[table] {
			if o, ok := ownedRow(table, idx, vals); ok {
				owned = append(owned, o)
			}
		}
	}
	return ts, owned
}

// ownedRow extracts the ownership fact a semantic invariant needs from one row.
// Tombstoned rows are skipped (only live rows can jointly violate an invariant).
func ownedRow(table string, idx map[string]int, vals []interface{}) (OwnedRow, bool) {
	if j, ok := idx["deleted_at"]; ok && j < len(vals) && vals[j] != nil && cellString(vals[j]) != "" {
		return OwnedRow{}, false // tombstoned
	}
	get := func(col string) string {
		if j, ok := idx[col]; ok && j < len(vals) {
			return cellString(vals[j])
		}
		return ""
	}
	switch table {
	case "containers":
		// For the duplicate-NAME check: group an unqualified name across hosts.
		return OwnedRow{Host: get("host_name"), Name: get("name")}, true
	case "ip_allocations":
		// owner_kind/owner_host (schema v36) disambiguate same-named owners across
		// kinds/hosts — vm_name is the legacy owner-NAME column for both. Two CTs
		// named "web" on different hosts must NOT collapse to one owner.
		return OwnedRow{Name: ipOwnerID(get("owner_kind"), get("owner_host"), get("vm_name")), IP: get("ip")}, true
	case "vm_interfaces":
		return OwnedRow{Name: "vm:" + get("vm_name"), IP: get("ip")}, true
	case "container_interfaces":
		return OwnedRow{Name: "ct:" + get("host_name") + ":" + get("ct_name"), IP: get("ip")}, true
	}
	return OwnedRow{}, false
}

// ipOwnerID composes a fully-qualified IP owner identity so distinct owners never
// alias: vm:<name> (VMs are cluster-unique by name) and ct:<host>:<name>
// (container names are per-host). Empty owner_kind defaults to vm (legacy rows).
func ipOwnerID(ownerKind, ownerHost, ownerName string) string {
	if ownerKind == "ct" {
		return "ct:" + ownerHost + ":" + ownerName
	}
	return "vm:" + ownerName
}

// ScanLocalTables reads this node's own rows for the given operator-safe tables
// and returns per-table snapshots plus the owned rows for semantic checks.
func (c *Client) ScanLocalTables(ctx context.Context, tables []string) (map[string]TableSnapshot, []OwnedRow, error) {
	out := make(map[string]TableSnapshot, len(tables))
	var owned []OwnedRow
	for _, table := range tables {
		rows, err := c.Query(ctx, "SELECT * FROM "+table)
		if err != nil {
			return nil, nil, fmt.Errorf("scan %s: %w", table, err)
		}
		if len(rows) == 0 {
			out[table] = TableSnapshot{Rows: map[string]RowMeta{}}
			continue
		}
		cols := rows[0].Columns
		vals := make([][]interface{}, len(rows))
		for i, r := range rows {
			vals[i] = r.Values
		}
		ts, o := tableSnapshotFromRows(table, cols, vals)
		out[table] = ts
		owned = append(owned, o...)
	}
	return out, owned, nil
}

// SnapshotFromDumpBytes parses a peer's gzipped operator-safe state dump into
// per-table snapshots + owned rows, restricted to the requested tables.
func SnapshotFromDumpBytes(buf []byte, want map[string]bool) (map[string]TableSnapshot, []OwnedRow, error) {
	payload, err := decompressPayload(buf)
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]TableSnapshot, len(payload.Tables))
	var owned []OwnedRow
	for _, t := range payload.Tables {
		if want != nil && !want[t.Name] {
			continue
		}
		ts, o := tableSnapshotFromRows(t.Name, t.Columns, t.Rows)
		out[t.Name] = ts
		owned = append(owned, o...)
	}
	return out, owned, nil
}

// SensitiveRow is one node's HMAC'd view of a sensitive row — the only thing the
// sensitive lane ever emits (never a raw PK or plaintext).
type SensitiveRow struct {
	Table     string
	PKLabel   string // HMAC(key, "pk\0"+table+"\0"+pk)
	RowHash   string // HMAC(key, "row\0"+table+"\0"+encoding)
	UpdatedAt string
	Deleted   bool
}

// ScanLocalSensitive reads this node's sensitive rows and returns ONLY keyed
// HMACs (domain-separated) — never raw PKs or row content. key is the per-scan
// HMAC secret shared across nodes over peer-mTLS.
func (c *Client) ScanLocalSensitive(ctx context.Context, key []byte, tables []string) ([]SensitiveRow, error) {
	var out []SensitiveRow
	for _, table := range tables {
		rows, err := c.Query(ctx, "SELECT * FROM "+table)
		if err != nil {
			return nil, fmt.Errorf("scan sensitive %s: %w", table, err)
		}
		for _, r := range rows {
			idx := colIndex(r.Columns)
			label := pkLabel(table, idx, r.Values)
			if label == "" {
				continue
			}
			m := rowMeta(idx, r.Values) // we reuse updated_at/deleted, discard the plain hash
			out = append(out, SensitiveRow{
				Table:     table,
				PKLabel:   ScanPKLabel(key, table, label),
				RowHash:   ScanRowHash(key, table, encodeRowCells(r.Values)),
				UpdatedAt: m.UpdatedAt,
				Deleted:   m.Deleted,
			})
		}
	}
	return out, nil
}

// SensitiveRowsToSnapshot folds a node's HMAC'd sensitive rows into TableSnapshots
// keyed by the HMAC PK label, so the same ClassifyTable engine compares them.
func SensitiveRowsToSnapshot(rows []SensitiveRow) map[string]TableSnapshot {
	out := map[string]TableSnapshot{}
	for _, r := range rows {
		ts, ok := out[r.Table]
		if !ok {
			ts = TableSnapshot{Rows: map[string]RowMeta{}}
		}
		ts.Rows[r.PKLabel] = RowMeta{UpdatedAt: r.UpdatedAt, RowHash: r.RowHash, Deleted: r.Deleted}
		out[r.Table] = ts
	}
	return out
}

// SensitiveTableNames exposes the sensitive-table allowlist to the scanner
// orchestrator (peer-mTLS lane).
func SensitiveTableNames() []string { return append([]string(nil), sensitiveTableNames...) }

// OperatorTableNames exposes the operator-safe replicated-table list.
func OperatorTableNames() []string { return append([]string(nil), tableNames...) }
