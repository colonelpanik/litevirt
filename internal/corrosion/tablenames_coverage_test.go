package corrosion

import (
	"regexp"
	"testing"
)

// antiEntropyExcluded documents every CREATE-TABLE in schemaDDL that is
// deliberately NOT in tableNames or sensitiveTableNames — i.e. not carried by
// either anti-entropy repair path:
//
//   - coordination / local / transient state that MUST NOT be full-state-merged
//     (leases, replication progress, per-node bookkeeping, schema version), and
//   - secret stores that are not yet safe for the peer-only sensitive
//     anti-entropy lane, and therefore still rely on push replication.
//
// TestTableNamesCoverage forces every schemaDDL table into exactly one bucket
// (tableNames, sensitiveTableNames, or here) so coverage can't silently drift
// and tests can't overstate what anti-entropy actually repairs.
var antiEntropyExcluded = map[string]string{
	// Coordination / local / transient — must not be full-state-merged.
	"clock_skew":             "per-node clock observations, GC'd locally",
	"crl_versions":           "per-host CRL version tracking (gossiped)",
	"schema_state":           "per-node schema version — must stay local for rolling upgrades (not CRDT-replicated)",
	"leader_election":        "distributed lease — merging would corrupt leadership",
	"vm_locks":               "per-VM lease — full-state merge would risk split-brain",
	"rebalance_proposals":    "transient, leader-gated proposals",
	"vm_restarts":            "per-node restart bookkeeping",
	"container_restarts":     "per-node restart bookkeeping (container analogue of vm_restarts)",
	"vm_events":              "high-volume append-only event log; best-effort, not full-state-repaired",
	"sessions":               "ephemeral auth sessions",
	"mutation_log":           "the replication WAL itself — never full-state-synced",
	"replication_watermarks": "per-node replication progress",
	"mutation_seen":          "per-node relay-dedup table",
	"host_runtime_usage":     "per-host runtime telemetry (disk_iops/net_mbps); replicates via the WAL/mutation_log but is excluded from full-state anti-entropy — stale telemetry self-corrects on the next sample (cf. vm_events), so it needn't be repaired and shouldn't bloat the digest/dump",
	"idempotency_keys":       "ephemeral request-dedup records (v39); LOCAL-only (owned by the entry node, never replicated), so no anti-entropy repair applies — see localOnly",
	// (user_2fa, recovery_codes, recovery_code_sets are now in sensitiveTableNames
	//  — schema v32 made them LWW-repairable: soft-delete + active-set pointer.)
}

// localOnly are schemaDDL tables that are NOT CRDT-replicated (written via direct
// DB access, not the replicating Execute path). The updated_at→primary-key
// invariant below doesn't apply to them.
var localOnly = map[string]bool{
	"schema_state":     true, // per-node schema version, set during InitSchema/migrate
	"idempotency_keys": true, // v39: entry-node-owned request dedup; execLocal writes, never replicated
}

var createTableRe = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS ([a-z_0-9]+)`)

func schemaDDLTables() []string {
	var out []string
	for _, stmt := range schemaDDL {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// TestTableNamesCoverage is anchored on the schema (schemaDDL), not on
// tablePrimaryKeys — a replicated table missing from tablePrimaryKeys would
// otherwise be invisible. Every schemaDDL table must be explicitly categorized,
// and every replicated table with updated_at must have a primary key so LWW
// applies (both in the anti-entropy merge and the Crescent apply path).
func TestTableNamesCoverage(t *testing.T) {
	tables := schemaDDLTables()
	if len(tables) < 50 {
		t.Fatalf("parsed only %d schemaDDL tables — regex likely broke", len(tables))
	}
	schemaSet := make(map[string]bool, len(tables))
	for _, n := range tables {
		schemaSet[n] = true
	}
	inTableNames := make(map[string]bool, len(tableNames))
	for _, n := range tableNames {
		inTableNames[n] = true
	}
	inSensitiveNames := make(map[string]bool, len(sensitiveTableNames))
	for _, n := range sensitiveTableNames {
		inSensitiveNames[n] = true
	}

	c := mustTestClient(t)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	for _, tbl := range tables {
		_, excluded := antiEntropyExcluded[tbl]
		switch {
		case inTableNames[tbl] && inSensitiveNames[tbl]:
			t.Errorf("table %q is in BOTH tableNames and sensitiveTableNames — public dumps must stay redacted", tbl)
		case (inTableNames[tbl] || inSensitiveNames[tbl]) && excluded:
			t.Errorf("table %q is repaired and antiEntropyExcluded — pick one", tbl)
		case !inTableNames[tbl] && !inSensitiveNames[tbl] && !excluded:
			t.Errorf("schemaDDL table %q is neither in tableNames nor antiEntropyExcluded — "+
				"add it to tableNames/sensitiveTableNames (anti-entropy coverage) or to antiEntropyExcluded with a reason", tbl)
		}

		// Replicated table with updated_at MUST have a primary key, else LWW is
		// silently skipped and an older write/dump can clobber a newer row.
		if localOnly[tbl] {
			continue
		}
		cols, err := tableColumns(tx, tbl)
		if err != nil {
			t.Fatalf("tableColumns(%s): %v", tbl, err)
		}
		if cols["updated_at"] {
			if _, ok := tablePrimaryKeys[tbl]; !ok {
				t.Errorf("table %q has updated_at but no tablePrimaryKeys entry — LWW is silently "+
					"skipped (older write/dump can clobber newer)", tbl)
			}
		}

		// A full-state table that soft-deletes (has deleted_at) MUST also have
		// updated_at: a tombstone needs a timestamp to win LWW, otherwise a stale
		// live row from a peer blind-replaces (resurrects) it via INSERT OR REPLACE
		// — e.g. an un-revoked token.
		if inTableNames[tbl] && cols["deleted_at"] && !cols["updated_at"] {
			t.Errorf("table %q is full-state synced with deleted_at but no updated_at — "+
				"a tombstone can't win LWW, so a stale live row resurrects it", tbl)
		}
		if inSensitiveNames[tbl] {
			if _, ok := tablePrimaryKeys[tbl]; !ok {
				t.Errorf("sensitive table %q has no tablePrimaryKeys entry — sensitive merge would blind-replace rows", tbl)
			}
			if !cols["updated_at"] {
				t.Errorf("sensitive table %q has no updated_at — sensitive merge cannot arbitrate LWW", tbl)
			}
			if !cols["deleted_at"] {
				t.Errorf("sensitive table %q has no deleted_at — delete/revoke tombstones cannot be repaired", tbl)
			}
		}
	}

	// No phantom entries: every name in our maps/lists must be a real schemaDDL table.
	for _, n := range tableNames {
		if !schemaSet[n] {
			t.Errorf("tableNames contains %q which is not a schemaDDL table", n)
		}
	}
	for _, n := range sensitiveTableNames {
		if !schemaSet[n] {
			t.Errorf("sensitiveTableNames contains %q which is not a schemaDDL table", n)
		}
	}
	for n := range antiEntropyExcluded {
		if !schemaSet[n] {
			t.Errorf("antiEntropyExcluded names %q which is not a schemaDDL table (stale?)", n)
		}
	}
	for n := range tablePrimaryKeys {
		if !schemaSet[n] {
			t.Errorf("tablePrimaryKeys names %q which is not a schemaDDL table (stale?)", n)
		}
	}
	for n := range localOnly {
		if !schemaSet[n] {
			t.Errorf("localOnly names %q which is not a schemaDDL table (stale?)", n)
		}
	}
}
