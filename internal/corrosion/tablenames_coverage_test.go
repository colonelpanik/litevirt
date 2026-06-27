package corrosion

import (
	"sort"
	"testing"
)

// antiEntropyExcluded documents every CRDT-replicated table (one with an entry
// in tablePrimaryKeys) that is deliberately NOT in tableNames — i.e. not carried
// by the full-state dump / anti-entropy repair path:
//
//   - coordination / local / transient state that MUST NOT be full-state-merged
//     (merging it would corrupt leases, replication progress, etc.), and
//   - a couple of secret stores excluded from the bulk dump (one lacks updated_at
//     so it isn't LWW-safe; both still replicate via push).
//
// TestTableNamesCoverage forces every replicated table into exactly one bucket
// (tableNames or here) so coverage can't silently drift and tests can't overstate
// what anti-entropy actually repairs.
var antiEntropyExcluded = map[string]string{
	// Coordination / local / transient — must not be full-state-merged.
	"clock_skew":             "per-node clock observations, GC'd locally",
	"crl_versions":           "per-host CRL version tracking (gossiped)",
	"leader_election":        "distributed lease — merging would corrupt leadership",
	"mutation_log":           "the replication WAL itself — never full-state-synced",
	"replication_watermarks": "per-node replication progress",
	"vm_locks":               "per-VM lease — full-state merge would risk split-brain",
	"vm_restarts":            "per-node restart bookkeeping",
	"rebalance_proposals":    "transient, leader-gated proposals",
	"sessions":               "ephemeral auth sessions",
	"vm_events":              "high-volume append-only event log; best-effort, not full-state-repaired",
	"recovery_codes":         "single-use 2FA secrets (no updated_at → not LWW-safe); push-replicated, excluded from the bulk dump",
	"user_2fa":               "2FA enrollment secrets; push-replicated, excluded from the bulk dump",
}

// TestTableNamesCoverage asserts every CRDT-replicated table is explicitly
// categorized: either in tableNames (full-state/anti-entropy covered) or in
// antiEntropyExcluded (with a documented reason). A new replicated table forces
// a decision rather than silently going uncovered.
func TestTableNamesCoverage(t *testing.T) {
	inTableNames := make(map[string]bool, len(tableNames))
	for _, n := range tableNames {
		inTableNames[n] = true
	}

	var uncategorized []string
	for tbl := range tablePrimaryKeys {
		_, excluded := antiEntropyExcluded[tbl]
		switch {
		case inTableNames[tbl] && excluded:
			t.Errorf("table %q is in BOTH tableNames and antiEntropyExcluded — pick one", tbl)
		case !inTableNames[tbl] && !excluded:
			uncategorized = append(uncategorized, tbl)
		}
	}
	if len(uncategorized) > 0 {
		sort.Strings(uncategorized)
		t.Errorf("replicated tables neither in tableNames nor documented as excluded: %v\n"+
			"add each to tableNames (anti-entropy full-state coverage) or to antiEntropyExcluded with a reason",
			uncategorized)
	}

	// No stale exclusions: every excluded name must still be a real replicated table.
	for tbl := range antiEntropyExcluded {
		if _, ok := tablePrimaryKeys[tbl]; !ok {
			t.Errorf("antiEntropyExcluded names %q which is not in tablePrimaryKeys (stale entry?)", tbl)
		}
	}

	// Reverse: any table that is dumped/merged (in tableNames) and has an
	// updated_at column MUST have a tablePrimaryKeys entry. Without one,
	// mergeStatePayloadLWW and the replicator apply path see pkCols == nil and
	// fall back to blind INSERT OR REPLACE — so an older full-state dump or a
	// stale mutation can overwrite a newer local row (no LWW).
	c := mustTestClient(t)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	for _, tbl := range tableNames {
		cols, err := tableColumns(tx, tbl)
		if err != nil {
			t.Fatalf("tableColumns(%s): %v", tbl, err)
		}
		if cols["updated_at"] {
			if _, ok := tablePrimaryKeys[tbl]; !ok {
				t.Errorf("table %q is in tableNames with an updated_at column but has no "+
					"tablePrimaryKeys entry — LWW is silently skipped (older write can clobber newer)", tbl)
			}
		}
	}
}
