package corrosion

import (
	"sort"
	"testing"
)

// antiEntropyExcluded documents every CRDT-replicated table (one with an entry
// in tablePrimaryKeys) that is deliberately NOT in tableNames — i.e. not carried
// by the full-state dump / anti-entropy repair path. Two buckets:
//
//   - coordination / local / transient state that MUST NOT be full-state-merged
//     (merging it would corrupt leases, replication progress, etc.), and
//   - push-replicated config that anti-entropy does not YET cover — a known gap
//     (these have PKs and could be added to tableNames in a deliberate follow-up;
//     today they rely on the push replicator only and are not full-state-repaired).
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
	"recovery_codes":         "single-use 2FA secrets; push-replicated, excluded from the bulk dump",
	"user_2fa":               "2FA enrollment secrets; push-replicated, excluded from the bulk dump",

	// Push-replicated config NOT yet covered by anti-entropy (known gap;
	// deliberate candidates to add to tableNames later).
	"backup_schedules":     "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"host_pci_devices":     "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"notification_routes":  "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"notification_targets": "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"project_quotas":       "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"projects":             "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"registry_credentials": "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"resource_mappings":    "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"role_bindings":        "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"roles":                "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"service_endpoints":    "push-only; anti-entropy coverage gap (candidate for tableNames)",
	"storage_pools":        "push-only; anti-entropy coverage gap (candidate for tableNames)",
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
