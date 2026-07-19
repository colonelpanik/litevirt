package corrosion

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Gap 3 — release-corpus ledger completeness.
//
// The compatibility ledger claims to cover every statement shape a SUPPORTED prior release
// emits in-flight during a rolling upgrade + the WAL-retention horizon. The CI guard
// (scripts/ci/stmtshapecheck) only proves the CURRENT tree's builders are registered; nothing
// otherwise proves the ledger actually covers an OLD binary's shapes. If our enumeration of a
// prior release's writes (stmthistorical.go) is incomplete, an upgraded receiver would
// back-pressure a valid historical statement and stall that peer's stream.
//
// This test replays an INDEPENDENTLY-HARVESTED corpus of the shapes v1.3.0 emits and asserts
// every one resolves in the ledger (generated ∪ historical) with a stable fingerprint. The
// static corpus in testdata/release_corpus/v1.3.0.json is harvested from the real v1.3.0
// source tree (not from our own historical families), so it is a non-circular cross-check.
//
// Regenerate the fixture when a release enters/leaves the supported horizon:
//
//	git worktree add /tmp/vX v1.3.0
//	go run ./scripts/ci/stmtshapecheck -root /tmp/vX -report \
//	  | awk -F'\t' '$2 ~ /^stmtshape\/v1:/{print}' \
//	  | <dedup-by-fingerprint to JSON {fingerprint,sql}>  # see testdata/release_corpus/README

type corpusShape struct {
	Fingerprint string `json:"fingerprint"`
	SQL         string `json:"sql"`
}

func loadReleaseCorpus(t *testing.T, release string) []corpusShape {
	t.Helper()
	path := fmt.Sprintf("testdata/release_corpus/%s.json", release)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus %s: %v", path, err)
	}
	var shapes []corpusShape
	if err := json.Unmarshal(b, &shapes); err != nil {
		t.Fatalf("decode corpus %s: %v", path, err)
	}
	return shapes
}

// TestReleaseCorpus_V130_LedgerCovers proves every static replicated statement shape v1.3.0
// emits (a) fingerprints identically under the current code and (b) resolves in the ledger.
func TestReleaseCorpus_V130_LedgerCovers(t *testing.T) {
	shapes := loadReleaseCorpus(t, "v1.3.0")
	// Guard against a truncated/empty fixture silently passing.
	if len(shapes) < 200 {
		t.Fatalf("v1.3.0 corpus has only %d shapes; expected the full static set (~211) — fixture truncated?", len(shapes))
	}
	var uncovered, drifted []string
	for _, s := range shapes {
		fp, err := FingerprintSQL(s.SQL)
		if err != nil {
			t.Errorf("v1.3.0 shape no longer parses: %v\n  sql: %s", err, s.SQL)
			continue
		}
		if fp != s.Fingerprint {
			drifted = append(drifted, fmt.Sprintf("%s: recorded %s got %s", firstLine(s.SQL), s.Fingerprint, fp))
		}
		if _, ok := LedgerLookup(fp); !ok {
			uncovered = append(uncovered, fmt.Sprintf("%s  (%s)", firstLine(s.SQL), fp))
		}
	}
	if len(drifted) > 0 {
		t.Errorf("fingerprint drift vs the recorded v1.3.0 corpus (%d) — a canonicalization change must become stmtshape/v2, and the corpus must be regenerated:\n%s",
			len(drifted), strings.Join(drifted, "\n"))
	}
	if len(uncovered) > 0 {
		t.Errorf("v1.3.0 shapes NOT in the ledger (%d) — an upgraded receiver would back-pressure a valid historical statement and stall the peer stream; add the shape to stmthistorical.go and regenerate:\n%s",
			len(uncovered), strings.Join(uncovered, "\n"))
	}
}

// TestReleaseCorpus_V130_DynamicBuildersCovered accounts for the handful of v1.3.0 replicated
// writers the static scanner can't enumerate (they build SQL dynamically) or the strict parser
// rejects (a receiver-evaluated expression). Each is enumerated to its concrete v1.3.0 shape(s)
// here and asserted covered, so the corpus is complete w.r.t. every v1.3.0 replicated write —
// not just the statically-harvestable ones.
func TestReleaseCorpus_V130_DynamicBuildersCovered(t *testing.T) {
	// (1) UpdateObservedActuals (vmspec.go) — an UPDATE vms whose WHERE grows optional CAS
	// conjuncts. All four concrete shapes must resolve.
	vmsBase := "UPDATE vms SET cpu_actual = ?, mem_actual = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL"
	for _, tail := range []string{"", " AND vm_owner_epoch = ?", " AND spec_generation = ?", " AND vm_owner_epoch = ? AND spec_generation = ?"} {
		mustResolve(t, "vmspec UpdateObservedActuals", vmsBase+tail)
	}

	// (2) DeleteStackFirewall (firewall.go) — one bulk tombstone per firewall table.
	for _, tbl := range []string{"ip_sets", "cluster_firewall_rules", "host_firewall_rules", "firewall_defaults"} {
		mustResolve(t, "firewall stack teardown",
			fmt.Sprintf("UPDATE %s SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL", tbl))
	}

	// (3) ConfigureHost (grpcapi/host.go) — UPDATE hosts SET <non-empty subset of these 7 fields,
	// in this order>, updated_at = ? WHERE name = ?. The field list is copied from the v1.3.0
	// source, so this doubles as a check that our historical family matches what v1.3.0 emits.
	fields := []string{"fence_strategy", "ipmi_address", "ipmi_user", "ipmi_pass", "watchdog_dev", "role", "region"}
	for mask := 1; mask < (1 << len(fields)); mask++ {
		var sets []string
		for i, f := range fields {
			if mask&(1<<i) != 0 {
				sets = append(sets, f+" = ?")
			}
		}
		sets = append(sets, "updated_at = ?")
		mustResolve(t, "ConfigureHost",
			"UPDATE hosts SET "+strings.Join(sets, ", ")+" WHERE name = ?")
	}

	// (4) The two shapes the strict parser rejects because they carry a receiver-evaluated
	// expression or a non-per-statement semantic — each is authorized by an exact legacy
	// transformer, not the ledger. Assert the transformer still matches.
	// Built verbatim as v1.3.0's source emits them (the gc reap uses the tsMsSQL age helper),
	// so a change to either builder OR to the transformer's match key trips this.
	legacy := map[string]string{
		"crl_versions datetime('now')":  "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, datetime('now'))",
		"gc runtime_action_proofs reap": "UPDATE runtime_action_proofs\n\t\t    SET deleted_at = ?, updated_at = ?\n\t\t  WHERE deleted_at IS NULL\n\t\t    AND status IN ('completed','failed')\n\t\t    AND " + tsMsSQL("updated_at") + " < ?",
	}
	for name, sql := range legacy {
		if _, ok := legacyTransformerFor(sql); !ok {
			t.Errorf("v1.3.0 legacy shape %q no longer matches any legacy transformer — an upgraded receiver would back-pressure it:\n  %s", name, sql)
		}
	}
}

func mustResolve(t *testing.T, builder, sql string) {
	t.Helper()
	fp, err := FingerprintSQL(sql)
	if err != nil {
		t.Errorf("%s: v1.3.0 shape no longer parses: %v\n  sql: %s", builder, err, sql)
		return
	}
	if _, ok := LedgerLookup(fp); !ok {
		t.Errorf("%s: v1.3.0 shape not in the ledger (%s):\n  %s", builder, fp, sql)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i]) + " …"
	}
	return s
}
