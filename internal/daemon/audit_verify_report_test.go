package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// auditFinding is litevirt_audit_chain_findings{kind}, as last published.
func auditFinding(t *testing.T, kind string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "litevirt_audit_chain_findings" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "kind" && l.GetValue() == kind {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("no litevirt_audit_chain_findings{kind=%q}", kind)
	return 0
}

// Lab 1: every node's hourly check logged "evidence of tampering" for a chain
// `lv audit verify` classifies as a forked chain. The periodic verifier now
// names a fork a fork, in its log and its findings metric, and still says
// tampering for a real hash mismatch, or for a fork beside a deleted row.
//
// Mutations: Forked ignored (every finding logged as tampering) — red. A
// fork counted as broken_hash — red. A deletion beside a fork reported as a
// fork alone (Forked not checking the seq jumps) — red.
func TestReportAuditVerify_AForkIsReportedAsAForkedChain(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	fork := corrosion.AuditVerifyResult{
		RowsChecked: 6, BrokenAt: "fork-1", BrokenKind: corrosion.AuditBrokenForked,
		SeqGaps:       []string{"node-3: row fork-1 repeats seq 1 (duplicate: two rows claim the same position, a forked chain)"},
		SeqDuplicates: 1, ForkedHosts: []string{"node-3"},
	}
	edited := corrosion.AuditVerifyResult{RowsChecked: 6, BrokenAt: "r2", BrokenKind: corrosion.AuditBrokenContent, ContentBreaks: 1}
	forkAndDeletion := fork
	forkAndDeletion.SeqGaps = append([]string{"node-3: row r5 has seq 5 after 3"}, fork.SeqGaps...)
	// Review I-2: the first break is the fork on node-3; an edited row on
	// node-4 comes later in the walk.
	forkAndEdit := fork
	forkAndEdit.ContentBreaks = 1
	// Re-review I-3: a row deleted on the forked host inside the second
	// chain's seq range leaves an orphan and no seq jump.
	forkAndOrphan := fork
	forkAndOrphan.Orphaned = 1
	forkAndOrphan.Orphans = []string{"node-3: row r3 (seq 3) follows prev_hash abc, which is the hash of no row of node-3 at seq 2"}

	for _, tc := range []struct {
		name          string
		res           corrosion.AuditVerifyResult
		log, notLog   string
		forked, hash  float64
		gaps, repeats float64
	}{
		{"a fork", fork, "found a forked chain", "evidence of tampering", 1, 0, 0, 1},
		{"an edited row", edited, "evidence of tampering", "forked chain", 0, 1, 0, 0},
		{"a fork beside a deleted row", forkAndDeletion, "evidence of tampering", "found a forked chain", 1, 0, 1, 1},
		{"a fork on one host and an edit on another", forkAndEdit, "evidence of tampering", "found a forked chain", 1, 1, 0, 1},
		{"a fork hiding a deleted row", forkAndOrphan, "evidence of tampering", "found a forked chain", 1, 1, 0, 1},
	} {
		buf.Reset()
		reportAuditVerify("node-1", tc.res)
		out := buf.String()
		if !strings.Contains(out, tc.log) || strings.Contains(out, tc.notLog) {
			t.Errorf("%s: logged %q, want %q and not %q", tc.name, out, tc.log, tc.notLog)
		}
		// Re-review m-3: the hourly check names an orphaned row, not a count.
		for _, o := range tc.res.Orphans {
			if !strings.Contains(out, "row r3 (seq 3)") {
				t.Errorf("%s: logged %q, want the orphan %q named", tc.name, out, o)
			}
		}
		for kind, want := range map[string]float64{
			"forked_chain": tc.forked, "broken_hash": tc.hash, "seq_gap": tc.gaps, "seq_duplicate": tc.repeats,
		} {
			if got := auditFinding(t, kind); got != want {
				t.Errorf("%s: findings{kind=%q} = %v, want %v", tc.name, kind, got, want)
			}
		}
	}
}
