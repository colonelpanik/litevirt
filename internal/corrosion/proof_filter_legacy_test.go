package corrosion

import (
	"encoding/json"
	"testing"
)

func marshalStmts(t *testing.T, stmts ...Statement) string {
	t.Helper()
	b, err := json.Marshal(stmts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestDropUnsupportedProofEntries_KeepsLegacyCRL (review 1, P1 regression): the v1.3.0 CRL statement
// intentionally fails the strict parser and is handled by a legacy transformer targeting crl_versions
// (NON custom-merge). It must NOT be dropped when forwarding to a peer without proof support —
// crl_versions is excluded from anti-entropy, so a dropped CRL update would be lost with no repair.
func TestDropUnsupportedProofEntries_KeepsLegacyCRL(t *testing.T) {
	crl := Statement{
		SQL:    `INSERT OR REPLACE INTO crl_versions (host, version, updated_at) VALUES (?, ?, datetime('now'))`,
		Params: []interface{}{"h", "1"},
	}
	other := Statement{
		SQL:    `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`,
		Params: []interface{}{"r", "3000000000000-0000-n1", "h"},
	}

	// CRL alone → kept.
	if got := dropUnsupportedProofEntries([]mutationEntry{{Seq: 1, Stmts: marshalStmts(t, crl)}}); len(got) != 1 {
		t.Fatal("a legacy CRL entry (crl_versions, non-custom-merge) must NOT be dropped for an unready peer")
	}
	// CRL co-batched with a normal mutation → still kept (neither is proof-bearing).
	if got := dropUnsupportedProofEntries([]mutationEntry{{Seq: 2, Stmts: marshalStmts(t, crl, other)}}); len(got) != 1 {
		t.Fatal("a CRL entry co-batched with a normal mutation must NOT be dropped")
	}
}

// TestDropUnsupportedProofEntries_DropsProofBearing (review 1): a proof-bearing entry — the legacy
// spent-proof-GC transformer (runtime_action_proofs, custom-merge) OR a normal runtime_action_proofs
// statement — must still be dropped for a peer that can't apply proofs (it reconverges via sensitive
// AE).
func TestDropUnsupportedProofEntries_DropsProofBearing(t *testing.T) {
	gc := Statement{
		SQL:    `UPDATE runtime_action_proofs SET deleted_at = ?, updated_at = ? WHERE deleted_at IS NULL AND status IN ('completed','failed') AND ` + tsMsSQL("updated_at") + ` < ?`,
		Params: []interface{}{"2026-01-01T00:00:00Z", "3000000000000-0000-n1", int64(1)},
	}
	if got := dropUnsupportedProofEntries([]mutationEntry{{Seq: 1, Stmts: marshalStmts(t, gc)}}); len(got) != 0 {
		t.Fatal("the legacy proof-GC transformer (runtime_action_proofs, custom-merge) must be dropped for an unready peer")
	}
	proof := Statement{SQL: `INSERT INTO runtime_action_proofs (id, status) VALUES (?, ?)`, Params: []interface{}{"p", "prepared"}}
	if got := dropUnsupportedProofEntries([]mutationEntry{{Seq: 2, Stmts: marshalStmts(t, proof)}}); len(got) != 0 {
		t.Fatal("a proof-bearing runtime_action_proofs statement must be dropped")
	}
	// And a proof co-batched with a normal mutation drops the WHOLE entry (never split).
	other := Statement{SQL: `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"r", "3000000000000-0000-n2", "h"}}
	if got := dropUnsupportedProofEntries([]mutationEntry{{Seq: 3, Stmts: marshalStmts(t, other, proof)}}); len(got) != 0 {
		t.Fatal("an entry co-batching a proof must be dropped whole")
	}
}
