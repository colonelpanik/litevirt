package corrosion

import (
	"testing"
)

// Anti-entropy must not let one node's copy of an audit row overwrite another's.
//
// audit_log has no updated_at column, so mergeChunk's whole LWW-and-tie block is
// skipped: `existing` is only prefetched when updatedAtIdx >= 0, and with no
// local timestamps to compare, every incoming row goes straight to the upsert.
// The capabilityMap entry for audit_log — content-default, tombstone then
// content-max — is therefore never consulted at all. The practical effect is
// that the LAST peer to sync wins unconditionally.
//
// For an append-only log that is the wrong outcome in every case. Two nodes only
// ever hold different content for the same row id if something is wrong, and the
// two possibilities are corruption and tampering. Overwriting the local copy
// destroys the good version of the record and, worse, spreads the bad one: a
// node that edits its own history has anti-entropy carry the edit to everyone.
//
// Signed rows must therefore be kept, not merged, and the divergence surfaced.

func auditSyncTable() syncTable {
	return syncTable{Name: "audit_log", Columns: []string{
		"id", "timestamp", "username", "host_name", "action", "target",
		"detail", "result", "prev_hash", "content_hash", "key_id", "signature", "seq",
	}}
}

func auditRowCells(id, host, target, contentHash, keyID, sig string, seq int64) []interface{} {
	return []interface{}{
		id, "2026-07-29T10:00:01Z", "alice", host, "vm.start", target,
		"", "ok", "", contentHash, keyID, sig, seq,
	}
}

// TestAuditMerge_PeerCannotOverwriteASignedRow is the propagation half of
// tamper-evidence. Detection on every node is worth much less if the tampered
// copy replaces the original everywhere — the log would still be flagged, but
// the record of what actually happened would be gone.
func TestAuditMerge_PeerCannotOverwriteASignedRow(t *testing.T) {
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	original := oneCol(t, c, `SELECT target FROM audit_log WHERE id = 'r1'`)
	if original != "x" {
		t.Fatalf("unexpected seeded target %q", original)
	}
	localHash := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`)
	localKey := oneCol(t, c, `SELECT key_id FROM audit_log WHERE id = 'r1'`)
	localSig := oneCol(t, c, `SELECT signature FROM audit_log WHERE id = 'r1'`)

	// A peer offers a DIFFERENT version of the same row id. Its content_hash is
	// internally consistent, which is all an attacker needs — the hash is
	// unkeyed. Only the signature can tell the two apart.
	table := auditSyncTable()
	incoming := auditRowCells("r1", "node-0", "tampered-vm", localHash+"ff", localKey, localSig, 1)

	merged, skipped, err := c.mergeChunk(
		table, [][]interface{}{incoming},
		buildMergeUpsertSQL(table.Name, table.Columns, []string{"id"}),
		[]string{"id"}, []int{0}, indexOf(table.Columns, "updated_at"),
	)
	if err != nil {
		t.Fatalf("mergeChunk: %v", err)
	}

	if got := oneCol(t, c, `SELECT target FROM audit_log WHERE id = 'r1'`); got != original {
		t.Fatalf("a peer's differing copy of a signed audit row overwrote the local one "+
			"(target %q -> %q, merged=%d skipped=%d)\n"+
			"anti-entropy would carry one node's edited history to every other node, "+
			"and the original record would no longer exist anywhere",
			original, got, merged, skipped)
	}
}

// TestAuditMerge_StillHealsUnsignedLegacyRows is the other side of the rule.
//
// Rows written before signing were never tamper-evident, and their hashes
// legitimately change when a node re-bases a legacy chain. Refusing to merge
// those would strand every pre-v45 row in permanent disagreement — protection
// that only produces noise gets switched off, so the rule is scoped to rows
// that actually carry a signature.
func TestAuditMerge_StillHealsUnsignedLegacyRows(t *testing.T) {
	c := newAuditTestClient(t) // no keyring: unsigned, like every pre-v45 row
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	table := auditSyncTable()
	incoming := auditRowCells("r1", "node-0", "resealed", "newhash", "", "", 0)

	if _, _, err := c.mergeChunk(
		table, [][]interface{}{incoming},
		buildMergeUpsertSQL(table.Name, table.Columns, []string{"id"}),
		[]string{"id"}, []int{0}, indexOf(table.Columns, "updated_at"),
	); err != nil {
		t.Fatalf("mergeChunk: %v", err)
	}

	if got := oneCol(t, c, `SELECT target FROM audit_log WHERE id = 'r1'`); got != "resealed" {
		t.Fatalf("an unsigned legacy row did not converge (target = %q); pre-v45 rows would "+
			"stay divergent across the cluster forever", got)
	}
}
