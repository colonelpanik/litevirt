// Fleet scenario: the evidence a peer holds is not the compromised node's to
// erase.
//
// internal/corrosion/audit_evidence_test.go covers each guard against one merge
// call. What only a multi-node test can show is the thing the guards exist for:
// a peer that has ALREADY seen the retirement and the chain heads, and is then
// handed a full state dump from the node those records incriminate.
//
// That dump is not a hypothetical. It is what anti-entropy exchanges on every
// cycle, it carries whole rows including deleted_at, and its clocks are written
// by the sender. So on a cluster where audit evidence merges by plain LWW, one
// node with database write access does not have to hide anything locally — it
// can have replication carry the erasure outward, and every neighbour's good
// copy goes with it. A peer that keeps reporting the finding AFTER absorbing
// that dump is the only demonstration that the record survives its author.

package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_PeerKeepsRetirementAfterAbsorbingTheCompromisedNodesDump.
//
// node-0 rotates, so its old key is retired at a boundary and node-1 learns it.
// The attacker — who kept the old key, which is why the rotation happened — then
// signs a new row with it and, in the same breath, clears the retirement marker
// on their own node with a far-future clock.
//
// Under plain LWW that clock decides, and the retirement disappears on every
// peer: the row signed by the leaked key stops being reported anywhere, and
// there is nothing left to show a rotation ever happened.
func TestFleet_PeerKeepsRetirementAfterAbsorbingTheCompromisedNodesDump(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	signNode(t, a)
	signNode(t, b)

	auditRow(t, a, "a1", "vm.create", "vm1")
	oldKR := a.DB.AuditKeyringOf()
	rotateNode(t, c, a)
	auditRow(t, a, "a2", "vm.start", "vm1")

	// The peer sees the rotation first — this is the state the attacker has to
	// undo, not merely avoid creating.
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))
	if n := rowCount(t, b,
		`SELECT count(*) AS n FROM audit_signing_keys WHERE key_id = ? AND retired_at IS NOT NULL`,
		oldKR.KeyID()); n != 1 {
		t.Fatalf("%s never saw the retirement, so the erasure below would prove nothing", b.Name)
	}

	forgeRowWithRetiredKey(t, a, oldKR, "forged", 3)

	// The erasure: retirement cleared, with a clock no honest write can beat.
	if err := a.DB.Execute(ctx,
		`UPDATE audit_signing_keys SET retired_at = NULL, retired_at_seq = 0, updated_at = ?
		 WHERE key_id = ?`, "2999-01-01T00:00:00Z", oldKR.KeyID()); err != nil {
		t.Fatalf("clear the retirement on %s: %v", a.Name, err)
	}

	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	if n := rowCount(t, b,
		`SELECT count(*) AS n FROM audit_signing_keys WHERE key_id = ? AND retired_at IS NOT NULL`,
		oldKR.KeyID()); n != 1 {
		t.Fatalf("%s dropped the retirement of key %s because %s said so with a newer clock\n"+
			"the sender writes that clock, so 'newest wins' means 'the compromised node wins'",
			b.Name, oldKR.KeyID(), a.Name)
	}
	res := verifyOn(t, b)
	if len(res.RetiredKeyUse) == 0 {
		t.Fatalf("%s stopped reporting a row signed by the rotated-out key: %+v", b.Name, res)
	}
	if !strings.Contains(strings.Join(res.RetiredKeyUse, " "), "forged") {
		t.Errorf("findings %v do not name the forged row", res.RetiredKeyUse)
	}
}

// TestFleet_PeerKeepsChainHeadsAfterAbsorbingTheCompromisedNodesDump.
//
// A hash chain links backward, so cutting rows off the end leaves every
// surviving link verifying — a signed chain head is the only thing that notices.
// Which makes deleting the heads, not the rows, the efficient attack: tombstone
// them on one node, let anti-entropy carry the tombstones outward, and the
// truncation becomes invisible cluster-wide.
func TestFleet_PeerKeepsChainHeadsAfterAbsorbingTheCompromisedNodesDump(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	signNode(t, a)
	signNode(t, b)

	for _, id := range []string{"a1", "a2", "a3", "a4"} {
		auditRow(t, a, id, "vm.start", "vm1")
	}
	if err := corrosion.PublishAuditChainHead(ctx, a.DB, a.Name); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))
	if n := rowCount(t, b,
		`SELECT count(*) AS n FROM audit_chain_heads WHERE host_name = ? AND deleted_at IS NULL`,
		a.Name); n == 0 {
		t.Fatalf("%s never received a head for %s; the erasure below would prove nothing",
			b.Name, a.Name)
	}

	// Cut the tail off, then delete the heads that would have noticed.
	if err := a.DB.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('a3','a4')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := a.DB.Execute(ctx,
		`UPDATE audit_chain_heads SET deleted_at = ?, updated_at = ? WHERE host_name = ?`,
		"2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z", a.Name); err != nil {
		t.Fatalf("tombstone the heads on %s: %v", a.Name, err)
	}

	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	if n := rowCount(t, b,
		`SELECT count(*) AS n FROM audit_chain_heads WHERE host_name = ? AND deleted_at IS NULL`,
		a.Name); n == 0 {
		t.Fatalf("%s's tombstones deleted every chain head for it on %s\n"+
			"truncation detection is gone cluster-wide, and a backward-linking hash chain "+
			"cannot see a missing tail on its own", a.Name, b.Name)
	}
}

// forgeRowWithRetiredKey appends a correctly chained, correctly signed row using
// a key that has been rotated out — the move a retirement boundary exists to
// catch.
func forgeRowWithRetiredKey(t *testing.T, n *Node, kr *corrosion.AuditKeyring, id string, seq int64) {
	t.Helper()
	ctx := context.Background()
	rows, err := n.DB.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ? ORDER BY timestamp DESC, id DESC LIMIT 1`,
		n.Name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s's tail: %v (rows=%d)", n.Name, err, len(rows))
	}
	rec := corrosion.AuditRecord{
		ID: id, Timestamp: "2026-07-30T12:00:00Z", Username: "root", HostName: n.Name,
		Action: "user.delete", Target: "alice", Result: "success",
		PrevHash: rows[0].String("content_hash"), Seq: seq,
	}
	rec.ContentHash = corrosion.HashAuditRow(rec)
	sig, err := kr.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow with the retired key: %v", err)
	}
	if err := n.DB.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, rec.ContentHash, kr.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert the forged row: %v", err)
	}
}
