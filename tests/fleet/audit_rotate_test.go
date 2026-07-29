// Fleet scenario: audit signing key rotation across nodes.
//
// Rotation is worth nothing if it only convinces the node that performed it.
// The retired certificate, the retirement marker and the sealing chain head all
// have to reach the peers, because peers are the parties whose agreement makes
// a host's log credible in the first place.
//
// internal/corrosion/audit_rotate_test.go covers the mechanism in one database.
// What only a multi-node test can show is that a peer, holding nothing but the
// cluster CA and whatever replicated to it, reaches the same verdict as the
// node that rotated — and keeps being able to verify the history the old key
// signed, which is the property that breaks if retirement is ever implemented
// as a delete.

package fleet

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// rotateNode installs a fresh dedicated audit signing pair for a node — what
// `lv host rotate-audit-key` does on disk — and lets the node adopt it, exactly
// as the daemon does on its next start.
func rotateNode(t *testing.T, c *Cluster, n *Node) *corrosion.AuditKeyring {
	t.Helper()
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(n.PKIDir, "ca.crt"), filepath.Join(n.PKIDir, "ca.key"),
		filepath.Join(n.PKIDir, pki.AuditSigningCertName),
		filepath.Join(n.PKIDir, pki.AuditSigningKeyName),
		n.Name); err != nil {
		t.Fatalf("mint audit signing cert for %s: %v", n.Name, err)
	}
	kr, err := corrosion.LoadAuditKeyring(n.PKIDir, n.Name)
	if err != nil {
		t.Fatalf("LoadAuditKeyring after rotation on %s: %v", n.Name, err)
	}
	n.DB.SetAuditKeyring(kr)
	if _, err := corrosion.AdoptAuditKey(context.Background(), n.DB, kr, n.Name); err != nil {
		t.Fatalf("AdoptAuditKey on %s: %v", n.Name, err)
	}
	return kr
}

// TestFleet_RotationIsVisibleAndEnforcedOnPeers.
func TestFleet_RotationIsVisibleAndEnforcedOnPeers(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	a, b, cc := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	for _, n := range []*Node{a, b, cc} {
		signNode(t, n)
	}

	auditRow(t, a, "a1", "vm.create", "vm1")
	auditRow(t, a, "a2", "user.delete", "alice")
	oldKey, _, err := corrosion.ActiveAuditKeyID(context.Background(), a.DB, a.DB.AuditKeyringOf(), a.Name)
	if err != nil || oldKey == "" {
		t.Fatalf("no active key for %s before rotation: %v", a.Name, err)
	}

	newKR := rotateNode(t, c, a)
	if newKR.KeyID() == oldKey {
		t.Fatal("rotation produced the same key id; every assertion below would pass vacuously")
	}
	auditRow(t, a, "a3", "vm.start", "vm1")

	dump := pullDump(t, c, a)
	b.DB.MergeStateBytesLWW(dump)
	cc.DB.MergeStateBytesLWW(dump)

	for _, peer := range []*Node{b, cc} {
		// BOTH certificates must be present on the peer. Dropping the retired
		// one would make every row it signed unverifiable, so a rotation
		// performed to improve integrity would read as mass tampering.
		for _, keyID := range []string{oldKey, newKR.KeyID()} {
			if n := rowCount(t, peer, `SELECT count(*) AS n FROM audit_signing_keys WHERE key_id = ?`, keyID); n != 1 {
				t.Fatalf("%s is missing the certificate for key %s (%d rows)", peer.Name, keyID, n)
			}
		}
		if n := rowCount(t, peer,
			`SELECT count(*) AS n FROM audit_key_retirements WHERE retired_key_id = ?`, oldKey); n != 1 {
			t.Errorf("%s does not see key %s as retired; it would accept new rows signed with it",
				peer.Name, oldKey)
		}
		// The peer verifies the whole log — rows from before AND after the
		// rotation — using only the cluster CA and what replicated to it.
		res := verifyOn(t, peer)
		if res.Tampered() {
			t.Fatalf("%s reports a cleanly-rotated log as tampered: %+v", peer.Name, res)
		}
		if res.Unverifiable > 0 || res.Unsigned > 0 {
			t.Errorf("%s: unsigned=%d unverifiable=%d, want 0/0 — some rows went unchecked and "+
				"the verdict above is weaker than it looks", peer.Name, res.Unsigned, res.Unverifiable)
		}
	}
}

// TestFleet_PeersRejectTheRetiredKeyAfterRotation.
//
// The attacker kept a copy of the old key — which is the reason to rotate — and
// uses it to append to the log on the node they compromised. Every peer has to
// reach that conclusion independently, from replicated state alone.
func TestFleet_PeersRejectTheRetiredKeyAfterRotation(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	signNode(t, a)
	signNode(t, b)

	auditRow(t, a, "a1", "vm.create", "vm1")
	oldKR := a.DB.AuditKeyringOf()
	rotateNode(t, c, a)
	auditRow(t, a, "a2", "vm.start", "vm1")

	// Forge a row with the retired key, correctly chained and correctly signed.
	prev := oneString(t, a, `SELECT content_hash FROM audit_log WHERE id = 'a2'`)
	rec := corrosion.AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T12:00:00Z", Username: "root", HostName: a.Name,
		Action: "user.delete", Target: "alice", Result: "success", PrevHash: prev, Seq: 3,
	}
	rec.ContentHash = corrosion.HashAuditRow(rec)
	sig, err := oldKR.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow with the retired key: %v", err)
	}
	if err := a.DB.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, rec.ContentHash, oldKR.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert forged row: %v", err)
	}

	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	res := verifyOn(t, b)
	if len(res.RetiredKeyUse) == 0 {
		t.Fatalf("%s accepted a row signed with a key retired on %s: %+v\n"+
			"the peer has the retirement marker and the certificate; nothing else is needed "+
			"to reject it", b.Name, a.Name, res)
	}
	if !strings.Contains(strings.Join(res.RetiredKeyUse, " "), "forged") {
		t.Errorf("findings %v do not name the forged row", res.RetiredKeyUse)
	}
}

func oneString(t *testing.T, n *Node, query string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), query)
	if err != nil || len(rows) != 1 {
		t.Fatalf("query %q on %s: %v (rows=%d)", query, n.Name, err, len(rows))
	}
	for _, col := range []string{"content_hash", "key_id", "target"} {
		if v := rows[0].String(col); v != "" {
			return v
		}
	}
	return ""
}

// TestFleet_PeerCatchesARewriteSealedByTheRotationHead is the case a retirement
// boundary cannot reach, checked from a peer rather than in one process.
//
// The attacker holds only the retired key. They rewrite a row that key was
// entitled to sign, re-sign it correctly, and pick the LAST row so nothing links
// forward to contradict them. Every ordinary check passes: the chain links, the
// signature verifies against a published certificate, the sequence numbers are
// untouched, and the key was within its boundary.
//
// The only thing left is the chain head published at rotation, which records the
// hash the chain had at that sequence and is signed by the successor key the
// attacker does not have. Isolating this on the live lab is not practical —
// anti-entropy keeps repairing the tampered node from its peers, which is
// correct behaviour but removes the evidence mid-test.
func TestFleet_PeerCatchesARewriteSealedByTheRotationHead(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	signNode(t, a)
	signNode(t, b)

	auditRow(t, a, "a1", "vm.create", "vm1")
	auditRow(t, a, "a2", "user.delete", "alice")
	oldKR := a.DB.AuditKeyringOf()

	rotateNode(t, c, a) // publishes a head over a1+a2, signed with the NEW key

	// Rewrite the tail row and re-sign it with the retired key — a complete,
	// internally consistent forgery.
	if err := a.DB.Execute(ctx,
		`UPDATE audit_log SET target = 'bob', username = 'system' WHERE id = 'a2'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rows, err := a.DB.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, seq
		 FROM audit_log WHERE id = 'a2'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read a2: %v (rows=%d)", err, len(rows))
	}
	r := rows[0]
	rec := corrosion.AuditRecord{
		ID: r.String("id"), Timestamp: r.String("timestamp"), Username: r.String("username"),
		HostName: r.String("host_name"), Action: r.String("action"), Target: r.String("target"),
		Detail: r.String("detail"), Result: r.String("result"),
		PrevHash: r.String("prev_hash"), Seq: r.Int64("seq"),
	}
	rec.ContentHash = corrosion.HashAuditRow(rec)
	sig, err := oldKR.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow with the retired key: %v", err)
	}
	if err := a.DB.Execute(ctx,
		`UPDATE audit_log SET content_hash = ?, signature = ?, key_id = ? WHERE id = 'a2'`,
		rec.ContentHash, sig, oldKR.KeyID()); err != nil {
		t.Fatalf("re-sign a2: %v", err)
	}

	// Sanity: the forgery really does defeat every other check, or this test
	// would be proving something easier than it claims.
	onA := verifyOn(t, a)
	if onA.BrokenAt != "" {
		t.Fatalf("the forged chain does not link (broke at %q); the point is a rewrite that "+
			"only the head can see", onA.BrokenAt)
	}
	if len(onA.BadSignature) > 0 || len(onA.RetiredKeyUse) > 0 {
		t.Fatalf("the forgery was caught by an easier check (bad_sig=%v retired=%v); it is "+
			"supposed to be signature-valid and inside the retired key's boundary",
			onA.BadSignature, onA.RetiredKeyUse)
	}
	if len(onA.HeadMismatch) == 0 {
		t.Fatalf("the node itself did not catch the rewrite: %+v", onA)
	}

	// And the peer reaches the same conclusion from replicated state alone.
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))
	onB := verifyOn(t, b)
	if len(onB.HeadMismatch) == 0 {
		t.Fatalf("%s did not catch a rewrite sealed by %s's rotation head: %+v\n"+
			"the head is the only remaining witness once the signature verifies and the "+
			"sequence numbers are intact", b.Name, a.Name, onB)
	}
	if !strings.Contains(strings.Join(onB.HeadMismatch, " "), a.Name) {
		t.Errorf("findings %v do not name the affected host", onB.HeadMismatch)
	}
}
