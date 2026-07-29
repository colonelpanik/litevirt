// Fleet scenario: audit-log tamper-evidence across nodes (schema v45).
//
// The point of signing audit rows is that a host cannot be the sole judge of its
// own history. A hash chain is checkable by anyone, which sounds like the same
// thing but is not: the hash is unkeyed, so a host that edits its own rows can
// recompute the chain and every node — including its neighbours — agrees the log
// is fine. Signing moves the check from "can this be recomputed" to "was this
// written by the host that claims to have written it", and the only party who
// cannot fake that answer is the host itself.
//
// internal/corrosion/audit_sign_test.go covers detection within one database.
// What a single-package test structurally cannot reach, and what this file
// exercises, is the part that makes the guarantee worth anything:
//
//   - node A's certificate reaching B and C through real replication, because
//     verification on a peer is impossible without it
//   - B and C independently reaching the same verdict about A's log, using only
//     the cluster CA and what replicated to them
//   - A's tampered row NOT overwriting the copies B and C already hold, which is
//     the difference between "the cluster notices" and "the cluster is rewritten"
//
// The last one is the one that bit: audit_log has no updated_at, so anti-entropy
// skipped LWW entirely and upserted every incoming row unconditionally. One
// node's edited history would have propagated to the whole fleet.

package fleet

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// signNode gives a node the audit signing identity its own PKI dir already
// contains and publishes its certificate. This is exactly what the daemon does
// when enforcement.audit_signature is on — the signing key IS the host's
// cluster key, so nothing new has to be minted or distributed.
func signNode(t *testing.T, n *Node) *corrosion.AuditKeyring {
	t.Helper()
	kr, err := corrosion.LoadAuditKeyring(n.PKIDir, n.Name)
	if err != nil {
		t.Fatalf("LoadAuditKeyring(%s): %v", n.Name, err)
	}
	n.DB.SetAuditKeyring(kr)
	if err := kr.PublishSigningKey(context.Background(), n.DB); err != nil {
		t.Fatalf("PublishSigningKey(%s): %v", n.Name, err)
	}
	return kr
}

// verifyOn runs verification against one node's own replica.
func verifyOn(t *testing.T, n *Node) corrosion.AuditVerifyResult {
	t.Helper()
	res, err := corrosion.VerifyAuditChain(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("VerifyAuditChain on %s: %v", n.Name, err)
	}
	return res
}

func auditRow(t *testing.T, n *Node, id, action, target string) {
	t.Helper()
	if err := corrosion.InsertAuditLog(context.Background(), n.DB, corrosion.AuditRecord{
		ID: id, Username: "admin", HostName: n.Name,
		Action: action, Target: target, Result: "success",
	}); err != nil {
		t.Fatalf("InsertAuditLog %s on %s: %v", id, n.Name, err)
	}
}

// TestFleet_TamperedAuditRowIsCaughtByEveryPeer is the whole scenario.
func TestFleet_TamperedAuditRowIsCaughtByEveryPeer(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, cc := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")

	// All three sign. B and C need keyrings to VERIFY, not just to write: a
	// keyring carries the cluster CA, and without it a peer can only report
	// A's rows as unverifiable.
	signNode(t, a)
	signNode(t, b)
	signNode(t, cc)

	auditRow(t, a, "a1", "vm.create", "vm1")
	auditRow(t, a, "a2", "vm.start", "vm1")
	auditRow(t, a, "a3", "user.delete", "alice")

	// Replicate A's rows and, crucially, A's certificate.
	dump := pullDump(t, c, a)
	b.DB.MergeStateBytesLWW(dump)
	cc.DB.MergeStateBytesLWW(dump)

	for _, peer := range []*Node{b, cc} {
		if n := rowCount(t, peer, `SELECT count(*) AS n FROM audit_signing_keys WHERE host_name = ?`, a.Name); n != 1 {
			t.Fatalf("%s did not receive %s's signing certificate (%d rows); without it no peer "+
				"can check that host's chain at all", peer.Name, a.Name, n)
		}
		if res := verifyOn(t, peer); res.Tampered() {
			t.Fatalf("%s reports %s's replicated chain as tampered before any tampering: %+v",
				peer.Name, a.Name, res)
		} else if res.Unverifiable > 0 {
			t.Fatalf("%s could not verify %d replicated rows; the test would pass vacuously "+
				"because an unchecked row can never be reported as tampered", peer.Name, res.Unverifiable)
		}
	}

	// node-0 is compromised. Someone rewrites what an action recorded AND
	// recomputes the hash chain, which is free — HashAuditRow is unkeyed. That
	// alone used to be enough to pass verification everywhere.
	if err := a.DB.Execute(ctx,
		`UPDATE audit_log SET target = 'bob', detail = 'routine' WHERE id = 'a3'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rehashChainOnNode(t, a)
	if res := verifyOn(t, a); res.BrokenAt != "" {
		t.Fatalf("the forged chain does not link on %s (broke at %q); this scenario is meant "+
			"to start from an attack the hash chain cannot see", a.Name, res.BrokenAt)
	}

	// The compromised node also runs the repair path, which pre-v45 ran on
	// every daemon start and would have re-based the chain around the edit.
	if _, err := corrosion.ResealAuditChain(ctx, a.DB, a.Name); err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}

	// Every node — including the compromised one — must now report it.
	for _, n := range []*Node{a, b, cc} {
		res := verifyOn(t, n)
		if n == a {
			if !res.Tampered() {
				t.Errorf("%s (the compromised node) reports its own log clean after editing, "+
					"rehashing and resealing it: %+v", n.Name, res)
			}
			continue
		}
		// B and C have not yet re-synced, so they still hold the ORIGINAL row.
		// Their verdict at this point should be clean — that is the property
		// that makes them useful witnesses.
		if res.Tampered() {
			t.Errorf("%s reports tampering before the forged row reached it: %+v", n.Name, res)
		}
	}

	// Now the compromised node syncs to its peers. This is the propagation step.
	forged := pullDump(t, c, a)
	b.DB.MergeStateBytesLWW(forged)
	cc.DB.MergeStateBytesLWW(forged)

	for _, peer := range []*Node{b, cc} {
		if got := auditTarget(t, peer, "a3"); got != "alice" {
			t.Errorf("%s's copy of the audit row was overwritten by the compromised node "+
				"(target = %q, want alice)\nanti-entropy carried one node's edited history to "+
				"the fleet, and the original record no longer exists anywhere", peer.Name, got)
		}
		res := verifyOn(t, peer)
		if res.Tampered() {
			t.Errorf("%s reports tampering after refusing the forged row: %+v\n"+
				"keeping the good copy should leave this peer's own view clean", peer.Name, res)
		}
	}
}

// TestFleet_APeerRejectsARowSignedWithAKeyItCannotTrust.
//
// audit_signing_keys replicates, so an attacker who can write audit_log can
// usually publish a certificate too. Signing forged rows with a self-minted key
// and shipping the certificate alongside is the obvious next move, and it has to
// fail on every peer — otherwise a signature only proves that someone, somewhere,
// had a key.
func TestFleet_APeerRejectsARowSignedWithAKeyItCannotTrust(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Node("node-0"), c.Node("node-1")
	signNode(t, a)
	signNode(t, b)
	auditRow(t, a, "a1", "vm.create", "vm1")

	// A rogue CA and host cert for node-0, structurally identical to the real
	// pair but not signed by the cluster CA.
	rogueDir := filepath.Join(t.TempDir(), "rogue")
	mintRoguePKI(t, rogueDir, a.Name)
	rogue, err := corrosion.LoadAuditKeyring(rogueDir, a.Name)
	if err != nil {
		t.Fatalf("LoadAuditKeyring(rogue): %v", err)
	}
	if err := rogue.PublishSigningKey(ctx, a.DB); err != nil {
		t.Fatalf("publish rogue key: %v", err)
	}

	rec := corrosion.AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T12:00:00Z", Username: "root",
		HostName: a.Name, Action: "user.delete", Target: "alice", Result: "success", Seq: 99,
	}
	rec.ContentHash = corrosion.HashAuditRow(rec)
	sig, err := rogue.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow: %v", err)
	}
	if err := a.DB.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.ContentHash, rogue.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert forged row: %v", err)
	}

	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	res := verifyOn(t, b)
	if len(res.UnknownKeyID) == 0 {
		t.Fatalf("%s accepted a row signed with a certificate the cluster CA never issued: %+v\n"+
			"a published certificate is replicated data an attacker can write, so it is only "+
			"worth what the CA says about it", b.Name, res)
	}
	if !strings.Contains(strings.Join(res.UnknownKeyID, " "), "forged") {
		t.Errorf("findings %v do not name the forged row", res.UnknownKeyID)
	}
}

func auditTarget(t *testing.T, n *Node, id string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT target FROM audit_log WHERE id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s on %s: %v (rows=%d)", id, n.Name, err, len(rows))
	}
	return rows[0].String("target")
}

// rehashChainOnNode recomputes a node's whole audit chain from current row
// content — what resealHostChainLocked did for every row before v45, and what
// any attacker can do unaided because the hash takes no secret.
func rehashChainOnNode(t *testing.T, n *Node) {
	t.Helper()
	ctx := context.Background()
	rows, err := n.DB.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result
		 FROM audit_log WHERE host_name = ? ORDER BY timestamp ASC, id ASC`, n.Name)
	if err != nil {
		t.Fatalf("read chain on %s: %v", n.Name, err)
	}
	prev := ""
	for _, r := range rows {
		rec := corrosion.AuditRecord{
			ID: r.String("id"), Timestamp: r.String("timestamp"),
			Username: r.String("username"), HostName: r.String("host_name"),
			Action: r.String("action"), Target: r.String("target"),
			Detail: r.String("detail"), Result: r.String("result"),
			PrevHash: prev,
		}
		h := corrosion.HashAuditRow(rec)
		if err := n.DB.Execute(ctx,
			`UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = ?`, prev, h, rec.ID); err != nil {
			t.Fatalf("rehash %s: %v", rec.ID, err)
		}
		prev = h
	}
}

// mintRoguePKI builds a complete PKI directory under an attacker's OWN CA. The
// files are indistinguishable in form from a real node's — that is the point:
// what makes them untrustworthy is only that the cluster CA never signed them.
func mintRoguePKI(t *testing.T, dir, hostName string) {
	t.Helper()
	if err := mkdirAll(dir); err != nil {
		t.Fatalf("mkdir rogue pki: %v", err)
	}
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("rogue GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey,
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("rogue GenerateHostCert: %v", err)
	}
}
