package corrosion

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// testPKI mints a cluster CA and a host certificate for hostName, returning the
// pki directory. It uses the real internal/pki generators, so the certificates
// are exactly the ones a node gets from `lv host init`.
func testPKI(t *testing.T, hostName string) string {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey,
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		hostName, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}
	return dir
}

// signedClient is a client whose audit rows are signed by hostName's key, with
// the verification certificate already published.
func signedClient(t *testing.T, hostName string) (*Client, *AuditKeyring, string) {
	t.Helper()
	dir := testPKI(t, hostName)
	c := newAuditTestClient(t)
	kr, err := LoadAuditKeyring(dir, hostName)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if err := kr.PublishSigningKey(context.Background(), c); err != nil {
		t.Fatalf("PublishSigningKey: %v", err)
	}
	return c, kr, dir
}

func verify(t *testing.T, c *Client) AuditVerifyResult {
	t.Helper()
	res, err := VerifyAuditChain(context.Background(), c)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	return res
}

// TestAuditSigning_RoundTrips is the baseline, and exists mostly to keep the
// tests below from passing vacuously: if signing were silently a no-op, every
// "tampering is detected" test would still pass for the wrong reason (the
// unkeyed hash check alone would catch a naive edit) while the signature
// carried no weight at all.
func TestAuditSigning_RoundTrips(t *testing.T) {
	c, _, _ := signedClient(t, "node-0")

	for i, action := range []string{"vm.create", "vm.start", "vm.stop"} {
		ins(t, c, "row-"+string(rune('a'+i)), "node-0", "")
		_ = action
	}

	rows, err := c.Query(context.Background(),
		`SELECT key_id, signature, seq FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	for i, r := range rows {
		if r.String("signature") == "" || r.String("key_id") == "" {
			t.Fatalf("row %d is unsigned; every test below would pass vacuously", i)
		}
		if got, want := r.Int64("seq"), int64(i+1); got != want {
			t.Errorf("row %d has seq %d, want %d", i, got, want)
		}
	}

	res := verify(t, c)
	if res.Tampered() {
		t.Fatalf("a freshly written signed chain reports tampering: %+v", res)
	}
	if res.Unsigned != 0 || res.Unverifiable != 0 {
		t.Errorf("unsigned=%d unverifiable=%d, want 0/0 — the signatures are not being checked",
			res.Unsigned, res.Unverifiable)
	}
	if res.RowsChecked != 3 {
		t.Errorf("checked %d rows, want 3", res.RowsChecked)
	}
}

// TestAuditSigning_TamperSurvivesTheResealPath is THE test.
//
// It reproduces the actual attack the old design allowed: someone with write
// access to the database edits an audit row, then lets the daemon's reseal run.
// Before v45 the reseal recomputed every hash from the edited content, so the
// chain verified clean afterwards and the edit was permanently invisible —
// and the reseal ran unconditionally at every daemon start, so the attacker
// only had to wait for a restart.
//
// The attacker here has database write access but NOT the host's private key,
// which is the whole point of the change: the reseal cannot regenerate a
// signature, and it is not allowed to touch a signed row in the first place.
func TestAuditSigning_TamperSurvivesTheResealPath(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")

	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	ins(t, c, "r3", "node-0", "2026-07-29T10:00:03Z")
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("clean chain reported tampering before the attack: %+v", res)
	}

	// The attack: rewrite what an action recorded, and — this is the part that
	// defeats an unkeyed chain entirely — recompute the hashes so the chain
	// still links. HashAuditRow is exported, deterministic and takes no secret,
	// so this costs the attacker nothing. Pre-v45 the daemon's own reseal did
	// it for them at the next restart.
	if err := c.Execute(ctx,
		`UPDATE audit_log SET target = 'some-other-vm', detail = 'authorized' WHERE id = 'r2'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rehashHostChain(t, c, "node-0")

	// Confirm the attacker succeeded against the OLD defence: the hash chain
	// now links perfectly. Without this the test could pass on the hash check
	// alone and say nothing about signing.
	if res := verify(t, c); res.BrokenAt != "" {
		t.Fatalf("the forged chain does not link (broke at %q); this test is meant to "+
			"start from an attack the unkeyed hash chain cannot see", res.BrokenAt)
	}

	// The attacker also runs the repair path, which is what used to launder it.
	if _, err := ResealAuditChain(ctx, c, "node-0"); err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("after tampering, rehashing and resealing, verify reports a clean log: %+v\n"+
			"this is the pre-v45 behaviour — an attacker with DB write access rewrites "+
			"history and passes verification", res)
	}
	if len(res.BadSignature) == 0 {
		t.Errorf("tampering was detected as %+v but not as a bad signature; with the chain "+
			"rehashed, the signature is the only thing left that can catch it", res)
	}
	if !strings.Contains(strings.Join(res.BadSignature, " "), "r2") {
		t.Errorf("bad signatures %v do not name the edited row r2", res.BadSignature)
	}
}

// rehashHostChain recomputes a host's whole prev_hash/content_hash chain from
// current row content — exactly what resealHostChainLocked did for every row
// before v45, and what any attacker can do unaided because the hash is unkeyed.
// It deliberately bypasses the signed-row guard, since the attacker is writing
// SQL directly rather than calling into the daemon.
func rehashHostChain(t *testing.T, c *Client, hostName string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result
		 FROM audit_log WHERE host_name = ? ORDER BY timestamp ASC, id ASC`, hostName)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	prev := ""
	for _, r := range rows {
		rec := AuditRecord{
			ID: r.String("id"), Timestamp: r.String("timestamp"),
			Username: r.String("username"), HostName: r.String("host_name"),
			Action: r.String("action"), Target: r.String("target"),
			Detail: r.String("detail"), Result: r.String("result"),
			PrevHash: prev,
		}
		h := HashAuditRow(rec)
		if err := c.Execute(ctx,
			`UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = ?`, prev, h, rec.ID); err != nil {
			t.Fatalf("rehash %s: %v", rec.ID, err)
		}
		prev = h
	}
}

// TestReseal_RefusesToRewriteASignedRow pins the mechanism the test above
// depends on. A reseal that "helpfully" recomputed a signed row's hash would
// destroy the mismatch that proves an edit happened — the evidence and the
// damage look identical from inside the reseal.
func TestReseal_RefusesToRewriteASignedRow(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	before := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`)
	if err := c.Execute(ctx, `UPDATE audit_log SET detail = 'tampered' WHERE id = 'r1'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	n, err := ResealAuditChain(ctx, c, "node-0")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 0 {
		t.Errorf("reseal rewrote %d signed row(s); it must never touch one", n)
	}
	if after := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`); after != before {
		t.Errorf("a signed row's content_hash was rewritten (%s -> %s); the evidence of the "+
			"edit has been erased", before, after)
	}
}

// TestAuditSigning_RejectsARowSignedForAnotherHost.
//
// Cross-node verification is the reason the scheme is asymmetric, and it only
// works if a key can speak for exactly one host. Without the CN check, a single
// compromised node could sign rows attributed to any host in the cluster and
// every peer would accept them — the log would say a different machine did it.
func TestAuditSigning_RejectsARowSignedForAnotherHost(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")

	// A well-formed row that claims to come from node-1, signed with node-0's key.
	rec := AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T10:00:01Z", Username: "root",
		HostName: "node-1", Action: "user.delete", Target: "alice", Result: "ok", Seq: 1,
	}
	rec.ContentHash = HashAuditRow(rec)
	sig, err := kr.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.ContentHash, kr.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert forged row: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a row attributed to node-1 but signed by node-0's key verified clean: %+v", res)
	}
	joined := strings.Join(append(res.BadSignature, res.UnknownKeyID...), " ")
	if !strings.Contains(joined, "forged") {
		t.Errorf("findings %v do not name the forged row", joined)
	}
}

// TestAuditSigning_RejectsASelfMintedCertificate.
//
// audit_signing_keys is replicated, so an attacker who can write audit_log can
// usually write it too. The obvious move is to sign forged rows with a key they
// generated themselves and publish the matching certificate alongside. That has
// to fail, or the signature proves only that someone had *a* key.
func TestAuditSigning_RejectsASelfMintedCertificate(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// The attacker's own CA and host cert for node-0 — structurally identical
	// to the real ones, but not signed by the cluster CA.
	rogue := testPKI(t, "node-0")
	rogueKR, err := LoadAuditKeyring(rogue, "node-0")
	if err != nil {
		t.Fatalf("LoadAuditKeyring(rogue): %v", err)
	}
	if err := rogueKR.PublishSigningKey(ctx, c); err != nil {
		t.Fatalf("publish rogue key: %v", err)
	}

	rec := AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T10:00:02Z", Username: "root",
		HostName: "node-0", Action: "user.delete", Target: "alice", Result: "ok", Seq: 2,
	}
	rec.ContentHash = HashAuditRow(rec)
	sig, err := rogueKR.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.ContentHash, rogueKR.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert forged row: %v", err)
	}

	res := verify(t, c)
	if len(res.UnknownKeyID) == 0 {
		t.Fatalf("a certificate the attacker minted themselves was accepted: %+v\n"+
			"the published certificate must chain to the cluster CA or the signature "+
			"proves nothing about who wrote the row", res)
	}
}

// TestAuditVerify_BlankingAHashDoesNotLaunderTheChain.
//
// The verifier treats a row with no content hash as predating the chain and
// resets the running tail. That is right for genuinely old rows and was a free
// pass for everything else: blank ONE row's hash and every row after it is
// re-based against an empty tail, so an edited history verifies clean without
// the attacker touching a single hash they would have to compute.
func TestAuditVerify_BlankingAHashDoesNotLaunderTheChain(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	ins(t, c, "r3", "node-0", "2026-07-29T10:00:03Z")

	if err := c.Execute(ctx,
		`UPDATE audit_log SET content_hash = '', signature = '', key_id = '' WHERE id = 'r2'`); err != nil {
		t.Fatalf("blank r2: %v", err)
	}

	res := verify(t, c)
	if len(res.Laundered) == 0 {
		t.Fatalf("a blanked hash mid-chain was accepted as a pre-chain reset point: %+v\n"+
			"this re-bases every later row against an empty tail", res)
	}
	if !res.Tampered() {
		t.Errorf("laundering was recorded but Tampered() is false: %+v", res)
	}
}

// TestAuditVerify_DetectsTruncation.
//
// A hash chain links backward, so removing the tail leaves every surviving link
// intact — the log simply appears shorter, with nothing to say it ever wasn't.
// The signed chain head is the only thing that notices.
func TestAuditVerify_DetectsTruncation(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	// Backdate the head past the replication settle window, so the shortfall is
	// read as missing data rather than a peer that has not caught up yet.
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET created_at = '2026-01-01T00:00:00Z' WHERE host_name = 'node-0'`); err != nil {
		t.Fatalf("backdate head: %v", err)
	}

	if res := verify(t, c); res.Tampered() {
		t.Fatalf("clean chain with a head reports tampering: %+v", res)
	}

	// Cut the tail off.
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r3', 'r4')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	res := verify(t, c)
	if len(res.TruncatedHosts) == 0 {
		t.Fatalf("two rows were deleted from the end of the chain and verify saw nothing: %+v\n"+
			"every remaining link still verifies — only the signed head knows they existed", res)
	}
	if !strings.Contains(res.TruncatedHosts[0], "node-0") {
		t.Errorf("truncation finding %q does not name the host", res.TruncatedHosts[0])
	}
}

// TestAuditVerify_RenumberingCannotHideATruncation.
//
// Truncation is caught by comparing the signed head's seq against the highest
// seq still in the log. That comparison is only worth anything if seq cannot be
// edited: an attacker who deletes the last two rows and then renumbers the
// survivors to end at the head's seq restores the equality and the shortfall
// disappears. Renumbering to a CONTIGUOUS run also slips past the gap check, so
// the sequence numbers must be covered by the signature — nothing else notices.
//
// This test exists because mutation testing found the hole: removing seq from
// the signed payload broke no test at all.
func TestAuditVerify_RenumberingCannotHideATruncation(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET created_at = '2026-01-01T00:00:00Z' WHERE host_name = 'node-0'`); err != nil {
		t.Fatalf("backdate head: %v", err)
	}

	// Delete the last two rows, then renumber the survivors so the log still
	// appears to end at seq 4 with no gap in between.
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r3', 'r4')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE audit_log SET seq = 3 WHERE id = 'r1'`); err != nil {
		t.Fatalf("renumber r1: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE audit_log SET seq = 4 WHERE id = 'r2'`); err != nil {
		t.Fatalf("renumber r2: %v", err)
	}

	res := verify(t, c)
	if len(res.TruncatedHosts) != 0 {
		// The cover-up worked on the seq comparison, which is expected — this
		// test is about what catches it afterwards.
		t.Logf("truncation still visible: %v", res.TruncatedHosts)
	}
	if len(res.BadSignature) == 0 {
		t.Fatalf("rows were renumbered to hide a truncation and every signature still "+
			"verified: %+v\nseq must be covered by the signature, or the head comparison "+
			"can always be neutralised", res)
	}
	if !res.Tampered() {
		t.Errorf("renumbering left the log looking clean: %+v", res)
	}
}

// TestAuditVerify_UnsignedRowsAreReportedNotFlagged.
//
// Every cluster upgrading to v45 has a log full of unsigned rows, and every
// cluster that has not enabled enforcement keeps writing them. Reporting those
// as tampering would make the check useless on day one — operators would learn
// to ignore it, which is worse than not having it.
func TestAuditVerify_UnsignedRowsAreReportedNotFlagged(t *testing.T) {
	c := newAuditTestClient(t) // no keyring: signing disabled
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	res := verify(t, c)
	if res.Tampered() {
		t.Fatalf("an unsigned log reports tampering: %+v", res)
	}
	if res.Unsigned != 2 {
		t.Errorf("unsigned = %d, want 2 — operators need to see how much of the log "+
			"predates tamper-evidence", res.Unsigned)
	}
}

// colOf extracts the single selected column name from "SELECT <col> FROM ...".
func colOf(query string) string {
	q := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(query), "SELECT"))
	return strings.TrimSpace(q[:strings.Index(q, " FROM")])
}

func oneCol(t *testing.T, c *Client, query string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), query)
	if err != nil || len(rows) != 1 {
		t.Fatalf("query %q: %v (rows=%d)", query, err, len(rows))
	}
	return rows[0].String(colOf(query))
}
