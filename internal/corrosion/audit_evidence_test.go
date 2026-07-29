package corrosion

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// The tamper-evidence a signature produces is only worth what the REPLICATION
// layer will let stand.
//
// Every check in the verifier reads from three tables — audit_log,
// audit_chain_heads and audit_signing_keys — and all three replicate. So a node
// with local database write access does not have to defeat the cryptography at
// all. It can go after the evidence: publish a chain head that agrees with its
// rewrite, delete the heads that disagree, clear the retirement marker that
// makes a rotated-out key's signature a finding, or emit the pre-v45 reseal
// statement whose WHERE clause never learned about signatures. Each of those
// moves is silent, and each replicates from one node to every peer — so it does
// not merely hide the tampering locally, it destroys the good copy that a
// neighbour would have used to contradict the compromised node.
//
// These tests fix the floor under the verifier: what a peer is allowed to
// change about another node's evidence, whatever clock or epoch it claims.

// ─────────────────── chain heads: who gets to speak for the chain ───────────────────

// TestAuditHeads_RetiredKeyCannotDisplaceTheSealingHead is the attack rotation
// exists to stop, aimed one level down at the machinery that detects it.
//
// The attacker holds the rotated-out key. They rewrite the last row it signed
// and re-sign it: the signature verifies (they have the key), the chain still
// links, the sequence numbers are untouched, and the key was inside its
// boundary. The only witness left is the head published at rotation, signed by
// the successor key they do not have.
//
// So they publish their own head — over the forged tail hash, at a far higher
// epoch. Selecting the authoritative head by highest epoch hands them the
// choice: their head becomes the one that gets checked, it agrees with the
// forgery, and the sealing head that disagrees is silently discarded for being
// at a lower epoch. Heads have to be tracked PER KEY for the successor's
// assertion to survive an old key's.
func TestAuditHeads_RetiredKeyCannotDisplaceTheSealingHead(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	newKR := rotateTo(t, c, dir, "node-0") // seals seq 2 with a head signed by the new key
	if newKR.KeyID() == oldKR.KeyID() {
		t.Fatal("rotation produced the same key id; every assertion below would pass vacuously")
	}

	forged := rewriteTailRowWithRetiredKey(t, c, oldKR, "r2", 2)

	// The head the attacker can make: over their own tail hash, at an epoch far
	// above anything the host has published, signed with the retired key.
	if err := insertAuditChainHead(ctx, c, oldKR, "node-0", 99, 2, forged); err != nil {
		t.Fatalf("publish the forged head: %v", err)
	}

	res := verify(t, c)
	// Sanity: the forgery really does defeat every easier check, or this test is
	// proving something weaker than it claims.
	if res.BrokenAt != "" || len(res.BadSignature) > 0 {
		t.Fatalf("the forgery was caught by an easier check (broken_at=%q bad_sig=%v); it is "+
			"supposed to be chain-consistent and signature-valid", res.BrokenAt, res.BadSignature)
	}
	if len(res.HeadMismatch) == 0 {
		t.Fatalf("a head published with the RETIRED key displaced the sealing head signed by its "+
			"successor, and a rewrite of the log verified clean: %+v\n"+
			"epoch is chosen by whoever writes the head, so it cannot be what picks the "+
			"authority — the successor key's assertion has to survive alongside it", res)
	}
}

// TestAuditHeads_RetiredKeyCannotAttestPastItsBoundary.
//
// The retirement boundary applies to heads for the same reason it applies to
// rows: a key that has been rotated out has no standing to make a fresh
// assertion about the chain. Without this, the holder of a leaked key could
// keep publishing heads forever and the log would look actively maintained by
// a key nobody trusts.
func TestAuditHeads_RetiredKeyCannotAttestPastItsBoundary(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0") // retires the old key at seq 1
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	tail := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r2'`)
	if err := insertAuditChainHead(ctx, c, oldKR, "node-0", 5, 2, tail); err != nil {
		t.Fatalf("publish a head with the retired key: %v", err)
	}

	res := verify(t, c)
	if len(res.RetiredKeyUse) == 0 {
		t.Fatalf("a chain head signed by a key retired at seq 1 was accepted as an assertion "+
			"about seq 2: %+v", res)
	}
}

// rewriteTailRowWithRetiredKey rewrites one row's content and re-signs it with
// the given (retired) keyring, leaving the chain internally consistent. It
// returns the new content hash.
func rewriteTailRowWithRetiredKey(t *testing.T, c *Client, kr *AuditKeyring, id string, seq int64) string {
	t.Helper()
	ctx := context.Background()
	if err := c.Execute(ctx,
		`UPDATE audit_log SET target = 'bob', username = 'system' WHERE id = ?`, id); err != nil {
		t.Fatalf("tamper with %s: %v", id, err)
	}
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash
		 FROM audit_log WHERE id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %v (rows=%d)", id, err, len(rows))
	}
	r := rows[0]
	rec := AuditRecord{
		ID: r.String("id"), Timestamp: r.String("timestamp"), Username: r.String("username"),
		HostName: r.String("host_name"), Action: r.String("action"), Target: r.String("target"),
		Detail: r.String("detail"), Result: r.String("result"), PrevHash: r.String("prev_hash"),
		Seq: seq,
	}
	rec.ContentHash = HashAuditRow(rec)
	sig, err := kr.SignRow(rec.ContentHash, seq)
	if err != nil {
		t.Fatalf("re-sign %s with the retired key: %v", id, err)
	}
	if err := c.Execute(ctx,
		`UPDATE audit_log SET content_hash = ?, signature = ?, key_id = ? WHERE id = ?`,
		rec.ContentHash, sig, kr.KeyID(), id); err != nil {
		t.Fatalf("store the re-signed %s: %v", id, err)
	}
	return rec.ContentHash
}

// TestAuditHeads_AnHLCTimestampDoesNotFakeATruncation.
//
// created_at is a wall time the settle window is measured against, but it used
// to be stamped with NowTS — the LWW conflict key, which starts emitting HLC
// strings the moment hlc_lww latches. Reading an HLC value as wall time skipped
// the window entirely, and a head that had simply arrived before the rows behind
// it was reported as a truncated log. That is the ordinary
// eventually-consistent case, so on an HLC cluster every publish produced a
// tampering alert seconds later.
func TestAuditHeads_AnHLCTimestampDoesNotFakeATruncation(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// A head attesting to rows this node has not received yet, stamped the way
	// an HLC-emitting node stamps it: now, in HLC form — and SIGNED over that
	// value, which is what makes the window trustworthy enough to honour.
	hlcNow := hlc.Timestamp{PhysicalMS: time.Now().UnixMilli(), NodeID: "node-0"}.String()
	insertSignedHead(t, c, kr, 0, 9, "aabb", hlcNow)

	if res := verify(t, c); len(res.TruncatedHosts) > 0 {
		t.Fatalf("a head published seconds ago was read as a truncated log: %v\n"+
			"the settle window exists because a peer can hold a head before the rows it "+
			"attests to", res.TruncatedHosts)
	}

	// Same head, genuinely older than the window: the shortfall is real.
	old := hlc.Timestamp{
		PhysicalMS: time.Now().Add(-2 * headSettleWindow).UnixMilli(), NodeID: "node-0",
	}.String()
	if err := c.Execute(ctx, `DELETE FROM audit_chain_heads WHERE seq = 9`); err != nil {
		t.Fatalf("clear: %v", err)
	}
	insertSignedHead(t, c, kr, 0, 9, "aabb", old)
	if res := verify(t, c); len(res.TruncatedHosts) == 0 {
		t.Fatalf("a head older than the settle window attests to seq 9 over a log that ends "+
			"at 1, and nothing was reported: %+v", res)
	}
}

// TestAuditHeads_AnEditedTimestampCannotSilenceTruncation.
//
// created_at was outside the signed payload, and the verifier measures the
// settle window against it. So an attacker could truncate a log and then scribble
// in created_at on their own heads — an unparseable value meant "not settled",
// which meant no finding at all. A silent off switch for the one check a
// backward-linking hash chain cannot perform for itself.
//
// Two shapes now close it, and the test covers both. On a head signed over its
// timestamp (payload v2) the edit breaks the signature, which is louder than the
// truncation would have been. On a head published before the column moved inside
// the payload, the signature still verifies — so an unverifiable timestamp gets
// the conservative reading, settled, and the shortfall is reported.
func TestAuditHeads_AnEditedTimestampCannotSilenceTruncation(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	for _, id := range []string{"r1", "r2", "r3"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r2','r3')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET created_at = 'not-a-timestamp' WHERE host_name = 'node-0'`); err != nil {
		t.Fatalf("edit created_at: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("editing a head's created_at silenced the truncation it attests to: %+v\n"+
			"the settle window is measured against that column, so leaving it outside the "+
			"signature made it an off switch for the check", res)
	}
	if len(res.BadSignature) == 0 {
		t.Errorf("want the edit reported against the head's signature, got %+v", res)
	}

	// A head from before created_at moved inside the payload: the signature still
	// verifies over the edited value, so only the conservative reading catches it.
	if err := c.Execute(ctx, `DELETE FROM audit_chain_heads`); err != nil {
		t.Fatalf("clear: %v", err)
	}
	insertV1Head(t, c, kr, 0, 3, "aabb", "not-a-timestamp")
	res = verify(t, c)
	if len(res.TruncatedHosts) == 0 {
		t.Fatalf("a legacy head with an unreadable timestamp stopped detecting a truncation: "+
			"%+v\nan unverifiable clock must not be able to suppress the finding", res)
	}
}

// insertV1Head writes a head signed with the pre-created_at payload, as one
// published before the upgrade would be.
func insertV1Head(t *testing.T, c *Client, kr *AuditKeyring, epoch, seq int64, hash, createdAt string) {
	t.Helper()
	sig, err := kr.sign(auditHeadDigestV1("node-0", epoch, seq, hash, kr.KeyID()))
	if err != nil {
		t.Fatalf("sign v1 head: %v", err)
	}
	if err := c.Execute(context.Background(),
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, ?, ?, ?, ?, ?, ?, NULL)`,
		epoch, seq, hash, kr.KeyID(), sig, createdAt, createdAt); err != nil {
		t.Fatalf("insert v1 head: %v", err)
	}
}

// insertSignedHead writes a head with a chosen created_at, signed over it.
func insertSignedHead(t *testing.T, c *Client, kr *AuditKeyring, epoch, seq int64, hash, createdAt string) {
	t.Helper()
	sig, err := kr.SignHead("node-0", epoch, seq, hash, createdAt)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := c.Execute(context.Background(),
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, ?, ?, ?, ?, ?, ?, NULL)`,
		epoch, seq, hash, kr.KeyID(), sig, createdAt, createdAt); err != nil {
		t.Fatalf("insert head: %v", err)
	}
}

// ─────────────────── the pre-v45 reseal shape ───────────────────

// TestWAL_LegacyResealCannotRewriteASignedRow.
//
// The v45 reseal builder grew a `signature IS NULL OR signature = ''` guard
// precisely because the statement replicates and peers apply it verbatim by
// primary key with no clock compare. But the PRE-v45 shape — the same UPDATE
// without the guard — stayed registered for the rolling-upgrade horizon, and a
// receiver applying it verbatim honours whichever shape it is handed. So the
// guard was bypassable by simply emitting the older statement, which any node
// with database write access can do.
//
// Worse than a local edit: this one overwrites every peer's good content_hash,
// and since reseal now refuses to touch signed rows, nothing can put the
// correct hash back afterwards.
func TestWAL_LegacyResealCannotRewriteASignedRow(t *testing.T) {
	c, _, _ := signedClient(t, "node-0")
	r := NewReplicator(c, "", RelayConfig{})
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	before := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`)

	applyLegacyReseal(t, r, c, "forged-prev", "forged-hash", "r1")

	if got := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`); got != before {
		t.Fatalf("the pre-v45 reseal shape rewrote a SIGNED row's content_hash (%s -> %s)\n"+
			"one node emitting the older statement would overwrite the good copy on every "+
			"peer, and reseal cannot restore it", before, got)
	}
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("the log is reported as tampered after a refused reseal: %+v", res)
	}
}

// TestWAL_LegacyResealStillHealsAnUnsignedRow is the other half of the rule.
//
// Rejecting the legacy shape outright would back-pressure a peer that is simply
// running the older build, and legacy rows genuinely do need re-basing. The
// guard has to exclude only what it was ever meant to exclude — and a sender old
// enough to emit this shape has no signed rows at all.
func TestWAL_LegacyResealStillHealsAnUnsignedRow(t *testing.T) {
	c := newAuditTestClient(t) // no keyring: unsigned, like every pre-v45 row
	r := NewReplicator(c, "", RelayConfig{})
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	applyLegacyReseal(t, r, c, "rebased-prev", "rebased-hash", "r1")

	if got := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`); got != "rebased-hash" {
		t.Fatalf("an unsigned legacy row was not re-based by the legacy reseal (content_hash = %q); "+
			"pre-v45 rows would stay divergent across the cluster forever", got)
	}
}

// applyLegacyReseal drives the WAL apply path with the PRE-v45 reseal shape,
// exactly as a peer on the older build emits it — no signature predicate.
func applyLegacyReseal(t *testing.T, r *Replicator, c *Client, prev, hash, id string) {
	t.Helper()
	s := Statement{
		SQL:    `UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = ?`,
		Params: []interface{}{prev, hash, id},
	}
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.applyStatementLWW(context.Background(), tx, s, "2999-01-01T00:00:00Z"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply the legacy reseal shape: %v\n"+
			"it must stay ACCEPTED for the upgrade horizon, not back-pressure a peer on the "+
			"older build", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// ─────────────────── anti-entropy over the evidence tables ───────────────────

func headSyncTable() syncTable {
	return syncTable{Name: "audit_chain_heads", Columns: []string{
		"host_name", "epoch", "seq", "head_hash", "key_id", "signature",
		"created_at", "updated_at", "deleted_at",
	}}
}

func retirementSyncTable() syncTable {
	return syncTable{Name: "audit_key_lifecycle", Columns: []string{
		"host_name", "key_id", "event", "at_seq", "by_key_id",
		"signature", "created_at", "updated_at", "deleted_at",
	}}
}

// mergeOne pushes one incoming anti-entropy row through the real merge path.
func mergeOne(t *testing.T, c *Client, table syncTable, pkCols []string, pkIdx []int, row []interface{}) {
	t.Helper()
	if _, _, err := c.mergeChunk(
		table, [][]interface{}{row},
		buildMergeUpsertSQL(table.Name, table.Columns, pkCols),
		pkCols, pkIdx, indexOf(table.Columns, "updated_at"),
	); err != nil {
		t.Fatalf("mergeChunk on %s: %v", table.Name, err)
	}
}

// TestAuditEvidence_ATombstoneIsInert.
//
// A chain head is the only construct that can detect a truncated tail: a hash
// chain links backward, so cutting the last N rows leaves every surviving link
// verifying. Deleting the heads is therefore the efficient attack, and for a
// while the answer here was a merge rule that refused tombstones and a
// force-apply that repaired them.
//
// Both were the wrong layer. The verifier simply does not filter on deleted_at,
// so setting it accomplishes nothing at all — no rule to get right, no repair to
// perform, and no force-apply path that could carry an unrelated column rewrite
// along with it.
func TestAuditEvidence_ATombstoneIsInert(t *testing.T) {
	ctx := context.Background()
	c, _, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	if before := verify(t, c); before.Tampered() {
		t.Fatalf("baseline is not clean: %+v", before)
	}

	// Tombstone every piece of evidence this node holds, with a clock no honest
	// write can beat.
	for _, q := range []string{
		`UPDATE audit_chain_heads SET deleted_at = ?, updated_at = ? WHERE host_name = 'node-0'`,
		`UPDATE audit_signing_keys SET deleted_at = ?, updated_at = ? WHERE host_name = 'node-0'`,
	} {
		if err := c.Execute(ctx, q, "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
			t.Fatalf("tombstone: %v", err)
		}
	}

	// A FRESH keyring, because certFor caches every certificate it resolves.
	// Reusing the warm one would answer from the cache and never reach the query
	// whose deleted_at filter is the thing under test — which is also the real
	// shape of the attack: the node that matters is the one starting up after the
	// tombstone replicated to it.
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)

	after := verify(t, c)
	if len(after.UnknownKeyID) > 0 {
		t.Fatalf("a tombstoned certificate stopped resolving: %v\n"+
			"deleting it does not hide the rows it signed, it makes them unverifiable — "+
			"which reads as mass tampering rather than as the erasure it is", after.UnknownKeyID)
	}
	if after.Tampered() {
		t.Fatalf("tombstoning the evidence changed the verdict: %+v", after)
	}
}

// TestAuditEvidence_PeerCannotRewriteAChainHead keeps the half that still
// matters. A head is a fixed assertion about (host, epoch, seq); there is no
// later revision of one, so a differing body is corruption or forgery and taking
// it would overwrite the copy that disagrees with whoever sent it.
func TestAuditEvidence_PeerCannotRewriteAChainHead(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	original := oneCol(t, c, `SELECT head_hash FROM audit_chain_heads WHERE host_name = 'node-0'`)

	incoming := []interface{}{
		"node-0", int64(0), int64(1), "forged-head-hash", kr.KeyID(), "sig",
		"2026-07-29T10:00:01Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, headSyncTable(), []string{"host_name", "epoch", "seq"}, []int{0, 1, 2}, incoming)

	if got := oneCol(t, c, `SELECT head_hash FROM audit_chain_heads WHERE host_name = 'node-0'`); got != original {
		t.Fatalf("a peer rewrote a published chain head (%s -> %s); the head is what "+
			"contradicts a rewritten chain, so overwriting it is the whole attack", original, got)
	}
}

// ─────────────────── signed retirement ───────────────────

// TestRetirement_ForgedOneIsIgnored is the v47 shape's reason for existing.
//
// v46 kept retirement in two mutable columns on audit_signing_keys. Any peer
// could write them, so setting retired_at on a host's LIVE key put every row
// that host had ever signed past a boundary — on every node, permanently, with
// no key required and no way back.
//
// A retirement is now an assertion someone had to sign. One that does not verify
// is not a weaker retirement, it is not a retirement at all.
func TestRetirement_ForgedOneIsIgnored(t *testing.T) {
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	// The attacker writes a retirement for the host's ACTIVE key, at seq 0, so
	// that every row it has signed falls past the boundary. They have no key, so
	// the signature is junk.
	if err := c.Execute(context.Background(),
		`INSERT INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature,
		    created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, 'retired', 0, ?, 'deadbeef', ?, ?, NULL)`,
		kr.KeyID(), kr.KeyID(), "2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert the forged retirement: %v", err)
	}

	res := verify(t, c)
	if len(res.RetiredKeyUse) > 0 {
		t.Fatalf("a forged retirement invalidated the host's live chain: %v\n"+
			"anyone able to write the table could put every row a host ever signed past a "+
			"boundary, on every node, without holding any key", res.RetiredKeyUse)
	}
	if res.Tampered() {
		t.Fatalf("a forged retirement made the log read as tampered: %+v", res)
	}
}

// TestRetirement_SignedOneIsHonoured is the other direction: the mechanism has
// to still work, or the fix above is just "never retire anything".
func TestRetirement_SignedOneIsHonoured(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	if n := countRows(t, c,
		`SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldKR.KeyID()+`'`); n != 1 {
		t.Fatalf("a genuine rotation recorded no retirement; the retired-key finding would " +
			"never fire again")
	}
	forgeRowWithKey(t, c, oldKR, "forged", 2)
	if res := verify(t, c); len(res.RetiredKeyUse) == 0 {
		t.Fatalf("a row signed by the retired key past its boundary was accepted: %+v", res)
	}
}

// TestRetirement_PeerCannotRewriteOne. The boundary is part of the signed
// payload, so moving it invalidates the signature — but the merge must refuse
// the rewrite anyway rather than let a peer replace the row that still verifies.
func TestRetirement_PeerCannotRewriteOne(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	oldID := oldKR.KeyID()
	sig := oneCol(t, c, `SELECT signature FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldID+`'`)
	by := oneCol(t, c, `SELECT by_key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldID+`'`)

	incoming := []interface{}{
		"node-0", oldID, "retired", int64(9999), by, sig,
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, retirementSyncTable(), []string{"host_name", "key_id", "event"}, []int{0, 1, 2}, incoming)

	if got := oneCol(t, c,
		`SELECT at_seq FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldID+`'`); got == "9999" {
		t.Fatalf("a peer moved a signed retirement boundary to seq 9999; every row the key "+
			"signed below it is silently re-authorised")
	}
}

// forgeRowWithKey appends a correctly chained, correctly signed row using the
// given key — the move a retirement boundary exists to catch.
func forgeRowWithKey(t *testing.T, c *Client, kr *AuditKeyring, id string, seq int64) {
	t.Helper()
	ctx := context.Background()
	prev := oneCol(t, c,
		`SELECT content_hash FROM audit_log WHERE host_name = 'node-0' ORDER BY timestamp DESC, id DESC LIMIT 1`)
	rec := AuditRecord{
		ID: id, Timestamp: "2026-07-30T12:00:00Z", Username: "root", HostName: "node-0",
		Action: "user.delete", Target: "alice", Result: "success", PrevHash: prev, Seq: seq,
	}
	rec.ContentHash = HashAuditRow(rec)
	sig, err := kr.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result,
		                        prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, rec.ContentHash, kr.KeyID(), sig, rec.Seq); err != nil {
		t.Fatalf("insert the forged row: %v", err)
	}
}

// TestAuditEvidence_ATombstonedHeadStillDetectsTruncation is the half of the
// inert-tombstone rule that carries the real weight.
//
// A certificate that stops resolving is loud — every row it signed turns into an
// UnknownKeyID finding. A head that stops counting is SILENT: the log simply
// looks shorter than nothing in particular, and truncation is the one thing a
// backward-linking hash chain cannot notice on its own. So the tombstone has to
// be inert here specifically, not merely survive in the table.
func TestAuditEvidence_ATombstonedHeadStillDetectsTruncation(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	for _, id := range []string{"r1", "r2", "r3"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}
	// Older than headSettleWindow, so a shortfall is not read as replication lag —
	// and SIGNED over that timestamp, since created_at is inside the payload.
	tail := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r3'`)
	insertSignedHead(t, c, kr, 0, 3, tail,
		time.Now().Add(-2*headSettleWindow).UTC().Format(time.RFC3339))

	// Cut the tail off, then delete the head that would have noticed.
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('r2','r3')`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET deleted_at = ?, updated_at = ? WHERE host_name = 'node-0'`,
		"2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("tombstone the head: %v", err)
	}

	if res := verify(t, c); len(res.TruncatedHosts) == 0 {
		t.Fatalf("a tombstoned chain head stopped detecting a truncated log: %+v\n"+
			"deleting the head is the cheapest way to hide missing rows, so setting "+
			"deleted_at must accomplish nothing at all", res)
	}
}

// TestRetirement_CannotBeRecordedWithoutAKey.
//
// The last line of defence under both rollback paths. A retirement is what
// distinguishes "this host stopped deliberately" from "someone took this host's
// key away" — and the only thing that can make that distinction is whether a
// signature could be produced. If an unsigned retirement could be written, then
// removing a host's key would BE a way to end its signing contract, which is
// exactly backwards.
func TestRetirement_CannotBeRecordedWithoutAKey(t *testing.T) {
	ctx := context.Background()
	c, kr, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	verifier, err := LoadAuditVerifier(dir) // CA only: can verify, cannot sign
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	if err := RetireAuditKey(ctx, c, verifier, "node-0", kr.KeyID(), 1); err == nil {
		t.Fatal("a retirement was recorded by a party that cannot sign one\n" +
			"taking a host's key away would then be a way to end its signing contract")
	}
	if n := countRows(t, c,
		`SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+kr.KeyID()+`'`); n != 0 {
		t.Fatalf("an unsigned retirement row was written anyway (%d rows)", n)
	}
}
