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
// strings the moment hlc_lww latches. The RFC3339 parse then failed, the window
// was skipped entirely, and a head that had simply arrived before the rows
// behind it was reported as a truncated log. That is the ordinary
// eventually-consistent case, so on an HLC cluster every publish produced a
// tampering alert seconds later.
//
// Both directions matter: a fresh head must not accuse, and a genuinely old one
// must still be able to.
func TestAuditHeads_AnHLCTimestampDoesNotFakeATruncation(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// A head attesting to rows this node has not received yet, stamped the way
	// an HLC-emitting node stamps it: now, in HLC form.
	hlcNow := hlc.Timestamp{PhysicalMS: time.Now().UnixMilli(), NodeID: "node-0"}.String()
	sig, err := kr.SignHead("node-0", 0, 9, "aabb")
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', 0, 9, 'aabb', ?, ?, ?, ?, NULL)`,
		kr.KeyID(), sig, hlcNow, hlcNow); err != nil {
		t.Fatalf("insert head: %v", err)
	}

	if res := verify(t, c); len(res.TruncatedHosts) > 0 {
		t.Fatalf("a head published seconds ago was read as a truncated log: %v\n"+
			"the settle window exists because a peer can hold a head before the rows it "+
			"attests to; an unreadable timestamp must not skip it", res.TruncatedHosts)
	}

	// Same head, now genuinely older than the window: the shortfall is real.
	old := hlc.Timestamp{
		PhysicalMS: time.Now().Add(-2 * headSettleWindow).UnixMilli(), NodeID: "node-0",
	}.String()
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET created_at = ? WHERE host_name = 'node-0' AND seq = 9`,
		old); err != nil {
		t.Fatalf("age the head: %v", err)
	}
	if res := verify(t, c); len(res.TruncatedHosts) == 0 {
		t.Fatalf("a head older than the settle window attests to seq 9 over a log that ends "+
			"at 1, and nothing was reported: %+v\n"+
			"treating an unreadable clock as 'not settled' must not switch truncation "+
			"detection off for heads already written in HLC form", res)
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

func keySyncTable() syncTable {
	return syncTable{Name: "audit_signing_keys", Columns: []string{
		"key_id", "host_name", "cert_pem", "retired_at", "retired_at_seq",
		"created_at", "updated_at", "deleted_at",
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

// TestAuditMerge_PeerCannotTombstoneAChainHead.
//
// A chain head is the ONLY construct that can detect a truncated tail: a hash
// chain links backward, so cutting the last N rows leaves every surviving link
// verifying. Heads are declared append-only and the statement lane enforces it —
// but anti-entropy ships whole rows, deleted_at included, and merges them by
// plain LWW. So a node could tombstone its own heads with a fresh updated_at,
// have anti-entropy carry the tombstones to every peer, and truncate its log
// with nothing left anywhere to notice.
func TestAuditMerge_PeerCannotTombstoneAChainHead(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	if n := countRows(t, c, `SELECT host_name FROM audit_chain_heads WHERE deleted_at IS NULL`); n != 1 {
		t.Fatalf("expected one live head to attack, got %d", n)
	}
	head := oneCol(t, c, `SELECT head_hash FROM audit_chain_heads WHERE host_name = 'node-0'`)

	table := keyedHeadRow(c, kr.KeyID(), head, "2999-01-01T00:00:00Z")
	mergeOne(t, c, headSyncTable(), []string{"host_name", "epoch", "seq"}, []int{0, 1, 2}, table)

	if n := countRows(t, c, `SELECT host_name FROM audit_chain_heads WHERE deleted_at IS NULL`); n != 1 {
		t.Fatalf("a peer's tombstone deleted a signed chain head (%d live heads left)\n"+
			"truncation detection is gone cluster-wide the moment that replicates, and a "+
			"hash chain cannot see a missing tail on its own", n)
	}
}

// keyedHeadRow builds an incoming anti-entropy copy of node-0's only head,
// carrying a tombstone and a far-future clock — the shape a compromised node
// would send to erase it everywhere.
func keyedHeadRow(c *Client, keyID, headHash, clock string) []interface{} {
	return []interface{}{
		"node-0", int64(0), int64(1), headHash, keyID, "sig",
		"2026-07-29T10:00:01Z", clock, clock,
	}
}

// TestAuditMerge_PeerCannotUnretireASigningKey.
//
// retired_at is the entire basis of the RetiredKeyUse finding — the detector for
// "the rotated-out key is still in someone's hands and still signing". It lives
// in an ordinary LWW-merged table, so clearing it locally with a fresh clock
// removes the finding on every peer at once. The clock on an incoming row is
// written by whoever sent it, which makes "newest wins" mean "the compromised
// node wins".
func TestAuditMerge_PeerCannotUnretireASigningKey(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	oldID := oldKR.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+oldID+`'`)
	if n := countRows(t, c,
		`SELECT key_id FROM audit_signing_keys WHERE key_id = '`+oldID+`' AND retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("the old key is not retired to begin with; nothing to protect")
	}

	// The peer offers the same key with retirement cleared and a far-future clock.
	incoming := []interface{}{
		oldID, "node-0", cert, nil, int64(0),
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if n := countRows(t, c,
		`SELECT key_id FROM audit_signing_keys WHERE key_id = '`+oldID+`' AND retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("a peer un-retired a rotated-out signing key\n"+
			"every row that key signs past its boundary stops being reported, on this node "+
			"and on every other one anti-entropy reaches")
	}
}

// TestAuditMerge_PeerCannotRaiseARetirementBoundary.
//
// The subtler version: leave the key retired, but move retired_at_seq forward so
// the rows already flagged fall back inside the window. It looks like ordinary
// convergence — both copies say "retired" — and it re-authorises exactly the
// signatures the boundary existed to reject.
func TestAuditMerge_PeerCannotRaiseARetirementBoundary(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	oldID := oldKR.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+oldID+`'`)
	retiredAt := oneCol(t, c, `SELECT retired_at FROM audit_signing_keys WHERE key_id = '`+oldID+`'`)

	incoming := []interface{}{
		oldID, "node-0", cert, retiredAt, int64(9999),
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if got := oneCol(t, c,
		`SELECT retired_at_seq FROM audit_signing_keys WHERE key_id = '`+oldID+`'`); got == "9999" {
		t.Fatalf("a peer moved a retirement boundary forward to seq 9999\n"+
			"the key stays nominally retired, and every row it signs below that point is "+
			"silently re-authorised on every node")
	}
}

// TestAuditMerge_PeerCannotTombstoneASigningCertificate.
//
// Deleting a retired certificate does not hide the rows it signed — it makes
// them UNVERIFIABLE, which reads as mass tampering rather than as the erasure it
// is. A retired certificate has to stay resolvable for as long as any row it
// signed exists, which is why retirement is a validity window and never a
// delete.
func TestAuditMerge_PeerCannotTombstoneASigningCertificate(t *testing.T) {
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	id := kr.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+id+`'`)
	incoming := []interface{}{
		id, "node-0", cert, nil, int64(0),
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z",
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if res := verify(t, c); len(res.UnknownKeyID) > 0 {
		t.Fatalf("a peer's tombstone removed the certificate for key %s, and every row it "+
			"signed is now unverifiable: %v\n"+
			"a rotation performed to improve integrity would read as mass tampering",
			id, res.UnknownKeyID)
	}
}

// TestAuditMerge_ARetirementStillPropagates keeps the guards from being a wall.
//
// Monotone means one-way, not frozen: a peer that learns of a retirement before
// this node does must still be able to deliver it, or a rotation would never
// reach the cluster and the guards would have replaced one silent failure with
// another.
func TestAuditMerge_ARetirementStillPropagates(t *testing.T) {
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	id := kr.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+id+`'`)
	incoming := []interface{}{
		id, "node-0", cert, "2026-07-29T11:00:00Z", int64(1),
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if n := countRows(t, c,
		`SELECT key_id FROM audit_signing_keys WHERE key_id = '`+id+`' AND retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("a retirement learned from a peer did not land; a rotation performed on one "+
			"node would never become visible to the rest of the cluster")
	}
}

// TestAuditMerge_HealsALocallyTombstonedChainHead is the other half of the
// tombstone rule, and the lab is what asked for it.
//
// Refusing a tombstone stops the erasure spreading. It does nothing for the node
// the erasure happened ON: that node wrote the clock on its own row, so under
// LWW its tombstone beats every peer's live copy forever. The compromised node
// then verifies clean locally while its neighbours hold the head — the guard
// would have converted a spreading problem into a permanent local one, and a
// node damaged by plain corruption could never recover at all.
func TestAuditMerge_HealsALocallyTombstonedChainHead(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	if err := PublishAuditChainHead(ctx, c, "node-0"); err != nil {
		t.Fatalf("PublishAuditChainHead: %v", err)
	}
	head := oneCol(t, c, `SELECT head_hash FROM audit_chain_heads WHERE host_name = 'node-0'`)
	created := oneCol(t, c, `SELECT created_at FROM audit_chain_heads WHERE host_name = 'node-0'`)
	sig := oneCol(t, c, `SELECT signature FROM audit_chain_heads WHERE host_name = 'node-0'`)

	// The head is deleted here, with a clock no peer's honest write can beat.
	if err := c.Execute(ctx,
		`UPDATE audit_chain_heads SET deleted_at = ?, updated_at = ? WHERE host_name = 'node-0'`,
		"2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"); err != nil {
		t.Fatalf("tombstone: %v", err)
	}

	// A peer offers its intact copy, carrying the ORIGINAL — and therefore much
	// older — clock. Ordinary LWW would discard it.
	incoming := []interface{}{
		"node-0", int64(0), int64(1), head, kr.KeyID(), sig, created, created, nil,
	}
	mergeOne(t, c, headSyncTable(), []string{"host_name", "epoch", "seq"}, []int{0, 1, 2}, incoming)

	if n := countRows(t, c,
		`SELECT host_name FROM audit_chain_heads WHERE host_name = 'node-0' AND deleted_at IS NULL`); n != 1 {
		t.Fatalf("a locally deleted chain head was not restored from a peer's intact copy "+
			"(%d live heads)\nthe node that deleted it wrote the newest clock, so under LWW "+
			"it keeps the tombstone forever and truncation detection stays off here", n)
	}
}

// TestAuditMerge_HealsALocallyTombstonedCertificate is the same rule for the
// certificate table, where the consequence is louder: a deleted certificate does
// not hide the rows that key signed, it makes them unverifiable.
func TestAuditMerge_HealsALocallyTombstonedCertificate(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	id := kr.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+id+`'`)
	created := oneCol(t, c, `SELECT created_at FROM audit_signing_keys WHERE key_id = '`+id+`'`)
	if err := c.Execute(ctx,
		`UPDATE audit_signing_keys SET deleted_at = ?, updated_at = ? WHERE key_id = ?`,
		"2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z", id); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if res := verify(t, c); len(res.UnknownKeyID) == 0 {
		t.Fatalf("deleting the certificate did not make its rows unverifiable, so this test " +
			"is not measuring the damage it claims to repair")
	}

	incoming := []interface{}{
		id, "node-0", cert, nil, int64(0), created, created, nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if res := verify(t, c); len(res.UnknownKeyID) > 0 {
		t.Fatalf("a locally deleted certificate was not restored from a peer's intact copy: %v\n"+
			"every row that key signed stays unverifiable on this node forever", res.UnknownKeyID)
	}
}

// TestAuditMerge_HealingDoesNotUnretireAKey.
//
// Healing must not become a back door. A peer's copy that is live AND
// un-retired, arriving at a node whose row is tombstoned and retired, would
// repair the tombstone and drop the retirement in the same write — so the
// monotone rule is checked first and wins.
func TestAuditMerge_HealingDoesNotUnretireAKey(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	oldID := oldKR.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+oldID+`'`)
	if err := c.Execute(ctx,
		`UPDATE audit_signing_keys SET deleted_at = ? WHERE key_id = ?`,
		"2999-01-01T00:00:00Z", oldID); err != nil {
		t.Fatalf("tombstone: %v", err)
	}

	incoming := []interface{}{
		oldID, "node-0", cert, nil, int64(0),
		"2026-07-29T10:00:00Z", "2999-01-01T00:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if n := countRows(t, c,
		`SELECT key_id FROM audit_signing_keys WHERE key_id = '`+oldID+`' AND retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("healing a tombstone also cleared the key's retirement\n" +
			"deleting the row would then be a way to launder an un-retirement past the " +
			"monotone check")
	}
}

// TestAuditMerge_LearnsARetirementOverAnUnbeatableLocalClock is the same lesson
// the tombstone taught, applied to retirement — and again the lab is what asked.
//
// On the live cluster node-2 cleared its own retired_at with a year-2999 clock.
// Every peer refused the erasure and kept the retirement, which is the point of
// the monotone rule. But node-2 kept its un-retired copy: it wrote that clock, so
// nothing a peer could honestly send would ever outrank it. The compromised node
// went on accepting the leaked key's signatures while every neighbour reported
// them.
//
// Sticky is not monotone. Strictly-more-retired has to WIN, in whichever
// direction of the merge it arrives.
func TestAuditMerge_LearnsARetirementOverAnUnbeatableLocalClock(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	id := kr.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+id+`'`)
	// This node's row is un-retired and carries a clock no honest peer can beat.
	if err := c.Execute(ctx,
		`UPDATE audit_signing_keys SET updated_at = ? WHERE key_id = ?`,
		"2999-01-01T00:00:00Z", id); err != nil {
		t.Fatalf("stamp the local clock: %v", err)
	}

	// A peer that knows about the retirement, speaking with an ordinary clock.
	incoming := []interface{}{
		id, "node-0", cert, "2026-07-29T11:00:00Z", int64(1),
		"2026-07-29T10:00:00Z", "2026-07-29T11:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if n := countRows(t, c,
		`SELECT key_id FROM audit_signing_keys WHERE key_id = '`+id+`' AND retired_at IS NOT NULL`); n != 1 {
		t.Fatalf("a retirement known to a peer never reached this node, because the local row " +
			"carried a newer clock\nthe node that cleared its own retired_at wrote that clock, " +
			"so refusing the weakening is not enough — the retirement has to win outright")
	}
}

// TestAuditMerge_TakesTheStricterBoundary.
//
// Two nodes can disagree about where a key's boundary sits. The earlier sequence
// is the strict one: it flags every row the later one would have re-authorised,
// so it is the only safe direction to converge in.
func TestAuditMerge_TakesTheStricterBoundary(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	rotateTo(t, c, dir, "node-0") // retires the old key at seq 2

	oldID := oldKR.KeyID()
	cert := oneCol(t, c, `SELECT cert_pem FROM audit_signing_keys WHERE key_id = '`+oldID+`'`)
	if err := c.Execute(ctx,
		`UPDATE audit_signing_keys SET updated_at = ? WHERE key_id = ?`,
		"2999-01-01T00:00:00Z", oldID); err != nil {
		t.Fatalf("stamp the local clock: %v", err)
	}

	incoming := []interface{}{
		oldID, "node-0", cert, "2026-07-29T11:00:00Z", int64(1),
		"2026-07-29T10:00:00Z", "2026-07-29T11:00:00Z", nil,
	}
	mergeOne(t, c, keySyncTable(), []string{"key_id"}, []int{0}, incoming)

	if got := oneCol(t, c,
		`SELECT retired_at_seq FROM audit_signing_keys WHERE key_id = '`+oldID+`'`); got != "1" {
		t.Fatalf("retired_at_seq is %q, want the stricter boundary 1; a node holding the looser "+
			"one keeps accepting signatures every peer already flags", got)
	}
}
