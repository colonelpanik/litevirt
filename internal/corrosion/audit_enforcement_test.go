package corrosion

import (
	"context"
	"strings"
	"testing"
)

// What "enforcement" is allowed to mean on the audit write path.
//
// The v45 design said: once audit_signature_v1 is latched, a node that cannot
// sign must FAIL the audit write rather than append an unsigned row, because
// otherwise tamper-evidence is removable by making the key unreadable.
//
// The first half of that is right and the second half was implemented in the one
// way that made it worse. InsertAuditLog returned an error — and every caller
// discards it. The gRPC audit helper warns; failover and the health assertions
// assign it to `_`. So the delete, the migrate, the fence all still executed and
// NO row was written for any of them, on a cluster where the operator had turned
// enforcement ON. `lv audit verify` reported the log intact, because a row that
// was never written leaves nothing to find.
//
// The row is now written unsigned and the anomaly is made loud instead. What
// makes that safe rather than a silent degradation is a boundary derived from
// the log itself: a host that has produced one signed row cannot legitimately
// produce an unsigned one afterwards, whatever the latch says. So both the
// attacker who appends a fabricated unsigned row and the node that quietly lost
// its key leave the same permanent, cluster-visible finding.

// requireSigning makes this client behave as if the cluster latch had formed.
func requireSigning(c *Client) { c.SetAuditSignatureRequired(func() bool { return true }) }

// TestEnforcement_AnUnsignableWriteIsRecordedNotDropped.
//
// The operation happened. Losing the record of it is not a safe failure mode —
// it is the outcome an attacker would choose, achieved by making one file
// unreadable, and every caller in the tree discards the error that was supposed
// to prevent it.
func TestEnforcement_AnUnsignableWriteIsRecordedNotDropped(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t) // no keyring: this node cannot sign
	requireSigning(c)

	err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "r1", Username: "root", HostName: "node-0",
		Action: "vm.delete", Target: "prod-db", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	})
	if err != nil {
		t.Fatalf("InsertAuditLog returned an error the callers all discard: %v\n"+
			"the VM was still deleted; refusing the write only removes the record of it", err)
	}
	if n := countRows(t, c, `SELECT id FROM audit_log WHERE id = 'r1'`); n != 1 {
		t.Fatalf("no audit row was written for a vm.delete that executed (%d rows)\n"+
			"a silent, total audit gap is worse than the unsigned row it was avoiding", n)
	}
	if got := oneCol(t, c, `SELECT action FROM audit_log WHERE id = 'r1'`); got != "vm.delete" {
		t.Fatalf("the recorded action is %q, not the one that happened", got)
	}
}

// TestEnforcement_UnsignedAfterSignedIsTampering is the half that makes writing
// unsigned acceptable.
//
// This is also the hole the latch was supposed to close and did not:
// HashAuditRow is unkeyed and takes only row content, so anyone able to write
// the table could append a fabricated row with a correctly recomputed hash, no
// signature, and seq 0. The verifier counted it as Unsigned and moved on — the
// sequence check ran only for signed rows — and Tampered() excluded Unsigned
// unconditionally, latch or no latch. `lv audit verify` printed "audit chain
// intact" and exited 0 over a fabricated authorisation.
func TestEnforcement_UnsignedAfterSignedIsTampering(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// The forgery: a row appended straight into the table, chained correctly
	// against the real tail, with no signature at all.
	prev := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r1'`)
	rec := AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T10:00:02Z", Username: "root", HostName: "node-0",
		Action: "user.grant", Target: "mallory:admin", Result: "success", PrevHash: prev,
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		                        result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', 0)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, HashAuditRow(rec)); err != nil {
		t.Fatalf("insert the forged row: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a fabricated row appended to a signing host's chain verified CLEAN: %+v\n"+
			"the content hash is unkeyed, so recomputing it costs an attacker nothing; the "+
			"absence of a signature is the only thing that distinguishes the row", res)
	}
	if len(res.UnsignedAfterSigned) == 0 {
		t.Fatalf("the forged row was not reported as an unsigned row after signing began: %+v", res)
	}
	if !strings.Contains(strings.Join(res.UnsignedAfterSigned, " "), "forged") {
		t.Errorf("findings %v do not name the forged row", res.UnsignedAfterSigned)
	}
}

// TestEnforcement_AnUnsignableWriteIsVisibleToTheVerifier joins the two halves.
//
// Degrading to unsigned is only defensible if the degradation cannot be quiet.
// A node that loses its key mid-life must leave a finding every other node can
// see, or "write it unsigned" becomes the off switch the refusal was guarding
// against.
func TestEnforcement_AnUnsignableWriteIsVisibleToTheVerifier(t *testing.T) {
	ctx := context.Background()
	c, _, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// The private key becomes unreadable — the node keeps the cluster CA, so it
	// can still VERIFY every published certificate, it just cannot sign. That is
	// what an attacker achieves with one chmod, and it is also what a peer sees.
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)
	requireSigning(c)

	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "r2", Username: "root", HostName: "node-0",
		Action: "vm.delete", Target: "prod-db", Result: "success",
		Timestamp: "2026-07-29T10:00:02Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a node that lost its key kept writing rows and the log still verifies "+
			"clean: %+v\nmaking one file unreadable would switch tamper-evidence off", res)
	}
	if len(res.UnsignedAfterSigned) != 1 {
		t.Fatalf("want exactly the one unsignable row reported, got %v", res.UnsignedAfterSigned)
	}
}

// TestEnforcement_LegacyHistoryIsNotTampering is the false-alarm guard.
//
// Every cluster that upgrades into signing has a long unsigned history, and it
// is not evidence of anything. Flagging it would put a permanent tamper verdict
// on the whole fleet the day the feature is enabled — protection that only
// produces noise gets switched off, which is why the finding is keyed to a
// per-host boundary rather than to the cluster latch.
func TestEnforcement_LegacyHistoryIsNotTampering(t *testing.T) {
	c := newAuditTestClient(t) // unsigned, like every pre-v45 row
	for _, id := range []string{"r1", "r2", "r3"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}
	requireSigning(c) // the operator turns enforcement on over that history

	res := verify(t, c)
	if res.Tampered() {
		t.Fatalf("a wholly pre-enforcement log is reported as tampered: %+v\n"+
			"turning the feature on must not accuse an operator of editing their own "+
			"history, or the first thing they do is turn it back off", res)
	}
	if res.Unsigned != 3 {
		t.Errorf("want the 3 legacy rows still COUNTED as unsigned, got %d", res.Unsigned)
	}
}

// TestEnforcement_APrependedRowCannotEscapeTheContract.
//
// The verdict used to latch on the host's own history — "has this host signed a
// row yet?" — accumulated as the walk went. The walk is ordered by (host,
// timestamp, id), and the timestamp is whatever the writer put there. So the
// fabricated row did not have to defeat the check; it just had to sort ahead of
// it.
//
// Worse, a blank content_hash reads as a pre-chain reset point, which the walk
// accepted before the host's first hashed row. Backdate a row, blank its hash,
// and it was not counted as unsigned, not reported as laundered, and did not
// break the chain — while sitting in `lv audit log` output looking exactly like
// a genuine record.
func TestEnforcement_APrependedRowCannotEscapeTheContract(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// Prepended: timestamp older than anything real, blank hash, no signature.
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		                        result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES ('prepended', '2020-01-01T00:00:00Z', 'root', 'node-0', 'user.grant',
		         'mallory:admin', '', 'success', '', '', '', '', 0)`); err != nil {
		t.Fatalf("insert the prepended row: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a row backdated ahead of the host's history verified CLEAN: %+v\n"+
			"the fabricated row never had to defeat the check, only to sort before it", res)
	}
}

// TestEnforcement_AHostThatNeverSignedIsStillCovered.
//
// The case a history-based rule structurally cannot see. A node joins a cluster
// that is already signing, its key is unreadable on the very first start, and it
// therefore never produces a single signed row. Asking "has this host signed
// before?" answers no forever, so every row it writes was pre-enforcement
// history as far as the verifier was concerned — an entire node's audit log
// unsigned, freely rewritable, and reported clean on every peer.
//
// The published certificate is what covers it: the host declared the contract
// even though it could not then honour it.
func TestEnforcement_AHostThatNeverSignedIsStillCovered(t *testing.T) {
	ctx := context.Background()
	c, kr, dir := signedClient(t, "node-0")

	// The contract exists — the certificate is published — but this node cannot
	// sign, so it never produces a signed row at all.
	if kr.KeyID() == "" {
		t.Fatal("no certificate published; the contract under test does not exist")
	}
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)
	requireSigning(c)

	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "r1", Username: "root", HostName: "node-0",
		Action: "vm.delete", Target: "prod-db", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	if n := countRows(t, c, `SELECT id FROM audit_log WHERE signature <> ''`); n != 0 {
		t.Fatalf("this host signed something; the never-signed case is not under test")
	}

	res := verify(t, c)
	if len(res.UnsignedAfterSigned) == 0 {
		t.Fatalf("a host with a published certificate wrote an unsigned row and nothing was "+
			"reported: %+v\nit never signed anything, so a rule keyed to its own history "+
			"could never fire — which is the whole case", res)
	}
}

// TestEnforcement_ADegradedWindowIsNotASequenceGap.
//
// A node loses read access to its key for a few writes and recovers. Those rows
// still consume sequence numbers, because InsertAuditLog assigns seq before it
// signs. Counting only SIGNED rows made the next signed row look like it had
// jumped — reported under SeqGaps, a category documented as evidence that rows
// were deleted and renumbered to hide it. Nobody had touched a thing.
func TestEnforcement_ADegradedWindowIsNotASequenceGap(t *testing.T) {
	c, kr, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// Key unreadable for two writes.
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)
	requireSigning(c)
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	ins(t, c, "r3", "node-0", "2026-07-29T10:00:03Z")

	// Recovered.
	c.SetAuditKeyring(kr)
	ins(t, c, "r4", "node-0", "2026-07-29T10:00:04Z")

	res := verify(t, c)
	if len(res.SeqGaps) > 0 {
		t.Fatalf("a degraded write window was reported as a sequence gap: %v\n"+
			"seq is assigned before signing, so unsigned rows consume numbers too — "+
			"the verifier has to count the same way the writer does", res.SeqGaps)
	}
	// The degradation itself must still be reported, or this test would pass by
	// the verifier having gone blind.
	if len(res.UnsignedAfterSigned) != 2 {
		t.Fatalf("want the 2 unsignable rows reported, got %v", res.UnsignedAfterSigned)
	}
}

// TestEnforcement_LegacyRowsAreNotASequenceGap.
//
// Found on the lab, not in any unit test. seq was added at v45 with DEFAULT 0,
// so every row written before then carries 0 — that is a "no sequence"
// sentinel, not a numbering. Once the verifier started comparing seq on every
// row rather than only signed ones, each legacy row produced a "seq 0 after 0"
// finding, under a heading that says rows were deleted from the chain.
//
// On the four-node lab that was several hundred findings on the first verify
// after upgrading, on a log nobody had touched.
func TestEnforcement_LegacyRowsAreNotASequenceGap(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Pre-v45 rows: hashed, unsigned, seq 0 — what an upgraded cluster holds.
	prev := ""
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		rec := AuditRecord{
			ID: id, Timestamp: "2026-07-29T10:00:0" + id[1:] + "Z", Username: "u",
			HostName: "node-0", Action: "vm.start", Target: "x", Result: "ok", PrevHash: prev,
		}
		rec.ContentHash = HashAuditRow(rec)
		if err := c.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			                        result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', 0)`,
			rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
			rec.Result, rec.PrevHash, rec.ContentHash); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		prev = rec.ContentHash
	}

	res := verify(t, c)
	if len(res.SeqGaps) > 0 {
		t.Fatalf("pre-v45 rows were reported as deleted-and-renumbered: %v\n"+
			"seq 0 is the sentinel every legacy row carries, so comparing it produces one "+
			"finding per row on the first verify after an upgrade", res.SeqGaps)
	}
	if res.Tampered() {
		t.Fatalf("an untouched legacy log reports tampering: %+v", res)
	}
}

// TestEnforcement_HistoryBeforeTheContractIsNotTampering.
//
// Found on the lab, immediately after the certificate contract shipped. Every
// cluster that turns signing on has history behind it, and publishing a
// certificate said nothing about WHEN — so the contract reached backwards over
// all of it and the first verify reported hundreds of rows as tampering on a log
// nobody had touched.
//
// That is the fastest way to teach an operator to ignore the command, which
// makes it worse than the hole it was closing. Adoption is a signed record with
// a sequence, so the contract has a start.
func TestEnforcement_HistoryBeforeTheContractIsNotTampering(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Pre-enforcement history, written with no keyring at all.
	for _, id := range []string{"r1", "r2", "r3"} {
		ins(t, c, id, "node-0", "2026-07-29T10:00:0"+id[1:]+"Z")
	}

	// The operator turns signing on: the daemon loads a keyring, publishes, and
	// records where the contract begins.
	dir := testPKI(t, "node-0")
	kr, err := LoadAuditKeyring(dir, "node-0")
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(ctx, c, kr, "node-0"); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	ins(t, c, "r4", "node-0", "2026-07-29T10:00:04Z") // signed

	res := verify(t, c)
	if len(res.UnsignedAfterSigned) > 0 {
		t.Fatalf("pre-contract history was reported as tampering: %v\n"+
			"a certificate says a host commits, not when — without the start, enabling "+
			"signing accuses the operator of editing their own log", res.UnsignedAfterSigned)
	}
	if res.Tampered() {
		t.Fatalf("an untouched log reports tampering after enabling signing: %+v", res)
	}
	if res.Unsigned != 3 {
		t.Errorf("want the 3 pre-contract rows still COUNTED as unsigned, got %d", res.Unsigned)
	}

	// And the contract still bites for anything written after it.
	prev := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r4'`)
	rec := AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T10:00:05Z", Username: "root", HostName: "node-0",
		Action: "user.grant", Target: "mallory:admin", Result: "success", PrevHash: prev,
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		                        result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', 0)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, HashAuditRow(rec)); err != nil {
		t.Fatalf("insert the forged row: %v", err)
	}
	if res := verify(t, c); len(res.UnsignedAfterSigned) == 0 {
		t.Fatalf("a row appended after the contract started was excused: %+v\n"+
			"giving the contract a start must not give an attacker one too", res)
	}
}
