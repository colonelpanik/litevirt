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
