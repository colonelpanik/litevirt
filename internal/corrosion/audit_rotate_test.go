package corrosion

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// Key rotation.
//
// Rotation is the answer to a key that may have leaked — and one did: `lv host
// init root@<host>` shipped host.key mode 0644 on every node it provisioned.
// Tightening the mode does not undo a copy already taken, so the operator needs
// to be able to replace the key and have the old one stop counting.

// rotateTo swaps in a NEW CA-signed certificate and key for hostName, the way
// `lv host rotate-key` does on disk, and reloads the keyring from the same
// directory. Returns the new keyring.
//
// The CA is reused, not regenerated: a rotated host certificate must still
// chain to the same cluster CA or every peer would reject the host outright.
func rotateTo(t *testing.T, c *Client, dir, hostName string) *AuditKeyring {
	t.Helper()
	if err := regenHostCert(dir, hostName); err != nil {
		t.Fatalf("re-mint host cert: %v", err)
	}
	kr, err := LoadAuditKeyring(dir, hostName)
	if err != nil {
		t.Fatalf("LoadAuditKeyring after rotation: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(context.Background(), c, kr, hostName); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	return kr
}

// TestRotation_OldKeyCannotSignNewRows.
//
// The point of rotating. Someone who took a copy of the old key can still
// produce signatures with it — nothing can stop that — so what has to happen is
// that those signatures stop being ACCEPTED for rows beyond the rotation.
func TestRotation_OldKeyCannotSignNewRows(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	oldKeyID := oldKR.KeyID()
	newKR := rotateTo(t, c, dir, "node-0")
	if newKR.KeyID() == oldKeyID {
		t.Fatal("rotation produced the same key id; nothing was actually rotated and every " +
			"assertion below would pass vacuously")
	}

	// The old key must be recorded as retired, and its certificate must still be
	// present — the rows it already signed depend on it.
	if n := countRows(t, c, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldKeyID+`'`); n != 1 {
		t.Fatalf("old key %s is not marked retired (%d matching rows)", oldKeyID, n)
	}

	// A new row signed with the CURRENT key is fine.
	ins(t, c, "r3", "node-0", "2026-07-29T10:00:03Z")
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("a clean log reports tampering right after rotation: %+v", res)
	}

	// The attacker still holds the old key and appends a row with it.
	forgeRow(t, c, oldKR, "forged", "node-0", "2026-07-29T10:00:04Z", 4)

	res := verify(t, c)
	if len(res.RetiredKeyUse) == 0 {
		t.Fatalf("a row signed with the RETIRED key was accepted: %+v\n"+
			"rotation that does not retire the old key changes which key signs new rows "+
			"and protects nothing", res)
	}
	if !strings.Contains(strings.Join(res.RetiredKeyUse, " "), "forged") {
		t.Errorf("findings %v do not name the forged row", res.RetiredKeyUse)
	}
	if !res.Tampered() {
		t.Errorf("retired-key use is not reported as tampering: %+v", res)
	}
}

// TestRotation_OldRowsStayVerifiableForever is the property that breaks if
// retirement is implemented as deletion.
//
// Every row the old key signed depends on the old certificate remaining
// resolvable. Tombstoning it on rotation would make all of that history
// unverifiable — a change made to IMPROVE integrity would destroy the record it
// was protecting, and it would look like mass tampering the moment anyone ran
// the check.
func TestRotation_OldRowsStayVerifiableForever(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	oldKeyID := oldKR.KeyID()

	rotateTo(t, c, dir, "node-0")
	ins(t, c, "r3", "node-0", "2026-07-29T10:00:03Z")

	res := verify(t, c)
	if res.Tampered() {
		t.Fatalf("rows signed before rotation stopped verifying: %+v\n"+
			"the retired certificate must stay resolvable for as long as any row it "+
			"signed exists", res)
	}
	if res.Unverifiable != 0 || res.Unsigned != 0 {
		t.Errorf("after rotation: unsigned=%d unverifiable=%d, want 0/0", res.Unsigned, res.Unverifiable)
	}
	// The rows really are still attributed to the old key — otherwise this test
	// would pass because they were somehow re-signed.
	if n := countRows(t, c, `SELECT id FROM audit_log WHERE key_id = '`+oldKeyID+`'`); n != 2 {
		t.Fatalf("%d rows still carry the old key id, want 2; they were re-signed rather "+
			"than verified against the retired certificate", n)
	}
}

// TestRotation_SealsTheOldKeysHistory is the part that actually defends the
// past, and the reason a timestamp comparison would not have been enough.
//
// Someone holding the old key can sign anything, including a row backdated to
// before the rotation, so "reject old-key rows dated after T" is decided by a
// value the attacker chooses. What they cannot do is forge a chain head signed
// with the NEW key. Rotation publishes one covering the whole existing log, so
// altering any row it covers contradicts a signature the attacker cannot make.
func TestRotation_SealsTheOldKeysHistory(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	newKR := rotateTo(t, c, dir, "node-0")

	// A head signed by the NEW key must now cover the rows the OLD key wrote.
	rows, err := c.Query(ctx,
		`SELECT key_id, seq FROM audit_chain_heads WHERE host_name = 'node-0' ORDER BY epoch DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("no chain head published at rotation: %v (rows=%d)\n"+
			"without it the old key's history is still rewritable by whoever holds that key",
			err, len(rows))
	}
	if got := rows[0].String("key_id"); got != newKR.KeyID() {
		t.Fatalf("the sealing head is signed by %s, want the NEW key %s; a head signed with "+
			"the compromised key seals nothing", got, newKR.KeyID())
	}
	if got := rows[0].Int64("seq"); got != 2 {
		t.Errorf("sealing head covers seq %d, want 2 (every row the old key wrote)", got)
	}

	// Now the attacker — holding ONLY the old key — rewrites a row it signed and
	// re-signs it, which they can do perfectly.
	if err := c.Execute(ctx,
		`UPDATE audit_log SET target = 'covered-up' WHERE id = 'r2'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	resignRow(t, c, oldKR, "r2", "node-0")

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a row rewritten and re-signed with the old key verified clean: %+v\n"+
			"the head signed by the new key is what should have caught it", res)
	}
}

// TestRotation_IsIdempotent — AdoptAuditKey runs on every daemon start, so a
// restart with an unchanged key must not retire anything, publish a head, or
// otherwise churn.
func TestRotation_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	for i := 0; i < 3; i++ {
		retiredKey, err := AdoptAuditKey(ctx, c, c.AuditKeyringOf(), "node-0")
		if err != nil {
			t.Fatalf("AdoptAuditKey pass %d: %v", i, err)
		}
		if retiredKey != "" {
			t.Fatalf("pass %d retired key %q with no rotation; every restart would retire "+
				"the key the node is actually using", i, retiredKey)
		}
	}
	if n := countRows(t, c, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired'`); n != 0 {
		t.Errorf("%d keys retired without a rotation", n)
	}
	if n := countRows(t, c, `SELECT host_name FROM audit_chain_heads`); n != 0 {
		t.Errorf("%d chain heads published by a no-op adopt; heads would grow without bound "+
			"across restarts", n)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func countRows(t *testing.T, c *Client, query string) int {
	t.Helper()
	rows, err := c.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return len(rows)
}

// forgeRow appends a well-formed, correctly-chained row signed with the given
// keyring — what an attacker in possession of a key can always do.
func forgeRow(t *testing.T, c *Client, kr *AuditKeyring, id, host, ts string, seq int64) {
	t.Helper()
	ctx := context.Background()
	prev := ""
	rows, err := c.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ? ORDER BY timestamp DESC, id DESC LIMIT 1`, host)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if len(rows) == 1 {
		prev = rows[0].String("content_hash")
	}
	rec := AuditRecord{
		ID: id, Timestamp: ts, Username: "root", HostName: host,
		Action: "user.delete", Target: "alice", Result: "ok", PrevHash: prev, Seq: seq,
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
		t.Fatalf("insert forged row: %v", err)
	}
}

// resignRow recomputes a row's hash from its CURRENT (edited) content and signs
// it with the given keyring — a complete, internally consistent forgery.
func resignRow(t *testing.T, c *Client, kr *AuditKeyring, id, host string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, seq
		 FROM audit_log WHERE id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %v (rows=%d)", id, err, len(rows))
	}
	r := rows[0]
	rec := AuditRecord{
		ID: r.String("id"), Timestamp: r.String("timestamp"), Username: r.String("username"),
		HostName: r.String("host_name"), Action: r.String("action"), Target: r.String("target"),
		Detail: r.String("detail"), Result: r.String("result"),
		PrevHash: r.String("prev_hash"), Seq: r.Int64("seq"),
	}
	rec.ContentHash = HashAuditRow(rec)
	sig, err := kr.SignRow(rec.ContentHash, rec.Seq)
	if err != nil {
		t.Fatalf("SignRow: %v", err)
	}
	if err := c.Execute(ctx,
		`UPDATE audit_log SET content_hash = ?, signature = ?, key_id = ? WHERE id = ?`,
		rec.ContentHash, sig, kr.KeyID(), id); err != nil {
		t.Fatalf("re-sign %s: %v", id, err)
	}
}

// regenHostCert installs a fresh DEDICATED audit signing pair under the SAME
// cluster CA — what `lv host rotate-audit-key` does on disk.
//
// The CA is reused, not regenerated: a rotated certificate that does not chain
// to the cluster CA would be rejected by every peer. It deliberately does NOT
// touch host.crt/host.key, because rotating the TLS identity of a running node
// is a much larger operation (serving TLS and the health checker both cache
// their certificates for the life of the process, and libvirt migration follows
// symlinks into the same files).
func regenHostCert(dir, hostName string) error {
	for _, f := range []string{pki.AuditSigningCertName, pki.AuditSigningKeyName} {
		p := filepath.Join(dir, f)
		if _, err := os.Stat(p); err == nil {
			if err := os.Chmod(p, 0o600); err != nil {
				return err
			}
		}
	}
	return pki.GenerateAuditSigningCert(
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, pki.AuditSigningCertName), filepath.Join(dir, pki.AuditSigningKeyName),
		hostName)
}

// TestRotation_ARetiredKeyCannotUnrotateItsSuccessor.
//
// The one who kept a copy of the old key is the reason rotation exists, so they
// are the party the mechanism has to survive. Booting a daemon with the old key
// back in place — a restored backup, a second instance, or a machine they still
// control — used to select "any other non-retired key for this host" as
// superseded, which after a rotation is the key that REPLACED it.
//
// The old key's retirement is a signed row that republishing cannot clear, so
// old key stayed retired and, in the same breath, retired its successor at the
// tail seq of the moment. Every row the legitimate key then signed sat past a
// retirement boundary: `lv audit verify` reported the live chain as tampered on
// every node, litevirt_audit_chain_last_verified_ok went to 0 cluster-wide, and
// the leaked key was the one still signing. Rotation was undoable by exactly the
// party it was performed against.
func TestRotation_ARetiredKeyCannotUnrotateItsSuccessor(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	newKR := rotateTo(t, c, dir, "node-0")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("the log is not clean after a legitimate rotation: %+v", res)
	}

	// The attacker puts the old key back and starts the daemon.
	c.SetAuditKeyring(oldKR)
	if _, err := AdoptAuditKey(ctx, c, oldKR, "node-0"); err != nil {
		t.Fatalf("AdoptAuditKey with the retired key: %v", err)
	}

	if n := countRows(t, c,
		`SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+newKR.KeyID()+`'`); n != 0 {
		t.Fatalf("booting with the RETIRED key retired its successor %s\n"+
			"every row the legitimate key signs is now past a retirement boundary, so the "+
			"whole live chain reads as tampered on every node — while the leaked key signs",
			newKR.KeyID())
	}
	if n := countRows(t, c,
		`SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldKR.KeyID()+`'`); n != 1 {
		t.Fatalf("the old key un-retired itself by being republished")
	}
}

// TestRotation_StillRetiresAGenuinelySupersededKey is the guard against fixing
// the above by simply never retiring anything.
func TestRotation_StillRetiresAGenuinelySupersededKey(t *testing.T) {
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	rotateTo(t, c, dir, "node-0")

	if n := countRows(t, c,
		`SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldKR.KeyID()+`'`); n != 1 {
		t.Fatalf("a genuine rotation did not retire the key it superseded; the whole " +
			"retired-key finding would never fire")
	}
}

// TestRotation_ARetiringKeyCannotRaiseItsOwnBoundary.
//
// The floor that keeps a stale replica from pinning a boundary too low must not
// become a lever for the party the retirement is aimed at.
//
// Someone holding a leaked key publishes a head for that host at an absurd
// sequence. It verifies — the key's certificate is still resolvable and names the
// host, which is exactly the situation rotation exists for. If that head counted
// toward the floor, the rotation would retire the leaked key at 10^9 instead of
// the real tail, and every row it forged afterwards would fall below the boundary
// with the RetiredKeyUse detection silently switched off.
//
// The floor therefore ignores heads signed by the keys being retired. What
// protects the honest stale-replica case instead is timing: the daemon defers
// every lifecycle record until replication is running (finishAuditKeyLifecycle),
// so the local tail is real by the time a boundary is taken from it.
func TestRotation_ARetiringKeyCannotRaiseItsOwnBoundary(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	// The leaked key asserts a wildly high position for its own host.
	tail := oneCol(t, c, `SELECT content_hash FROM audit_log WHERE id = 'r2'`)
	if err := insertAuditChainHead(ctx, c, oldKR, "node-0", 7, 1_000_000_000, tail); err != nil {
		t.Fatalf("publish the inflated head: %v", err)
	}

	rotateTo(t, c, dir, "node-0")

	got := oneCol(t, c,
		`SELECT at_seq FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = '`+oldKR.KeyID()+`'`)
	if got != "2" {
		t.Fatalf("retirement boundary is %q, want 2 — the real tail\n"+
			"a head signed by the key being retired is an assertion by the very party the "+
			"retirement is aimed at; counting it lets a leaked key set its own boundary and "+
			"switch off the detection rotation exists to provide", got)
	}
}

// rowsByID snapshots whole audit rows so a test can hand them back the way
// anti-entropy would.
func rowsByID(t *testing.T, c *Client, ids ...string) []map[string]string {
	t.Helper()
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		rows, err := c.Query(context.Background(),
			`SELECT id, timestamp, username, host_name, action, target, detail, result,
			        prev_hash, content_hash, key_id, signature, seq
			 FROM audit_log WHERE id = ?`, id)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read %s: %v (rows=%d)", id, err, len(rows))
		}
		r := rows[0]
		out = append(out, map[string]string{
			"id": r.String("id"), "timestamp": r.String("timestamp"),
			"username": r.String("username"), "host_name": r.String("host_name"),
			"action": r.String("action"), "target": r.String("target"),
			"detail": r.String("detail"), "result": r.String("result"),
			"prev_hash": r.String("prev_hash"), "content_hash": r.String("content_hash"),
			"key_id": r.String("key_id"), "signature": r.String("signature"),
			"seq": strconv.FormatInt(r.Int64("seq"), 10),
		})
	}
	return out
}

func restoreRows(t *testing.T, c *Client, rows []map[string]string) {
	t.Helper()
	for _, r := range rows {
		seq, _ := strconv.ParseInt(r["seq"], 10, 64)
		if err := c.Execute(context.Background(),
			`INSERT OR IGNORE INTO audit_log (id, timestamp, username, host_name, action, target,
			                                  detail, result, prev_hash, content_hash, key_id,
			                                  signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r["id"], r["timestamp"], r["username"], r["host_name"], r["action"], r["target"],
			r["detail"], r["result"], r["prev_hash"], r["content_hash"], r["key_id"],
			r["signature"], seq); err != nil {
			t.Fatalf("restore %s: %v", r["id"], err)
		}
	}
}

// headsFor returns every chain head recorded for a host.
func headsFor(t *testing.T, c *Client, host string) []AuditChainHead {
	t.Helper()
	byKey, err := latestAuditHeadsByKey(context.Background(), c)
	if err != nil {
		t.Fatalf("latestAuditHeadsByKey: %v", err)
	}
	return byKey[host]
}

// newKeyID is the key a host currently signs with.
func newKeyID(t *testing.T, c *Client, host string) string {
	t.Helper()
	id, _, err := ActiveAuditKeyID(context.Background(), c, c.AuditKeyringOf(), host)
	if err != nil {
		t.Fatalf("ActiveAuditKeyID: %v", err)
	}
	return id
}

// TestHostTailSeq_SeesRowsThatArrivedByReplication.
//
// The tail cache is a write-path structure: it advances when THIS node appends,
// and nothing invalidates it when corrosion delivers rows written elsewhere. Every
// boundary decision — adoption start, retirement boundary, the lagging-replica
// refusal — asks for a REMOTE host's tail, so reading the cache means reading a
// snapshot taken at some arbitrary earlier moment.
//
// The lab hit exactly this: node-1's cache said node-3 ended at 5, replication
// delivered 6, 7 and 8, and the cache still said 5 until the daemon restarted.
func TestHostTailSeq_SeesRowsThatArrivedByReplication(t *testing.T) {
	ctx := context.Background()
	c, _, _ := signedClient(t, "node-0")

	// Ask about the peer first, which is what populates the cache — here with the
	// honest answer that this node holds nothing of node-9's chain.
	before, err := HostTailSeq(ctx, c, "node-9")
	if err != nil {
		t.Fatalf("HostTailSeq: %v", err)
	}
	if before != 0 {
		t.Fatalf("this node should hold none of node-9's chain, got tail %d", before)
	}

	// Replication delivers three of node-9's rows. It does not go through
	// InsertAuditLog, so the cache learns nothing.
	for i, seq := range []int64{6, 7, 8} {
		if err := c.Execute(ctx,
			`INSERT INTO audit_log
			   (id, timestamp, username, host_name, action, target, detail, result,
			    prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, 'root', 'node-9', 'vm.start', 'vm1', '', 'ok', '', ?, '', '', ?)`,
			fmt.Sprintf("replicated-%d", i),
			fmt.Sprintf("2026-07-29T11:00:0%dZ", i),
			fmt.Sprintf("hash%d", seq), seq); err != nil {
			t.Fatalf("simulate replicated row: %v", err)
		}
	}

	after, err := HostTailSeq(ctx, c, "node-9")
	if err != nil {
		t.Fatalf("HostTailSeq: %v", err)
	}
	if after != 8 {
		t.Fatalf("node-9's tail reads %d after replication delivered rows 6, 7 and 8\n"+
			"a retirement computed from this pins a permanent boundary %d rows below what "+
			"the host legitimately signed", after, 8-after)
	}
}
