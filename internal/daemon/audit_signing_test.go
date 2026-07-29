package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// `lv host rotate-audit-key` is an incident response: it is run when a host's
// signing key MAY BE IN SOMEONE ELSE'S HANDS, and it told the operator their old
// key had been retired at the sequence its chain had reached and the history it
// wrote sealed under the new key.
//
// On a host with enforcement.audit_signature off — the default, and the state of
// any cluster that has not opted in — none of that happened. The entire adoption
// path hung off that flag, so the restart published no certificate, retired
// nothing and wrote no sealing head, while the command still exited 0 with the
// success text. The operator closed the incident and the leaked key remained the
// only published signing identity, with nothing sealing what it wrote.
//
// Adoption is now unconditional once the dedicated pair is on disk. Installing
// it is an explicit operator act with exactly one cause, and sealing the
// superseded key's history is the entire point of the exercise. What the flag
// still decides — and must keep deciding — is whether this host SIGNS new rows.

func auditPKIDir(t *testing.T, hostName string) string {
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

func auditTestDaemon(t *testing.T, pkiDir, hostName string) *Daemon {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Daemon{cfg: &Config{PKIDir: pkiDir, HostName: hostName}, db: db}
}

// TestRotation_CompletesWithEnforcementOff is the whole finding.
func TestRotation_CompletesWithEnforcementOff(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	dir := auditPKIDir(t, host)
	d := auditTestDaemon(t, dir, host)

	// The host has been signing with its TLS identity — the bootstrap case, and
	// the key `lv host rotate-audit-key` exists to replace.
	if err := d.setupAuditSigning(ctx); err != nil {
		t.Fatalf("setupAuditSigning: %v", err)
	}
	leaked := d.db.AuditKeyringOf().KeyID()
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID: "r1", Username: "admin", HostName: host,
		Action: "vm.create", Target: "vm1", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	// The operator rotates. That is all the command does on disk.
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, pki.AuditSigningCertName),
		filepath.Join(dir, pki.AuditSigningKeyName), host); err != nil {
		t.Fatalf("GenerateAuditSigningCert: %v", err)
	}

	// The restart, on a node whose enforcement.audit_signature is OFF.
	fresh := auditTestDaemon(t, dir, host)
	fresh.db = d.db // same cluster database
	if err := fresh.completeAuditKeyRotation(ctx); err != nil {
		t.Fatalf("completeAuditKeyRotation: %v", err)
	}

	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = ?`,
		leaked); n != 1 {
		t.Fatalf("the leaked key %s was not retired on a host with enforcement off\n"+
			"the command reported the incident closed; it was not", leaked)
	}
	newKR, err := corrosion.LoadAuditKeyring(dir, host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	if newKR.KeyID() == leaked {
		t.Fatal("the rotation produced the same key id; every assertion here is vacuous")
	}
	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_signing_keys WHERE key_id = ?`, newKR.KeyID()); n != 1 {
		t.Fatalf("the new certificate was never published, so no peer can verify anything "+
			"this host signs from now on")
	}
	// The seal: a head signed by the NEW key over everything the old one wrote.
	// Without it, the holder of the leaked key can still rewrite that history.
	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_chain_heads WHERE host_name = ? AND key_id = ?`,
		host, newKR.KeyID()); n != 1 {
		t.Fatalf("no chain head signed by the new key seals what the leaked key wrote")
	}
}

// TestRotation_WithEnforcementOffDoesNotStartSigning keeps the fix from
// quietly turning on the feature the flag exists to gate.
//
// enforcement.audit_signature is a fleet-uniformity latch driver: a node that
// began signing because someone rotated its key would advertise nothing and
// change the shape of the log without the operator asking.
func TestRotation_WithEnforcementOffDoesNotStartSigning(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	dir := auditPKIDir(t, host)
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, pki.AuditSigningCertName),
		filepath.Join(dir, pki.AuditSigningKeyName), host); err != nil {
		t.Fatalf("GenerateAuditSigningCert: %v", err)
	}
	d := auditTestDaemon(t, dir, host)
	if err := d.completeAuditKeyRotation(ctx); err != nil {
		t.Fatalf("completeAuditKeyRotation: %v", err)
	}

	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID: "r1", Username: "admin", HostName: host,
		Action: "vm.create", Target: "vm1", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_log WHERE id = 'r1' AND signature <> ''`); n != 0 {
		t.Fatal("a host with enforcement.audit_signature off started signing because its " +
			"audit key was rotated; the flag is the operator's decision, not the rotation's")
	}
	// But it must be able to VERIFY, because the rotation command's own last line
	// tells the operator to run `lv audit verify` — and a node with no keyring
	// reports every signed row as unverifiable, which confirms nothing.
	if d.db.AuditKeyringOf() == nil {
		t.Fatal("a non-signing host was left with no keyring at all, so `lv audit verify` " +
			"there cannot check a single signature")
	}
}

func auditCount(t *testing.T, db *corrosion.Client, query string, args ...interface{}) int {
	t.Helper()
	rows, err := db.Query(context.Background(), query, args...)
	if err != nil || len(rows) != 1 {
		t.Fatalf("query %q: %v (rows=%d)", query, err, len(rows))
	}
	return rows[0].Int("n")
}

// TestShouldCompleteAuditKeyRotation pins the decision daemon.Run makes at
// startup. The truth table is the fix: the "flag off, dedicated pair present"
// cell used to be false, and that single cell is what made
// `lv host rotate-audit-key` a no-op reporting success on a default cluster.
func TestShouldCompleteAuditKeyRotation(t *testing.T) {
	withPair := auditPKIDir(t, "node-0")
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(withPair, "ca.crt"), filepath.Join(withPair, "ca.key"),
		filepath.Join(withPair, pki.AuditSigningCertName),
		filepath.Join(withPair, pki.AuditSigningKeyName), "node-0"); err != nil {
		t.Fatalf("GenerateAuditSigningCert: %v", err)
	}
	withoutPair := auditPKIDir(t, "node-0")

	for _, tc := range []struct {
		name    string
		enforce bool
		pkiDir  string
		want    bool
		why     string
	}{
		{"flag off, rotated", false, withPair, true,
			"the rotation would silently do nothing while the command reports the leaked key retired"},
		{"flag off, never rotated", false, withoutPair, false,
			"a host that was never rotated has nothing to adopt"},
		{"flag on, rotated", true, withPair, false,
			"setupAuditSigning already adopts on this path; doing it twice would publish twice"},
		{"flag on, never rotated", true, withoutPair, false,
			"setupAuditSigning handles the bootstrap TLS identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{PKIDir: tc.pkiDir}
			cfg.Enforcement.AuditSignature = tc.enforce
			if got := shouldCompleteAuditKeyRotation(cfg); got != tc.want {
				t.Errorf("shouldCompleteAuditKeyRotation = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestSigning_AnUnreadableKeyStillPublishesTheContract.
//
// The worst of the three possible outcomes was the one that used to happen. A
// host configured to sign, whose private key will not load, published NOTHING —
// so it looked exactly like a host that was never meant to sign, and its entire
// audit log read as ordinary pre-enforcement history: unsigned, freely
// rewritable, and clean on every peer.
//
// "The key is unreadable" is precisely the state an attacker arranges with one
// chmod, so it is the state that must not go unnoticed. The certificate is
// public and does not need the key, so publishing it puts the host under
// contract and every unsigned row it writes becomes evidence.
func TestSigning_AnUnreadableKeyStillPublishesTheContract(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	dir := auditPKIDir(t, host)
	d := auditTestDaemon(t, dir, host)

	// Corrupt the private key, leaving the certificate intact.
	if err := os.WriteFile(filepath.Join(dir, "host.key"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("corrupt the key: %v", err)
	}

	if err := d.setupAuditSigning(ctx); err == nil {
		t.Fatal("setupAuditSigning reported success with an unloadable key")
	}

	if n := auditCount(t, d.db, `SELECT count(*) AS n FROM audit_signing_keys WHERE host_name = ?`, host); n != 1 {
		t.Fatalf("no certificate was published for a host that is configured to sign (%d rows)\n"+
			"without it the host's unsigned rows are indistinguishable from a cluster that "+
			"never enabled signing at all", n)
	}

	// And the contract bites: a row written now is reported, not excused.
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID: "r1", Username: "root", HostName: host,
		Action: "vm.delete", Target: "prod-db", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	res, err := corrosion.VerifyAuditChain(ctx, d.db)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if len(res.UnsignedAfterSigned) == 0 {
		t.Fatalf("an unsigned row from a host under contract was not reported: %+v", res)
	}
}

// TestRollback_SigningItselfOffIsRecordedNotReportedAsTampering.
//
// enforcement.audit_signature is documented as a reversible kill switch, but the
// published certificate is a cluster-wide declaration that this host's rows are
// signed — and a config edit on one machine cannot silently revoke it. Left
// standing, every row written after the rollback is reported as evidence on
// every node, permanently, for what was a legitimate operator action.
//
// So the rollback signs for itself. That is exactly the distinction the verifier
// needs and cannot otherwise make: a host that stopped deliberately still holds
// its key and can say so; a host whose key was taken away cannot. Both stop
// signing; only one can explain it.
func TestRollback_SigningItselfOffIsRecordedNotReportedAsTampering(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	dir := auditPKIDir(t, host)
	d := auditTestDaemon(t, dir, host)

	// Signing on: a contract and some signed history.
	if err := d.setupAuditSigning(ctx); err != nil {
		t.Fatalf("setupAuditSigning: %v", err)
	}
	keyID := d.db.AuditKeyringOf().KeyID()
	for _, id := range []string{"r1", "r2"} {
		if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
			ID: id, Username: "admin", HostName: host,
			Action: "vm.create", Target: "vm1", Result: "success",
			Timestamp: "2026-07-29T10:00:0" + id[1:] + "Z",
		}); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", id, err)
		}
	}

	// The operator turns the flag off and restarts.
	d.retireOwnAuditKeyOnRollback(ctx)

	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = ?`, keyID); n != 1 {
		t.Fatalf("turning signing off recorded no retirement (%d rows)\n"+
			"the certificate is still live, so every row from here on is reported as "+
			"tampering on every node — permanently, for a supported operator action", n)
	}

	// Rows written after the rollback are unsigned and must NOT be evidence.
	d.db.SetAuditKeyring(mustVerifier(t, dir))
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID: "r3", Username: "admin", HostName: host,
		Action: "vm.start", Target: "vm1", Result: "success",
		Timestamp: "2026-07-29T10:00:03Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog after rollback: %v", err)
	}
	res, err := corrosion.VerifyAuditChain(ctx, d.db)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.Tampered() {
		t.Fatalf("a signed rollback still reads as tampering: %+v\n"+
			"the operator turned a documented kill switch off; the log must record that, "+
			"not accuse them of editing it", res)
	}
	// The history the key DID sign stays verifiable — retirement is a window,
	// never a deletion.
	if len(res.UnknownKeyID) > 0 || res.RowsChecked != 3 {
		t.Fatalf("rows signed before the rollback stopped verifying: %+v", res)
	}
}

// TestRollback_WithoutTheKeyTheContractStaysInForce is the case the whole
// distinction exists for. A host that cannot sign a retirement cannot claim to
// have stopped deliberately — which is exactly the position an attacker who took
// the key away puts it in.
func TestRollback_WithoutTheKeyTheContractStaysInForce(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	dir := auditPKIDir(t, host)
	d := auditTestDaemon(t, dir, host)
	if err := d.setupAuditSigning(ctx); err != nil {
		t.Fatalf("setupAuditSigning: %v", err)
	}
	keyID := d.db.AuditKeyringOf().KeyID()

	// The key is taken away, then the flag goes off.
	if err := os.WriteFile(filepath.Join(dir, "host.key"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("corrupt the key: %v", err)
	}
	d.retireOwnAuditKeyOnRollback(ctx)

	if n := auditCount(t, d.db,
		`SELECT count(*) AS n FROM audit_key_lifecycle WHERE event = 'retired' AND key_id = ?`, keyID); n != 0 {
		t.Fatalf("a host that cannot sign produced a retirement anyway\n" +
			"then taking a host's key away would be a way to switch its contract off")
	}
	d.db.SetAuditKeyring(mustVerifier(t, dir))
	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		ID: "r1", Username: "root", HostName: host,
		Action: "vm.delete", Target: "prod-db", Result: "success",
		Timestamp: "2026-07-29T10:00:01Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	res, err := corrosion.VerifyAuditChain(ctx, d.db)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if len(res.UnsignedAfterSigned) == 0 {
		t.Fatalf("a host whose key was removed went quiet without a finding: %+v", res)
	}
}

func mustVerifier(t *testing.T, dir string) *corrosion.AuditKeyring {
	t.Helper()
	kr, err := corrosion.LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	return kr
}
