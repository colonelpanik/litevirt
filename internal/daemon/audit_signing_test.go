package daemon

import (
	"context"
	"net"
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
		`SELECT count(*) AS n FROM audit_key_retirements WHERE retired_key_id = ?`,
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
