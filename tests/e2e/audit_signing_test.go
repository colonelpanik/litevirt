package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Audit tamper-evidence against a live cluster.
//
// The fleet tests build their PKI in a temp directory and drive corrosion
// directly, so they prove the cryptography and the merge rules but say nothing
// about the two things that actually decide whether this works in production:
// whether the daemon can read the key material `lv host init` laid down on a
// real node, and whether the private key is protected on disk. A signing scheme
// whose key is world-readable is theatre — anyone who can read the file can
// forge the whole log — and no in-process test can see the file mode.
//
// These run on a cluster node (localMode) because they read the daemon's PKI
// directory and its database. From a workstation there is nothing to inspect,
// so they skip rather than pretend.

// auditPKIDir is where a node keeps its cluster identity, which is also its
// audit signing key. Matches pki_dir in the daemon config.
const auditPKIDir = "/etc/litevirt/pki"

func requireLocalNode(t *testing.T) {
	t.Helper()
	if !localMode {
		t.Skip("audit signing inspects the node's PKI dir and database; run on a cluster node")
	}
}

// thisHost is the name of the node the suite is running on.
//
// It does NOT read the package-level localHost, which TestSetup fills in: Go
// orders tests by filename, so this file runs BEFORE e2e_test.go and would see
// an empty string. That produced a confusing failure ("host \"\" has 0
// published signing certificates") that looked like a product bug and was
// purely test ordering.
func thisHost(t *testing.T) string {
	t.Helper()
	if localHost != "" {
		return localHost
	}
	data, err := os.ReadFile("/etc/litevirt/config.yaml")
	if err != nil {
		t.Skipf("cannot read the daemon config to learn this host's name: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "host_name:"); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	t.Skip("no host_name in the daemon config")
	return ""
}

// TestAuditSigningKeyIsNotReadableByOthers.
//
// The audit signature is only worth the secrecy of host.key. If any local user
// can read it they can sign rows as this host, and every peer will accept them
// — the certificate chains to the cluster CA and the CN matches, so nothing
// downstream has any reason to object. This is the one property of the whole
// design that lives in the filesystem rather than the code.
func TestAuditSigningKeyIsNotReadableByOthers(t *testing.T) {
	requireLocalNode(t)
	keyPath := filepath.Join(auditPKIDir, "host.key")
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Skipf("no host key at %s: %v", keyPath, err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("%s is mode %04o; group/other can read the audit signing key, so any local "+
			"user can forge audit rows for this host and every peer will accept them", keyPath, mode)
	}
}

// TestAuditVerifyReportsSigningState pins what `lv audit verify` tells an
// operator on a live cluster.
//
// The output has to be unambiguous in both directions: a clean log must not be
// reported in a way that can be mistaken for a finding, and unsigned rows must
// be visible without being called tampering. A cluster upgrading to v45 has a
// log full of unsigned rows, and if those read as an alarm operators learn to
// ignore the command entirely.
func TestAuditVerifyReportsSigningState(t *testing.T) {
	out, err := lvErr(t, "audit", "verify")
	if err != nil {
		if !strings.Contains(out, "TAMPERED") {
			t.Fatalf("audit verify failed for a reason other than a finding: %v\n%s", err, out)
		}
		t.Fatalf("the live cluster's audit chain reports tampering:\n%s", out)
	}
	if !strings.Contains(out, "audit chain intact") {
		t.Fatalf("audit verify succeeded but did not say the chain is intact:\n%s", out)
	}
	if strings.Contains(out, "TAMPERED") {
		t.Fatalf("a clean verify printed the tampering headline:\n%s", out)
	}
	t.Logf("audit verify: %s", strings.TrimSpace(out))
}

// TestAuditRowsAreSignedWhenEnforcementIsOn.
//
// This is the end-to-end wiring check the fleet cannot make: config flag →
// daemon loads the key laid down by `lv host init` → a real audited action
// through the real CLI lands a row carrying a signature and a key id.
//
// It performs an action rather than reading old rows, because the log is full
// of rows written before signing was enabled and finding one of those proves
// nothing. If signing is off on this node the test skips — that is a
// configuration choice, not a defect.
func TestAuditRowsAreSignedWhenEnforcementIsOn(t *testing.T) {
	requireLocalNode(t)
	if !auditSigningEnabled(t) {
		t.Skip("enforcement.audit_signature is off on this node")
	}

	project := "/e2e-audit-" + strconv.Itoa(os.Getpid())
	lv(t, "project", "create", project)
	t.Cleanup(func() { _, _ = lvErr(t, "project", "rm", project) })

	// The action must have produced a signed row attributed to this host.
	got := auditQuery(t, `SELECT count(*) FROM audit_log `+
		`WHERE target = '`+project+`' AND signature IS NOT NULL AND signature <> '' AND key_id <> ''`)
	if got != "1" {
		t.Fatalf("creating %s produced %q signed audit rows, want 1; the daemon is not signing "+
			"even though enforcement.audit_signature is on — check that it can read %s",
			project, got, filepath.Join(auditPKIDir, "host.key"))
	}

	// And this host's verification certificate must be published, or no peer
	// could ever check the row that was just written.
	host := thisHost(t)
	if n := auditQuery(t, `SELECT count(*) FROM audit_signing_keys WHERE host_name = '`+host+`'`); n != "1" {
		t.Fatalf("host %s has %q published signing certificates, want 1; its rows are signed but "+
			"unverifiable by every other node", host, n)
	}
}

// TestAuditChainHeadIsPublished.
//
// A head is the only thing that can detect a truncated tail — the hash chain
// links backward, so cutting the last rows leaves every surviving link
// verifying. The daemon publishes one at startup and every five minutes; a node
// that has written signed rows but published no head has lost that detection
// silently, which is exactly the failure this asserts against.
func TestAuditChainHeadIsPublished(t *testing.T) {
	requireLocalNode(t)
	if !auditSigningEnabled(t) {
		t.Skip("enforcement.audit_signature is off on this node")
	}
	host := thisHost(t)
	signed := auditQuery(t, `SELECT count(*) FROM audit_log WHERE host_name = '`+host+
		`' AND signature IS NOT NULL AND signature <> ''`)
	if signed == "0" {
		t.Skipf("host %s has written no signed rows yet; a head over an empty chain asserts nothing", host)
	}
	if n := auditQuery(t, `SELECT count(*) FROM audit_chain_heads WHERE host_name = '`+host+`'`); n == "0" {
		t.Fatalf("host %s has %s signed rows but has published no chain head; truncating its log "+
			"would leave every remaining link verifying and nothing would notice", host, signed)
	}
}

// auditSigningEnabled reports whether this node's config turns signing on.
func auditSigningEnabled(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile("/etc/litevirt/config.yaml")
	if err != nil {
		t.Skipf("cannot read the daemon config: %v", err)
	}
	return strings.Contains(string(data), "audit_signature: true")
}

// auditQuery reads a single scalar out of the node's state database.
//
// It goes to the database rather than the CLI on purpose: the point is to check
// what was actually STORED, and asking litevirt whether litevirt did the thing
// is exactly the shortcut this suite exists to avoid.
func auditQuery(t *testing.T, query string) string {
	t.Helper()
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not available on this node; cannot inspect stored rows directly")
	}
	out, err := exec.Command(sqlite, "/var/lib/litevirt/state.db", query).Output()
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return strings.TrimSpace(string(out))
}
