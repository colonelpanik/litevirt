package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// Removing a host tombstones its row and nothing else. The certificate it holds
// still chains to the cluster CA, so peer trust — which now falls back to the
// certificate for a host it has no row for — depends entirely on that tombstone
// reaching every node. A node that never receives it keeps accepting a peer the
// operator decommissioned, and nothing says so.
//
// The CRL is the second, independent mechanism, and every piece of it already
// existed: pki.AppendToCRL, a crl.pem the daemon re-reads on mtime change, and a
// health check that publishes each node's CRL version and warns on a mismatch.
// Nothing called them.

func TestRevokeHostCert_AddsTheSerialToTheCRL(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("revokeHostCert: %v", err)
	}
	serials, err := pki.LoadCRL(filepath.Join(dir, "crl.pem"))
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	found := false
	for _, s := range serials {
		if strings.EqualFold(s, "a1b2c3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the removed host's serial is not in the CRL (%v)\n"+
			"removal then rests solely on the tombstone reaching every node, and a node "+
			"that misses it keeps accepting a decommissioned peer", serials)
	}

	// Revoking again must not fail or duplicate — `lv host rm` is re-runnable.
	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if again, _ := pki.LoadCRL(filepath.Join(dir, "crl.pem")); len(again) != len(serials) {
		t.Errorf("re-revoking duplicated the entry: %v -> %v", serials, again)
	}
}

// TestRevokeHostCert_WithoutTheCAKeySaysSo — `lv host rm` may be run from a node
// that holds no CA private key. That cannot silently skip revocation.
func TestRevokeHostCert_WithoutTheCAKeySaysSo(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("remove ca.key: %v", err)
	}
	err := revokeHostCert(dir, "node-9", "a1b2c3")
	if err == nil {
		t.Fatal("revocation without the CA private key reported success")
	}
	// The bare signing failure already errors, so the explicit check only earns its
	// place by saying WHICH machine can do this — otherwise the operator is told a
	// file is missing without being told where the one that matters lives.
	if !strings.Contains(err.Error(), "lv host init") {
		t.Errorf("the error does not point at the machine holding the CA: %v", err)
	}
}

// TestRevokeHostCert_NoSerialIsNotAnError — a host record with no cert serial
// (pre-v45 rows carry "unknown") must not turn a successful removal into a failure.
func TestRevokeHostCert_NoSerialIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	for _, serial := range []string{"", "unknown"} {
		if err := revokeHostCert(dir, "node-9", serial); err != nil {
			t.Errorf("serial %q should be skipped, not fail the removal: %v", serial, err)
		}
	}
}
