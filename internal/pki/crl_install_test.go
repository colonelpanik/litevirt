package pki

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crlFor mints a CRL revoking serials, signed by the CA in caDir, and returns its
// PEM without leaving it in caDir — so a test can hand it to InstallCRL the way
// replication would rather than by copying a file.
//
// Every mint in one test goes through the SAME scratch file, because that is what
// makes successive CRLs carry increasing numbers: nextCRLNumber reads the previous
// number out of the file it is writing, and a fresh directory per mint would hand
// two CRLs minted in the same second the same number. Real minting always appends
// to one crl.pem, so a per-mint directory would be testing a situation that cannot
// arise — and it silently defeated the ordering these tests are about.
func crlFor(t *testing.T, caCert, caKey string, serials ...string) []byte {
	t.Helper()
	scratch := filepath.Join(mintDir(t), "minted.pem")
	if err := GenerateCRL(caCert, caKey, scratch, serials); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	pemBytes, err := os.ReadFile(scratch)
	if err != nil {
		t.Fatalf("read minted CRL: %v", err)
	}
	return pemBytes
}

// mintDir returns one scratch directory per test, created on first use.
func mintDir(t *testing.T) string {
	t.Helper()
	if d, ok := mintDirs[t.Name()]; ok {
		return d
	}
	d := t.TempDir()
	mintDirs[t.Name()] = d
	t.Cleanup(func() { delete(mintDirs, t.Name()) })
	return d
}

var mintDirs = map[string]string{}

func TestInstallCRL_InstallsACRLSignedByOurCA(t *testing.T) {
	caCert, caKey, dir := setupCA(t)

	version, installed, err := InstallCRL(dir, crlFor(t, caCert, caKey, "1a2b"))
	if err != nil {
		t.Fatalf("InstallCRL: %v", err)
	}
	if !installed {
		t.Fatal("a node with no CRL at all did not install the one it was given")
	}
	if version <= 0 {
		t.Fatalf("installed CRL reported version %d", version)
	}
	if !IsCertRevoked(dir, big.NewInt(0x1a2b)) {
		t.Fatal("serial 1a2b is not revoked after installing a CRL that revokes it")
	}
}

// A CRL arrives over replication, so any peer can put bytes in front of this — and
// the one with the strongest motive is the host whose certificate was just revoked.
// Only the cluster CA's signature separates a revocation from a wish.
func TestInstallCRL_RefusesACRLFromAnotherCA(t *testing.T) {
	_, _, dir := setupCA(t)
	otherCert, otherKey, _ := setupCA(t)

	_, installed, err := InstallCRL(dir, crlFor(t, otherCert, otherKey, "1a2b"))
	if err == nil {
		t.Fatal("installed a CRL signed by a CA that is not ours")
	}
	if installed {
		t.Fatal("reported a CRL as installed while also failing")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("error does not say why it was refused: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "crl.pem")); statErr == nil {
		t.Fatal("a refused CRL was written to disk anyway")
	}
}

// The un-revocation move: publish an OLD CRL — genuinely CA-signed, from before
// the removal — and every node that takes it stops revoking the serial.
func TestInstallCRL_RefusesToGoBackwards(t *testing.T) {
	caCert, caKey, dir := setupCA(t)
	stale := crlFor(t, caCert, caKey)

	current := crlFor(t, caCert, caKey, "1a2b")
	if _, _, err := InstallCRL(dir, current); err != nil {
		t.Fatalf("install current: %v", err)
	}

	_, installed, err := InstallCRL(dir, stale)
	if err != nil {
		t.Fatalf("InstallCRL(stale): %v", err)
	}
	if installed {
		t.Fatal("an older CRL replaced a newer one")
	}
	if !IsCertRevoked(dir, big.NewInt(0x1a2b)) {
		t.Fatal("the revocation was lost to an older CRL")
	}
}

func TestInstallCRL_RefusesGarbage(t *testing.T) {
	_, _, dir := setupCA(t)
	for name, body := range map[string][]byte{
		"not PEM at all":      []byte("hello"),
		"PEM of nothing":      []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"),
		"an empty submission": {},
	} {
		if _, _, err := InstallCRL(dir, body); err == nil {
			t.Fatalf("%s was accepted as a CRL", name)
		}
	}
}

// Two revocations inside one second must not produce the same CRL number: the
// number is how every reader decides whether a CRL is newer than the one it has,
// so a collision leaves half the cluster calling the second removal a duplicate.
func TestAppendToCRL_NumbersAreStrictlyIncreasing(t *testing.T) {
	caCert, caKey, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	var prev int64
	for i, serial := range []string{"a1", "b2", "c3", "d4"} {
		if err := AppendToCRL(caCert, caKey, crlPath, serial); err != nil {
			t.Fatalf("AppendToCRL %s: %v", serial, err)
		}
		v := CRLVersion(crlPath)
		if v <= prev {
			t.Fatalf("revocation %d produced CRL number %d, not greater than %d", i, v, prev)
		}
		prev = v
	}
}

// TestInstallCRL_RefusesANewerCRLThatRevokesLess.
//
// This one needs no attacker. A CRL is minted by appending one serial to whatever
// crl.pem the CA machine holds, and AppendToCRL treated an unreadable file as an
// empty one — so a CA host whose crl.pem was deleted, restored from an old backup,
// or never copied alongside ca.key mints a CRL revoking ONE serial, numbered now
// and therefore higher than the cluster's. Before distribution was replicated that
// damaged one machine. Now it would un-revoke every previously revoked host on
// every node, with the command reporting success.
func TestInstallCRL_RefusesANewerCRLThatRevokesLess(t *testing.T) {
	caCert, caKey, dir := setupCA(t)

	if _, _, err := InstallCRL(dir, crlFor(t, caCert, caKey, "aaaa", "bbbb")); err != nil {
		t.Fatalf("install the cluster's CRL: %v", err)
	}
	// Minted from a crl.pem that had lost its history: newer, and revokes only the
	// host being removed right now.
	forgetful := crlFor(t, caCert, caKey, "cccc")

	_, installed, err := InstallCRL(dir, forgetful)
	if err == nil {
		t.Fatal("installed a newer CRL that dropped two existing revocations")
	}
	if installed {
		t.Fatal("reported the CRL as installed while also failing")
	}
	if !strings.Contains(err.Error(), "aaaa") && !strings.Contains(err.Error(), "bbbb") {
		t.Errorf("the refusal does not name the revocations that would be lost: %v", err)
	}
	for _, serial := range []int64{0xaaaa, 0xbbbb} {
		if !IsCertRevoked(dir, big.NewInt(serial)) {
			t.Fatalf("serial %x is no longer revoked after a refused CRL", serial)
		}
	}
}

// Adding to a CRL that revokes MORE is the ordinary path and must keep working —
// the superset rule must not be so eager that it refuses normal revocations.
func TestInstallCRL_AcceptsANewerCRLThatRevokesMore(t *testing.T) {
	caCert, caKey, dir := setupCA(t)
	if _, _, err := InstallCRL(dir, crlFor(t, caCert, caKey, "aaaa")); err != nil {
		t.Fatalf("install the first CRL: %v", err)
	}
	_, installed, err := InstallCRL(dir, crlFor(t, caCert, caKey, "aaaa", "bbbb"))
	if err != nil {
		t.Fatalf("refused an ordinary additional revocation: %v", err)
	}
	if !installed {
		t.Fatal("a CRL revoking one more serial was not installed")
	}
	if !IsCertRevoked(dir, big.NewInt(0xbbbb)) {
		t.Fatal("the newly revoked serial is not enforced")
	}
}

// The minting side of the same defect: refuse to rebuild from a crl.pem that
// exists but cannot be read, rather than silently treating it as empty.
func TestAppendToCRL_RefusesToRebuildFromAnUnreadableCRL(t *testing.T) {
	caCert, caKey, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")
	if err := AppendToCRL(caCert, caKey, crlPath, "aaaa"); err != nil {
		t.Fatalf("first revocation: %v", err)
	}
	if err := os.WriteFile(crlPath, []byte("this is not a CRL"), 0o600); err != nil {
		t.Fatalf("corrupt the CRL: %v", err)
	}
	if err := AppendToCRL(caCert, caKey, crlPath, "bbbb"); err == nil {
		t.Fatal("rebuilt the CRL from an unreadable file, silently dropping every existing revocation")
	}
}

// A cluster that has never revoked anything must still be able to start.
func TestAppendToCRL_AnAbsentCRLIsTheFirstRevocation(t *testing.T) {
	caCert, caKey, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")
	if err := AppendToCRL(caCert, caKey, crlPath, "aaaa"); err != nil {
		t.Fatalf("first revocation on a cluster with no CRL: %v", err)
	}
	if !IsCertRevoked(dir, big.NewInt(0xaaaa)) {
		t.Fatal("the first revocation did not take effect")
	}
}
