package pki

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func hostCertSerial(t *testing.T, dir string) *big.Int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "host.crt"))
	if err != nil {
		t.Fatalf("read host.crt: %v", err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse host.crt: %v", err)
	}
	return cert.SerialNumber
}

// TestCRLChecker_FailSafe covers the WS6 CRL policy: only a CA-signed CRL
// enforces revocation; no CRL / forged CRL / garbage all fail safe to "allow".
func TestCRLChecker_FailSafe(t *testing.T) {
	dir := setupPKI(t)
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	crlPath := filepath.Join(dir, "crl.pem")
	caPEM, _ := os.ReadFile(caPath)
	caCert := parseCACert(caPEM)
	serial := hostCertSerial(t, dir)
	serialHex := serial.Text(16)

	// 1. No CRL → not revoked.
	if newCRLChecker(dir, caCert).isRevoked(serial) {
		t.Fatal("no CRL must mean not revoked")
	}

	// 2. CA-signed CRL revoking the serial → revoked; unrelated serial is not.
	if err := GenerateCRL(caPath, caKeyPath, crlPath, []string{serialHex}); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if !newCRLChecker(dir, caCert).isRevoked(serial) {
		t.Error("CA-signed CRL revoking the serial must report revoked")
	}
	if newCRLChecker(dir, caCert).isRevoked(big.NewInt(0xABCDEF)) {
		t.Error("unrelated serial must not be revoked")
	}

	// 3. Forged CRL signed by a DIFFERENT CA → IGNORED (fail-safe).
	otherDir := t.TempDir()
	otherCA := filepath.Join(otherDir, "ca.crt")
	otherKey := filepath.Join(otherDir, "ca.key")
	if err := GenerateCA(otherCA, otherKey); err != nil {
		t.Fatalf("GenerateCA (foreign): %v", err)
	}
	foreignPath := filepath.Join(otherDir, "crl.pem")
	if err := GenerateCRL(otherCA, otherKey, foreignPath, []string{serialHex}); err != nil {
		t.Fatalf("GenerateCRL (foreign): %v", err)
	}
	foreign, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("read foreign CRL: %v", err)
	}
	if err := os.WriteFile(crlPath, foreign, 0o600); err != nil {
		t.Fatalf("install forged CRL for fail-safe test: %v", err)
	}
	if newCRLChecker(dir, caCert).isRevoked(serial) {
		t.Error("a CRL not signed by our CA must be IGNORED, not enforced")
	}

	// 4. Garbage CRL file → ignored.
	if err := os.WriteFile(crlPath, []byte("definitely not a CRL"), 0600); err != nil {
		t.Fatal(err)
	}
	if newCRLChecker(dir, caCert).isRevoked(serial) {
		t.Error("a garbage CRL must be ignored")
	}
}

func TestCRLChecker_EnforcesEverySignedBundleMember(t *testing.T) {
	caPath, caKey, dir := setupCA(t)
	first := crlFor(t, caPath, caKey, "aaaa")
	second := crlFor(t, caPath, caKey, "bbbb")
	if _, _, err := InstallCRLs(dir, [][]byte{first, second}); err != nil {
		t.Fatalf("InstallCRLs: %v", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	checker := newCRLChecker(dir, parseCACert(caPEM))
	for _, serial := range []int64{0xaaaa, 0xbbbb} {
		if !checker.isRevoked(big.NewInt(serial)) {
			t.Fatalf("mTLS checker omitted serial %x from a signed bundle member", serial)
		}
	}
}

// TestCRLChecker_ReloadsWithoutRestart verifies a single checker picks up a
// newly-written CRL (revocation takes effect without a daemon restart).
func TestCRLChecker_ReloadsWithoutRestart(t *testing.T) {
	dir := setupPKI(t)
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	crlPath := filepath.Join(dir, "crl.pem")
	caPEM, _ := os.ReadFile(caPath)
	serial := hostCertSerial(t, dir)

	checker := newCRLChecker(dir, parseCACert(caPEM))
	if checker.isRevoked(serial) {
		t.Fatal("should not be revoked before any CRL exists")
	}
	// Revoke it after the checker has already been consulted once.
	if err := GenerateCRL(caPath, caKeyPath, crlPath, []string{serial.Text(16)}); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if !checker.isRevoked(serial) {
		t.Error("the same checker must pick up the freshly-written CRL (no restart)")
	}
	// Removing the CRL stops enforcement.
	os.Remove(crlPath)
	if checker.isRevoked(serial) {
		t.Error("removing the CRL must stop enforcing revocation")
	}
}
