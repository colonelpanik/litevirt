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
	if err := GenerateCRL(otherCA, otherKey, crlPath, []string{serialHex}); err != nil {
		t.Fatalf("GenerateCRL (foreign): %v", err)
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
