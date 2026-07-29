package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// caDir returns a config dir holding a freshly generated cluster CA, laid out
// the way PKIDir() expects.
func caDir(t *testing.T) string {
	t.Helper()
	cfg := t.TempDir()
	pkiDir := filepath.Join(cfg, "pki")
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return cfg
}

// Without ca.key nothing can be signed — litevirt has no CSR flow — so the
// command has to say which machine to run from rather than failing later with
// an opaque PKI error.
func TestMintAuditSigningPair_RefusesWithoutCAKey(t *testing.T) {
	pkiDir := t.TempDir()
	// A CA certificate on its own is the interesting case: it is what every
	// non-init node has, and it is not enough to sign anything.
	if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), []byte("not a real ca"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := mintAuditSigningPair(pkiDir, "host-a")
	if err == nil {
		t.Fatal("expected rotation to refuse without the CA private key")
	}
	if !strings.Contains(err.Error(), "lv host init") {
		t.Errorf("error does not name the node to run from: %v", err)
	}
}

// The refusal must come before the SSH connect, so a rotation attempted from
// the wrong machine leaves the target untouched.
func TestHostRotateAuditKey_RefusesBeforeTouchingTheHost(t *testing.T) {
	cfg := caDir(t)
	t.Setenv("LV_CONFIG_DIR", cfg)
	// The CA CERTIFICATE stays — every node has that. Only the private key,
	// which lives solely on the node that ran `lv host init`, is missing.
	if err := os.Remove(filepath.Join(PKIDir(), "ca.key")); err != nil {
		t.Fatal(err)
	}

	// 240.0.0.1 is reserved and unroutable: if the CA check did not run first
	// this would hang on the SSH dial instead of returning promptly.
	err := HostRotateAuditKey(context.Background(), "host-a", "root@240.0.0.1")
	if err == nil {
		t.Fatal("expected rotation to refuse without the CA private key")
	}
	if !strings.Contains(err.Error(), "CA private key") {
		t.Errorf("error = %v, want the missing-CA refusal", err)
	}
}

func TestMintAuditSigningPair_CertIsHostBoundAndNotUsableForTLS(t *testing.T) {
	cfg := caDir(t)
	t.Setenv("LV_CONFIG_DIR", cfg)

	tmpDir, certPath, keyPath, err := mintAuditSigningPair(PKIDir(), "host-a")
	if err != nil {
		t.Fatalf("mintAuditSigningPair: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in minted certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse minted certificate: %v", err)
	}

	// The daemon refuses a keyring whose CN is not its own host name, and the
	// verifier rejects a signature whose certificate names a different host.
	if cert.Subject.CommonName != "host-a" {
		t.Errorf("CN = %q, want host-a", cert.Subject.CommonName)
	}
	// An audit signing certificate must never be usable as a TLS credential.
	// With no ExtKeyUsage and no IP SANs it cannot serve or authenticate a
	// connection, so an operator who copies it around cannot accidentally hand
	// out a second cluster identity.
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("certificate carries ExtKeyUsage %v/%v — it would be usable for TLS",
			cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if len(cert.IPAddresses) != 0 || len(cert.DNSNames) != 0 {
		t.Errorf("certificate carries SANs %v/%v — it would be usable for TLS",
			cert.IPAddresses, cert.DNSNames)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("certificate cannot sign")
	}

	// The key never leaves this machine world-readable, and the temp dir it is
	// minted into is not readable by other local users either.
	if st, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("key mode = %04o, want no group/other bits", st.Mode().Perm())
	}
	if st, err := os.Stat(tmpDir); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("temp dir mode = %04o, want no group/other bits", st.Mode().Perm())
	}
}

// A rotated pair must chain to the cluster CA, or peers reject every row it
// signs as an unknown key.
func TestMintAuditSigningPair_ChainsToClusterCA(t *testing.T) {
	cfg := caDir(t)
	t.Setenv("LV_CONFIG_DIR", cfg)

	tmpDir, certPath, _, err := mintAuditSigningPair(PKIDir(), "host-a")
	if err != nil {
		t.Fatalf("mintAuditSigningPair: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caPEM, err := os.ReadFile(filepath.Join(PKIDir(), "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("cluster CA is unusable")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// ExtKeyUsageAny is what the verifier uses (internal/corrosion/audit_sign.go):
	// the certificate deliberately has no EKU, so any other constraint fails.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("minted certificate does not chain to the cluster CA: %v", err)
	}
}
