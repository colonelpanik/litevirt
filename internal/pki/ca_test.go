package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(certPath, keyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("CA cert not created: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("CA key not created: %v", err)
	}

	// Verify it's a valid CA cert
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("load CA cert: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected CA cert to have IsCA=true")
	}
	if cert.Subject.CommonName != "litevirt Cluster CA" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}
}

func TestGenerateHostCert(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(caPath, caKeyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostCertPath := filepath.Join(dir, "host.crt")
	hostKeyPath := filepath.Join(dir, "host.key")
	ip := net.ParseIP("10.0.50.10")

	if err := GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, "host-a", ip); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	// Verify host cert
	hostCert, err := loadCert(hostCertPath)
	if err != nil {
		t.Fatalf("load host cert: %v", err)
	}

	if hostCert.Subject.CommonName != "host-a" {
		t.Errorf("unexpected CN: %s", hostCert.Subject.CommonName)
	}
	if len(hostCert.DNSNames) == 0 || hostCert.DNSNames[0] != "host-a" {
		t.Errorf("expected DNS SAN 'host-a', got %v", hostCert.DNSNames)
	}
	if len(hostCert.IPAddresses) == 0 || !hostCert.IPAddresses[0].Equal(ip) {
		t.Errorf("expected IP SAN %v, got %v", ip, hostCert.IPAddresses)
	}

	// Verify the host cert is signed by the CA
	caCert, err := loadCert(caPath)
	if err != nil {
		t.Fatalf("load CA cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if _, err := hostCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("host cert verification failed: %v", err)
	}

	// Verify TLS keypair loads
	if _, err := tls.LoadX509KeyPair(hostCertPath, hostKeyPath); err != nil {
		t.Fatalf("load TLS keypair: %v", err)
	}
}

func TestCertSerial(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(certPath, keyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	serial, err := CertSerial(certPath)
	if err != nil {
		t.Fatalf("CertSerial: %v", err)
	}
	if serial == "" {
		t.Error("expected non-empty serial")
	}
}
