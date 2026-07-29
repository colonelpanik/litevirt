package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateCA creates a self-signed ECDSA P-256 CA certificate and key.
func GenerateCA(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"litevirt"},
			CommonName:   "litevirt Cluster CA",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}

	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

// GenerateHostCert creates a host certificate signed by the CA.
func GenerateHostCert(caCertPath, caKeyPath, certPath, keyPath string, hostName string, ip net.IP) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"litevirt"},
			CommonName:   hostName,
		},
		DNSNames:    []string{hostName},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Always include 127.0.0.1 so local gRPC clients can connect.
	loopback := net.IPv4(127, 0, 0, 1)
	if ip != nil {
		if !ip.Equal(loopback) {
			template.IPAddresses = []net.IP{ip, loopback}
		} else {
			template.IPAddresses = []net.IP{loopback}
		}
	} else {
		template.IPAddresses = []net.IP{loopback}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create host cert: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal host key: %w", err)
	}

	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

// CertSerial returns the serial number of a PEM certificate file.
func CertSerial(certPath string) (string, error) {
	cert, err := loadCert(certPath)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.Text(16), nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := loadCert(certPath)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in CA key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	return cert, key, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert %s: %w", path, err)
	}

	return cert, nil
}

func writePEM(path string, pemType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: data})
}

// GenerateClientCert creates a client-only certificate signed by the CA.
// Used by CLI machines that connect remotely via mTLS.
func GenerateClientCert(caCertPath, caKeyPath, certPath, keyPath, cn string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"litevirt"},
			CommonName:   cn,
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create client cert: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal client key: %w", err)
	}

	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

// AuditSigningCertName / AuditSigningKeyName are the dedicated audit signing
// identity, separate from the host's TLS identity.
const (
	AuditSigningCertName = "audit-signing.crt"
	AuditSigningKeyName  = "audit-signing.key"
)

// GenerateAuditSigningCert creates a CA-signed certificate used ONLY to sign
// audit rows, with hostName as its CN.
//
// It is deliberately not the host's TLS certificate. Audit signing bootstraps
// on host.key because every node already has one and minting anything new needs
// the CA private key, which lives only on the node that ran `lv host init`.
// ROTATION already requires that node, so it can mint a dedicated key — and
// doing so keeps rotation off the TLS path entirely.
//
// That separation is the whole point. Replacing host.crt/host.key on a running
// node changes the identity the gRPC listener serves (built once at boot and
// never reloaded), the client identity the health checker dials peers with
// (likewise), and the target of the libvirt TLS symlinks that qemu+tls://
// migration reads. Rotating the audit key must not risk any of that: an
// operator restoring audit integrity should not be gambling with quorum or a
// live migration.
//
// No IP SANs and no ExtKeyUsage: this certificate must never be usable for TLS.
// Its only job is to say "this public key belongs to this host".
func GenerateAuditSigningCert(caCertPath, caKeyPath, certPath, keyPath, hostName string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate audit signing key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"litevirt"},
			CommonName:   hostName,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create audit signing cert: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal audit signing key: %w", err)
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

// TightenPrivateKeys repairs the mode of every private key in pkiDir, making
// each unreadable to anyone but its owner.
//
// This runs on every daemon start, unconditionally, because the damage it
// repairs was shipped unconditionally: `lv host init root@<host>` pushed
// /etc/litevirt/pki/host.key mode 0644 on every node it provisioned — CopyFile's
// default, invisible at the call site — and host.key is the peer-mTLS identity.
// Any local user on such a node could read it and impersonate that host to the
// whole cluster.
//
// The push path is fixed, but existing clusters are never re-provisioned, so
// only a repair reaches them. It was previously reached only through
// LoadAuditKeyring, which runs solely when enforcement.audit_signature is on — a
// flag that defaults to false. An operator who upgraded specifically to pick up
// the fix, and left the flag at its default, got no repair and no warning.
//
// Tightening does not undo a copy already taken; that is what
// `lv host rotate-audit-key` is for, and the warning says so.
func TightenPrivateKeys(pkiDir string) error {
	var firstErr error
	for _, name := range []string{"ca.key", "host.key", AuditSigningKeyName} {
		path := filepath.Join(pkiDir, name)
		if _, err := os.Stat(path); err != nil {
			continue // not every node holds every key; ca.key lives on one
		}
		if err := TightenKeyMode(path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// TightenKeyMode makes one private key unreadable to anyone but its owner,
// repairing it in place if it is not.
//
// A repair, not a warning. A signature — or a TLS identity — is worth exactly
// the secrecy of the key behind it, and leaving an operator to notice a log line
// is not a fix.
func TightenKeyMode(keyPath string) error {
	fi, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("stat private key: %w", err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return fmt.Errorf("private key %s is mode %04o and readable by other local users, and it "+
			"could not be tightened: %w", keyPath, fi.Mode().Perm(), err)
	}
	slog.Warn("private key was readable by other local users; tightened to 0600. "+
		"Tightening does not undo a copy already taken: anyone who read it can still use it "+
		"as this host, so rotate if that is possible (`lv host rotate-audit-key` for the "+
		"audit key; re-provisioning for the TLS identity)",
		"path", keyPath, "was", fmt.Sprintf("%04o", fi.Mode().Perm()))
	return nil
}
