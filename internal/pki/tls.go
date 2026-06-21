package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// ServerTLSConfig returns a TLS config for the litevirtd gRPC server.
// Requires mTLS: server presents its cert, requires client certs from the same CA.
func ServerTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(pkiDir, "host.crt"),
		filepath.Join(pkiDir, "host.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load host cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Always install the revocation check (not only when a CRL exists at
	// startup) so a CRL added/updated later takes effect without a restart.
	// The checker is fail-safe: no CRL or an unverifiable one ⇒ allow.
	tlsCfg.VerifyPeerCertificate = revocationVerifier(pkiDir, caCert)

	return tlsCfg, nil
}

// revocationVerifier builds a VerifyPeerCertificate callback backed by a
// signature-verifying, mtime-cached CRL checker. Shared by the server and
// peer TLS configs.
func revocationVerifier(pkiDir string, caPEM []byte) func([][]byte, [][]*x509.Certificate) error {
	checker := newCRLChecker(pkiDir, parseCACert(caPEM))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				continue
			}
			if checker.isRevoked(cert.SerialNumber) {
				return fmt.Errorf("certificate serial %s has been revoked", cert.SerialNumber.Text(16))
			}
		}
		return nil
	}
}

// ClientTLSConfig returns a TLS config for connecting to litevirtd.
// Used by both CLI and host-to-host communication.
// Loads host.crt/host.key if present (daemon nodes), otherwise falls back
// to client.crt/client.key (remote CLI machines).
func ClientTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// Try host cert first (daemon node), then client cert (remote CLI).
	var certs []tls.Certificate
	for _, name := range []string{"host", "client"} {
		certFile := filepath.Join(pkiDir, name+".crt")
		keyFile := filepath.Join(pkiDir, name+".key")
		if _, err := os.Stat(certFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("load %s cert/key: %w", name, err)
			}
			certs = append(certs, cert)
			break
		}
	}

	return &tls.Config{
		Certificates: certs,
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// PeerTLSConfig returns a TLS config for host-to-host gRPC calls.
// Both sides present certs from the cluster CA.
func PeerTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(pkiDir, "host.crt"),
		filepath.Join(pkiDir, "host.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load host cert/key: %w", err)
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		RootCAs:               caPool,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: revocationVerifier(pkiDir, caCert),
	}, nil
}
