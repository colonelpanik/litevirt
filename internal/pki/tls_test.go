package pki

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
)

// setupPKI creates a CA + host cert in a temp directory.
func setupPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := GenerateCA(caPath, caKeyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostCertPath := filepath.Join(dir, "host.crt")
	hostKeyPath := filepath.Join(dir, "host.key")
	if err := GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, "test-host", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	return dir
}

func TestServerTLSConfig(t *testing.T) {
	dir := setupPKI(t)

	cfg, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("server should require client certs")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("should enforce TLS 1.3 minimum")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 cert, got %d", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestServerTLSConfig_MissingCA(t *testing.T) {
	dir := t.TempDir()
	_, err := ServerTLSConfig(dir)
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestServerTLSConfig_MissingHostCert(t *testing.T) {
	dir := t.TempDir()
	// Create CA but not host cert
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	GenerateCA(caPath, caKeyPath)

	_, err := ServerTLSConfig(dir)
	if err == nil {
		t.Error("expected error for missing host cert")
	}
}

func TestClientTLSConfig(t *testing.T) {
	dir := setupPKI(t)

	cfg, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	if cfg.RootCAs == nil {
		t.Error("RootCAs should not be nil")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("should enforce TLS 1.3 minimum")
	}
	// Client cert is optional but should be loaded if present
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 cert (host cert present), got %d", len(cfg.Certificates))
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false")
	}
}

func TestClientTLSConfig_NoCert(t *testing.T) {
	dir := t.TempDir()
	// Only CA, no host cert — should succeed (CLI mode)
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	GenerateCA(caPath, caKeyPath)

	cfg, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("expected 0 certs (no host cert), got %d", len(cfg.Certificates))
	}
}

func TestClientTLSConfig_ClientCertFallback(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	GenerateCA(caPath, caKeyPath)

	// Generate client cert (no host cert)
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	cfg, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 cert (client cert fallback), got %d", len(cfg.Certificates))
	}
}

func TestGenerateClientCert(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	GenerateCA(caPath, caKeyPath)

	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := GenerateClientCert(caPath, caKeyPath, certPath, keyPath, "test-cli"); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	if cert.Subject.CommonName != "test-cli" {
		t.Errorf("CN = %q, want test-cli", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != 2 { // x509.ExtKeyUsageClientAuth = 2
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("client cert should have no IP SANs, got %v", cert.IPAddresses)
	}
}

func TestPeerTLSConfig(t *testing.T) {
	dir := setupPKI(t)

	cfg, err := PeerTLSConfig(dir)
	if err != nil {
		t.Fatalf("PeerTLSConfig: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("peer should require client certs")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs should not be nil")
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 cert, got %d", len(cfg.Certificates))
	}
}

func TestPeerTLSConfig_MissingCA(t *testing.T) {
	_, err := PeerTLSConfig(t.TempDir())
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestMTLS_Handshake(t *testing.T) {
	dir := setupPKI(t)

	serverCfg, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	clientCfg, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	// Override ServerName for localhost
	clientCfg.ServerName = "test-host"

	// Start TLS listener
	lis, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	// Accept in goroutine
	errCh := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
		errCh <- nil
	}()

	// Client connects
	conn, err := tls.Dial("tcp", lis.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want hello", string(buf[:n]))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestGenerateHostCert_NilIP(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	GenerateCA(caPath, caKeyPath)

	hostCertPath := filepath.Join(dir, "host.crt")
	hostKeyPath := filepath.Join(dir, "host.key")

	// nil IP should work — 127.0.0.1 is always added as a SAN
	err := GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, "host-x", nil)
	if err != nil {
		t.Fatalf("GenerateHostCert with nil IP: %v", err)
	}

	cert, err := loadCert(hostCertPath)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("expected [127.0.0.1] IP SAN, got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "host-x" {
		t.Errorf("DNS SANs = %v", cert.DNSNames)
	}
}
