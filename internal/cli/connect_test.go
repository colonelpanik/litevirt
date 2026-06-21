package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestConnectRemote_StripUserPrefix(t *testing.T) {
	// connectRemote strips "user@" from LV_HOST and appends port.
	// We can't test the full connection (needs TLS), but we can test
	// the address parsing logic via LoadClusterConfig + address format.
	tests := []struct {
		name     string
		lvHost   string
		wantHost string
	}{
		{"plain_host", "10.0.50.10", "10.0.50.10"},
		{"user_at_host", "root@10.0.50.10", "root@10.0.50.10"},
		{"host_with_port", "10.0.50.10:7443", "10.0.50.10:7443"},
		{"user_at_host_port", "admin@host.local:8443", "admin@host.local:8443"},
		{"hostname_only", "node1.cluster.local", "node1.cluster.local"},
	}

	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LV_HOST", tt.lvHost)
			cfg, err := LoadClusterConfig()
			if err != nil {
				t.Fatalf("LoadClusterConfig: %v", err)
			}
			if cfg.DefaultHost != tt.wantHost {
				t.Errorf("DefaultHost = %q, want %q", cfg.DefaultHost, tt.wantHost)
			}
			if cfg.GRPCPort != 7443 {
				t.Errorf("GRPCPort = %d, want 7443", cfg.GRPCPort)
			}
			if cfg.Local {
				t.Error("should not be local mode when LV_HOST is set")
			}
		})
	}
}

func TestConnectRemote_AddressParsing(t *testing.T) {
	// Test the address parsing logic that connectRemote uses.
	// Simulates what connectRemote does: strip user@, add port.
	tests := []struct {
		input    string
		wantAddr string
	}{
		{"10.0.50.10", "10.0.50.10:7443"},
		{"root@10.0.50.10", "10.0.50.10:7443"},
		{"admin@host.example.com", "host.example.com:7443"},
		{"10.0.50.10:8443", "10.0.50.10:8443"},
		{"root@10.0.50.10:8443", "10.0.50.10:8443"},
		{"deploy@node1", "node1:7443"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cfg := &ClusterConfig{
				DefaultHost: tt.input,
				GRPCPort:    7443,
			}

			// Replicate the parsing logic from connectRemote.
			addr := cfg.DefaultHost
			if idx := strings.Index(addr, "@"); idx >= 0 {
				addr = addr[idx+1:]
			}
			if !strings.Contains(addr, ":") {
				addr = addr + ":7443"
			}

			if addr != tt.wantAddr {
				t.Errorf("parsed addr = %q, want %q", addr, tt.wantAddr)
			}
		})
	}
}

func TestLoadClusterConfig_LVHostOverridesLocal(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("grpc_port: 9443\n"), 0644); err != nil {
		t.Fatal(err)
	}

	old := daemonConfigPath
	daemonConfigPath = configFile
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "remote-host")

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	// LV_HOST should take priority over local config.
	if cfg.Local {
		t.Error("should not be local mode when LV_HOST is set")
	}
	if cfg.DefaultHost != "remote-host" {
		t.Errorf("DefaultHost = %q, want remote-host", cfg.DefaultHost)
	}
}

func TestBearerToken_GetRequestMetadata(t *testing.T) {
	bt := bearerToken{token: "my-secret-token"}
	md, err := bt.GetRequestMetadata(nil)
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if got := md["authorization"]; got != "Bearer my-secret-token" {
		t.Errorf("authorization = %q, want %q", got, "Bearer my-secret-token")
	}
}

func TestBearerToken_RequireTransportSecurity(t *testing.T) {
	bt := bearerToken{token: "tok"}
	if !bt.RequireTransportSecurity() {
		t.Error("RequireTransportSecurity should return true")
	}
}

func TestResolveToken_EnvVar(t *testing.T) {
	t.Setenv("LV_TOKEN", "env-token-123")
	tok := resolveToken()
	if tok != "env-token-123" {
		t.Errorf("resolveToken = %q, want env-token-123", tok)
	}
}

func TestResolveToken_Empty(t *testing.T) {
	t.Setenv("LV_TOKEN", "")
	t.Setenv("LV_CONFIG_DIR", t.TempDir()) // no credential file
	tok := resolveToken()
	// Should be empty when no env var and no credential file.
	if tok != "" {
		t.Errorf("resolveToken = %q, want empty", tok)
	}
}

func TestTokenDialOption_WithToken(t *testing.T) {
	t.Setenv("LV_TOKEN", "my-token")
	opt := tokenDialOption()
	if opt == nil {
		t.Error("tokenDialOption should return non-nil when token exists")
	}
}

func TestTokenDialOption_WithoutToken(t *testing.T) {
	t.Setenv("LV_TOKEN", "")
	t.Setenv("LV_CONFIG_DIR", t.TempDir())
	opt := tokenDialOption()
	if opt != nil {
		t.Error("tokenDialOption should return nil when no token")
	}
}

func TestWithTokenOption_AppendsOption(t *testing.T) {
	t.Setenv("LV_TOKEN", "tok")
	opts := withTokenOption(nil)
	if len(opts) != 1 {
		t.Errorf("len(opts) = %d, want 1", len(opts))
	}
}

func TestWithTokenOption_NoToken(t *testing.T) {
	t.Setenv("LV_TOKEN", "")
	t.Setenv("LV_CONFIG_DIR", t.TempDir())
	opts := withTokenOption(nil)
	if len(opts) != 0 {
		t.Errorf("len(opts) = %d, want 0", len(opts))
	}
}

// --- TLS connection integration tests ---

// setupTestPKI generates a full CA + host cert + client cert in a temp dir.
func setupTestPKI(t *testing.T) string {
	t.Helper()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	os.MkdirAll(pkiDir, 0700)

	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if err := pki.GenerateCA(caPath, caKeyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostCert := filepath.Join(pkiDir, "host.crt")
	hostKey := filepath.Join(pkiDir, "host.key")
	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCert, hostKey, "localhost", net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	clientCert := filepath.Join(pkiDir, "client.crt")
	clientKey := filepath.Join(pkiDir, "client.key")
	if err := pki.GenerateClientCert(caPath, caKeyPath, clientCert, clientKey, "test-cli"); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	return pkiDir
}

func TestConnectRemote_TLSHandshake(t *testing.T) {
	pkiDir := setupTestPKI(t)

	// Start a real mTLS gRPC server.
	serverTLS, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterLiteVirtServer(srv, &pb.UnimplementedLiteVirtServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	// Connect using connectRemote with client certs.
	cfg := &ClusterConfig{
		DefaultHost: "127.0.0.1",
		GRPCPort:    port,
		PKIDir:      pkiDir,
	}

	client, closer, err := connectRemote(cfg)
	if err != nil {
		t.Fatalf("connectRemote: %v", err)
	}
	defer closer()

	if client == nil {
		t.Fatal("client should not be nil")
	}

	// Actually call the server to verify the TLS handshake works end-to-end.
	_, err = client.Ping(context.Background(), &pb.PingRequest{})
	// The UnimplementedLiteVirtServer returns Unimplemented, which is fine —
	// what matters is that the TLS handshake succeeded (no transport error).
	if err != nil && !strings.Contains(err.Error(), "Unimplemented") {
		t.Fatalf("Ping failed with non-TLS error: %v", err)
	}
}

func TestConnectLocal_TLSHandshake(t *testing.T) {
	pkiDir := setupTestPKI(t)

	serverTLS, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterLiteVirtServer(srv, &pb.UnimplementedLiteVirtServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	cfg := &ClusterConfig{
		GRPCPort: port,
		PKIDir:   pkiDir,
		Local:    true,
	}

	client, closer, err := connectLocal(cfg)
	if err != nil {
		t.Fatalf("connectLocal: %v", err)
	}
	defer closer()

	if client == nil {
		t.Fatal("client should not be nil")
	}

	_, err = client.Ping(context.Background(), &pb.PingRequest{})
	if err != nil && !strings.Contains(err.Error(), "Unimplemented") {
		t.Fatalf("Ping failed with non-TLS error: %v", err)
	}
}

func TestConnectRemote_UserAtStripped(t *testing.T) {
	pkiDir := setupTestPKI(t)

	serverTLS, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterLiteVirtServer(srv, &pb.UnimplementedLiteVirtServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	// user@host format — user@ should be stripped.
	cfg := &ClusterConfig{
		DefaultHost: "root@127.0.0.1",
		GRPCPort:    port,
		PKIDir:      pkiDir,
	}

	client, closer, err := connectRemote(cfg)
	if err != nil {
		t.Fatalf("connectRemote with user@: %v", err)
	}
	defer closer()

	_, err = client.Ping(context.Background(), &pb.PingRequest{})
	if err != nil && !strings.Contains(err.Error(), "Unimplemented") {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestConnectRemote_ClientCertOnly(t *testing.T) {
	pkiDir := setupTestPKI(t)

	// Remove host cert — should fall back to client cert.
	os.Remove(filepath.Join(pkiDir, "host.crt"))
	os.Remove(filepath.Join(pkiDir, "host.key"))

	// Need a separate server PKI dir that still has host certs.
	serverPKI := filepath.Join(t.TempDir(), "server-pki")
	os.MkdirAll(serverPKI, 0700)
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	// Copy CA.
	caCert, _ := os.ReadFile(caPath)
	caKey, _ := os.ReadFile(caKeyPath)
	os.WriteFile(filepath.Join(serverPKI, "ca.crt"), caCert, 0644)
	os.WriteFile(filepath.Join(serverPKI, "ca.key"), caKey, 0600)
	// Generate server host cert.
	pki.GenerateHostCert(
		filepath.Join(serverPKI, "ca.crt"), filepath.Join(serverPKI, "ca.key"),
		filepath.Join(serverPKI, "host.crt"), filepath.Join(serverPKI, "host.key"),
		"localhost", net.IPv4(127, 0, 0, 1),
	)

	serverTLS, err := pki.ServerTLSConfig(serverPKI)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterLiteVirtServer(srv, &pb.UnimplementedLiteVirtServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	// Connect using client cert (no host cert in pkiDir).
	cfg := &ClusterConfig{
		DefaultHost: "127.0.0.1",
		GRPCPort:    port,
		PKIDir:      pkiDir,
	}

	client, closer, err := connectRemote(cfg)
	if err != nil {
		t.Fatalf("connectRemote with client cert: %v", err)
	}
	defer closer()

	_, err = client.Ping(context.Background(), &pb.PingRequest{})
	if err != nil && !strings.Contains(err.Error(), "Unimplemented") {
		t.Fatalf("Ping failed: %v", err)
	}
}
