package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestCheckHost_IPv6PeerProbesSuccessfully is the regression test for the peer
// probe target being built with fmt.Sprintf("%s:%d", host.Address, port).
//
// hosts.address holds a BARE host. For an IPv6 peer that Sprintf produced
// "::1:7443" — not a parseable dial target — so tls.DialWithDialer failed
// instantly on EVERY tick. Three ticks later the peer crossed suspectThreshold
// and a perfectly healthy host was handed to fencing/relocation, all because of
// a string format. The test therefore asserts on the OUTCOME (status healthy,
// zero failures) against a real TLS listener bound to ::1, not on the target
// string: it fails if any layer between the host record and the socket mangles
// an IPv6 address.
func TestCheckHost_IPv6PeerProbesSuccessfully(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this machine: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	serverCfg, clientCfg := ipv6PeerTLS(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tconn := tls.Server(conn, serverCfg)
			_ = tconn.Handshake()
			tconn.Close()
		}
	}()

	db := testCheckHostDB(t)
	ctx := context.Background()

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.tlsCfg = clientCfg

	c.checkHost(ctx, corrosion.HostRecord{
		Name:     "host-v6",
		Address:  "::1",
		GRPCPort: port,
	})

	rows, err := db.Query(ctx,
		`SELECT consecutive_failures, status FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-v6")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].String("status"); got != "healthy" {
		t.Errorf("status = %q, want healthy — the IPv6 peer is up and reachable; "+
			"a failure here means the probe target was mangled, which is how a live "+
			"host gets marked suspect and fenced", got)
	}
	if got := rows[0].Int("consecutive_failures"); got != 0 {
		t.Errorf("consecutive_failures = %d, want 0", got)
	}
}

// TestCheckHost_IPv6TargetIsBracketed pins the exact string, so a regression
// reports "wanted [::1]:7443, got ::1:7443" instead of a generic probe failure.
func TestCheckHost_IPv6TargetIsBracketed(t *testing.T) {
	for _, tc := range []struct {
		addr string
		port int
		want string
	}{
		{"::1", 7443, "[::1]:7443"},
		{"fd00::1", 9443, "[fd00::1]:9443"},
		{"2001:db8::1", 0, "[2001:db8::1]:7443"},
		{"10.0.0.5", 7443, "10.0.0.5:7443"},
	} {
		got := corrosion.PeerTarget(tc.addr, tc.port)
		if got != tc.want {
			t.Errorf("PeerTarget(%q, %d) = %q, want %q", tc.addr, tc.port, got, tc.want)
		}
		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Errorf("PeerTarget(%q, %d) = %q is not a parseable dial target: %v",
				tc.addr, tc.port, got, err)
		}
	}
}

// ipv6PeerTLS mints a CA and a host cert carrying ::1 as an IP SAN, returning a
// server config for the fake peer and a client config that trusts the CA. The
// client leaves ServerName empty exactly as Checker.probe does, so verification
// goes through the IP SAN — the same path a real peer probe takes.
func ipv6PeerTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	hostCert := filepath.Join(dir, "host.crt")
	hostKey := filepath.Join(dir, "host.key")

	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, hostCert, hostKey, "host-v6", net.ParseIP("::1")); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(hostCert, hostKey)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	pem, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("AppendCertsFromPEM: CA not added")
	}

	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
