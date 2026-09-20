package health

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// healthyPeer starts a real TLS listener that completes a handshake and hangs
// up, which is exactly what Checker.probe measures. Returns the host and port
// to put in a HostRecord.
//
// A real listener rather than a probe seam: probe's whole job is "can I
// complete a TLS handshake with this peer", and a fake would assert on itself.
func healthyPeer(t *testing.T) (string, int) {
	t.Helper()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				conn.Close()
			}()
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

// probingChecker is a Checker wired to trust healthyPeer's throwaway certificate.
// pki.PeerTLSConfig would need a whole CA on disk to say the same thing.
func probingChecker(t *testing.T, db *corrosion.Client) *Checker {
	t.Helper()
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // throwaway test cert
	return c
}

// A healthy probe records success — 0 failures, status healthy, last_seen set.
// This is what TestCheckHost_Healthy_RecordsSuccess claimed to test and could
// not, because probe needs a TLS peer; it pre-seeded a failure count instead and
// ended up pinning the #201 inheritance rather than the healthy path.
func TestCheckHost_HealthyProbeRecordsSuccess(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)

	c.checkHost(ctx, corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port})

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures, last_seen FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].String("status"); got != "healthy" {
		t.Errorf("status = %q, want healthy", got)
	}
	if got := rows[0].Int("consecutive_failures"); got != 0 {
		t.Errorf("consecutive_failures = %d, want 0", got)
	}
	if got := rows[0].String("last_seen"); got == "" {
		t.Error("last_seen is empty; a healthy observation must stamp it")
	}
}
