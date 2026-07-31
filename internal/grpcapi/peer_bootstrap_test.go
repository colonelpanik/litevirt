package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Peer trust and the bootstrap deadlock.
//
// isTrustedHostCN required the CN to name a row in the hosts table. Hosts learn
// about each other by REPLICATION, and replication is the thing being gated — so
// a cluster where each node knows only itself can never converge. Found rebuilding
// the lab: four freshly provisioned nodes, each with exactly its own row, every
// peer RPC refused with "replication RPC requires peer mTLS", forever. It only
// came up because I had to seed all four rows onto all four nodes by hand.
//
// The certificate is the trust root — minting one requires the cluster CA private
// key, which lives on no node. The hosts table's job is REVOCATION, and removal
// tombstones the row (DeleteHost sets deleted_at) rather than deleting it. So
// "absent" and "removed" are distinguishable, and only the second should be
// refused.

func trustFixture(t *testing.T) *Server {
	t.Helper()
	return testServer(t)
}

// certCtx builds a peer context presenting a certificate with the given extended
// key usages. ServerAuth is what GenerateHostCert sets and GenerateClientCert does
// not, so it is how a host certificate is told from a distributable client one.
func certCtx(cn string, usages ...x509.ExtKeyUsage) context.Context {
	return certSerialCtx(cn, nil, usages...)
}

func certSerialCtx(cn string, serial *big.Int, usages ...x509.ExtKeyUsage) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 1234},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{
				Subject:      pkix.Name{CommonName: cn},
				SerialNumber: serial,
				ExtKeyUsage:  usages,
			}},
		}},
	})
}

func TestPeerTrust_ReAdmittedNameAcceptsOnlyTheFreshCertificate(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-4", Address: "10.0.0.4", State: "active", CertSerial: "bb",
	}); err != nil {
		t.Fatal(err)
	}
	oldCert := certSerialCtx("node-4", big.NewInt(0xaa),
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if s.isTrustedHostCN(oldCert, "node-4") {
		t.Fatal("an active name admitted with a fresh serial accepted its old certificate")
	}
	freshCert := certSerialCtx("node-4", big.NewInt(0xbb),
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if !s.isTrustedHostCN(freshCert, "node-4") {
		t.Fatal("the certificate recorded by admission was refused")
	}
}

// TestPeerTrust_AnUnknownHostIsTrusted is the bootstrap case: a peer whose row has
// not replicated here yet must be able to talk to us, or it never can.
func TestPeerTrust_AnUnknownHostIsTrusted(t *testing.T) {
	s := trustFixture(t)
	ctx := certCtx("node-2", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if !s.isTrustedHostCN(ctx, "node-2") {
		t.Fatal("a CA-signed HOST certificate this node has never heard of was refused\n" +
			"peers are learned by replication and replication is what this gates, so a " +
			"fresh cluster where every node knows only itself can never converge")
	}
}

// TestPeerTrust_AClientCertIsNotAPeer is the property the bootstrap fix nearly
// traded away, and the reason the discriminator is ServerAuth rather than "the CA
// signed it".
//
// The lv-cli certificate is DISTRIBUTABLE — it is handed to every operator who
// runs the CLI. Trusting any CA-signed common name made every one of those a
// cluster peer, entitled to replicate. Three existing tests caught it, which is
// the only reason it is not in the tree.
func TestPeerTrust_AClientCertIsNotAPeer(t *testing.T) {
	s := trustFixture(t)
	ctx := certCtx("lv-cli", x509.ExtKeyUsageClientAuth)
	if s.isTrustedHostCN(ctx, "lv-cli") {
		t.Fatal("a client certificate was accepted as a cluster peer\n" +
			"lv-cli is handed to every operator, so this would make each of them able " +
			"to push replicated state into the cluster")
	}
}

// TestPeerTrust_ARemovedHostIsRefusedEvenWithAHostCert — removal outranks the
// certificate, or decommissioning would stop meaning anything.
func TestPeerTrust_ARemovedHostIsRefusedEvenWithAHostCert(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-8", Address: "10.0.0.8", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.db.Execute(ctx,
		`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = 'node-8'`,
		"2026-07-30T00:00:00Z", s.db.NowTS()); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	hostCert := certCtx("node-8", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if s.isTrustedHostCN(hostCert, "node-8") {
		t.Fatal("a decommissioned host was re-admitted because it still holds its host " +
			"certificate\nremoval has to outrank the certificate; the node still has the key")
	}
}

// TestPeerTrust_ARemovedHostIsRefused is the property the check exists for, and it
// must survive the fix above.
func TestPeerTrust_ARemovedHostIsRefused(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-9", Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !s.isTrustedHostCN(ctx, "node-9") {
		t.Fatal("a live host was refused")
	}
	if err := s.db.Execute(ctx,
		`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = 'node-9'`,
		"2026-07-30T00:00:00Z", s.db.NowTS()); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if s.isTrustedHostCN(ctx, "node-9") {
		t.Fatal("a REMOVED host is still trusted as a peer\n" +
			"removal is the one thing this check exists to enforce: a decommissioned " +
			"node's certificate must stop being accepted")
	}
}

// TestPeerTrust_AnEmptyCNIsRefused — no certificate, no identity.
func TestPeerTrust_AnEmptyCNIsRefused(t *testing.T) {
	if trustFixture(t).isTrustedHostCN(context.Background(), "") {
		t.Fatal("an empty common name was accepted as a peer")
	}
}

// TestPeerTrust_AnUnreadableHostRowRefusesThePeer.
//
// Absent and unreadable are not the same, and only one of them may fall through to
// the certificate.
//
// Removal is enforced by the tombstone in the hosts table and by nothing else —
// RemoveHost soft-deletes the row and logs the cert serial, but no CRL entry is
// issued, so a decommissioned node keeps a certificate that still chains to the
// cluster CA. If a read error let the check fall through to that certificate, a
// removed host would be re-admitted by the one failure mode nobody can see.
//
// The bootstrap fix only needs the fallback when the row is DEFINITELY not there.
// An error means we cannot rule out a removal, and the original code failed closed
// on that path — discarding the GetHost error and returning false. This keeps it.
func TestPeerTrust_AnUnreadableHostRowRefusesThePeer(t *testing.T) {
	s := trustFixture(t)
	// Drop the table so the lookup errors rather than returning no rows.
	if err := s.db.Execute(context.Background(), `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}
	ctx := certCtx("node-7", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if s.isTrustedHostCN(ctx, "node-7") {
		t.Fatal("an unreadable hosts table admitted a peer on its certificate alone\n" +
			"removal is enforced only by the tombstone — no CRL entry is issued — so " +
			"falling through here re-admits a decommissioned node whenever the read fails")
	}
}
