// Fleet scenario: a certificate revocation reaches the nodes that have to enforce it.
//
// Removing a host revokes its certificate, and until now nothing carried that
// revocation anywhere. The CRL was written on whichever machine held the CA key
// and copied around by hand — so the security of a removal came down to an
// operator remembering to scp a file, and a node that missed it kept accepting a
// decommissioned host's certificate with nothing reporting the fact.
//
// internal/pki covers what one node does with a CRL it is handed. What only a
// multi-node test can show is the part that matters operationally: node B, which
// holds no CA private key and did nothing but replicate, ends up enforcing a
// revocation node A minted — and does not end up enforcing one nobody signed.

package fleet

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// hostSerial reads a node's own certificate serial — the value `lv host rm`
// revokes, and the one a peer checks every handshake.
func hostSerial(t *testing.T, n *Node) *big.Int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(n.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("read %s host.crt: %v", n.Name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s host.crt has no PEM block", n.Name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s host.crt: %v", n.Name, err)
	}
	return cert.SerialNumber
}

// revokeOn mints a CRL on one node the way `lv host rm` does — locally, with the
// CA private key — and publishes it through the RPC the CLI calls.
func revokeOn(t *testing.T, c *Cluster, n *Node, serial *big.Int) {
	t.Helper()
	crlPath := filepath.Join(n.PKIDir, "crl.pem")
	if err := pki.AppendToCRL(
		filepath.Join(n.PKIDir, "ca.crt"), filepath.Join(n.PKIDir, "ca.key"),
		crlPath, serial.Text(16)); err != nil {
		t.Fatalf("revoke %s on %s: %v", serial.Text(16), n.Name, err)
	}
	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("read the CRL just written on %s: %v", n.Name, err)
	}
	if _, err := c.SelfClient(n).PublishCRL(context.Background(),
		&pb.PublishCRLRequest{CrlPem: string(crlPEM)}); err != nil {
		t.Fatalf("PublishCRL on %s: %v", n.Name, err)
	}
}

func TestFleet_ARevocationReachesAPeerThatHoldsNoCAKey(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, victim := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	serial := hostSerial(t, victim)

	if pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatal("node-1 started out revoking a certificate nobody revoked")
	}

	revokeOn(t, c, a, serial)
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	version, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir)
	if err != nil {
		t.Fatalf("SyncClusterCRL on %s: %v", b.Name, err)
	}
	if version == 0 {
		t.Fatalf("%s found nothing to install after %s revoked %s — a removal that only "+
			"convinces the node that performed it is not a removal", b.Name, a.Name, victim.Name)
	}
	if !pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatalf("%s is not enforcing the revocation of %s", b.Name, victim.Name)
	}

	// Running again is a no-op, not a reinstall: the sync runs every 30s forever.
	if again, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir); err != nil || again != 0 {
		t.Fatalf("second sync reported (%d, %v), want (0, nil)", again, err)
	}
}

// The move this table's shape exists to defeat. The host being revoked is a peer
// until the revocation lands, so it can write to cluster_crl — and the cheapest
// attack is to publish a CRL of its own at a number above the genuine one. It
// cannot sign one the cluster CA will accept, so the only question is whether an
// unsignable row can bury the real one.
func TestFleet_AForgedCRLCannotBuryTheRealOne(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, victim := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	serial := hostSerial(t, victim)

	revokeOn(t, c, a, serial)
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	// node-2 mints its own CA and a CRL revoking nothing, and publishes it.
	rogueDir := filepath.Join(t.TempDir(), "rogue")
	mintRoguePKI(t, rogueDir, victim.Name)
	rogueCRL := filepath.Join(rogueDir, "crl.pem")
	if err := pki.GenerateCRL(filepath.Join(rogueDir, "ca.crt"), filepath.Join(rogueDir, "ca.key"),
		rogueCRL, nil); err != nil {
		t.Fatalf("mint rogue CRL: %v", err)
	}
	roguePEM, err := os.ReadFile(rogueCRL)
	if err != nil {
		t.Fatalf("read rogue CRL: %v", err)
	}
	if err := corrosion.PublishCRL(ctx, b.DB, string(roguePEM)); err != nil {
		t.Fatalf("publish rogue CRL: %v", err)
	}

	if _, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir); err != nil {
		t.Fatalf("SyncClusterCRL on %s: %v", b.Name, err)
	}
	if !pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatalf("%s stopped enforcing the revocation of %s after %s published a CRL "+
			"signed by a CA the cluster never trusted", b.Name, victim.Name, victim.Name)
	}
}

// TestFleet_AnOldGenuineCRLCannotPinTheCluster.
//
// The attack the first version of this shipped wide open. Ordering came from a
// `version` COLUMN, which is peer-supplied and covered by no signature, and the
// sync stopped at the first row that verified. So a host about to be removed did
// not need to forge anything: re-publishing an OLD genuine CRL — which verifies
// perfectly — was enough to make every node stop there and never install the
// revocation naming it. The operator saw "published CRL N to the cluster".
//
// Ordering now comes from the number INSIDE the signed CRL, and every row is
// considered, so a replayed CRL is just an older one.
func TestFleet_AnOldGenuineCRLCannotPinTheCluster(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, victim := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")

	// CRL 1 revokes node-1. Keep a copy — this is what the attacker replays.
	revokeOn(t, c, a, hostSerial(t, b))
	stale, err := os.ReadFile(filepath.Join(a.PKIDir, "crl.pem"))
	if err != nil {
		t.Fatalf("keep a copy of the first CRL: %v", err)
	}

	// CRL 2 additionally revokes node-2 — the revocation that must survive.
	serial := hostSerial(t, victim)
	revokeOn(t, c, a, serial)

	// The replay, published AFTER the newer CRL and therefore the most recently
	// written row in the table.
	if err := corrosion.PublishCRL(ctx, a.DB, string(stale)); err != nil {
		t.Fatalf("replay the old CRL: %v", err)
	}
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	if _, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir); err != nil {
		t.Fatalf("SyncClusterCRL on %s: %v", b.Name, err)
	}
	if !pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatalf("%s did not install the newer CRL after an OLD genuine one was republished — "+
			"replaying a CRL anyone can read must not be able to suppress a revocation", b.Name)
	}
}

// TestFleet_ATombstoneCannotBuryARevocation.
//
// cluster_crl shares its anti-entropy merge floor with the audit evidence tables,
// and that floor deliberately does not refuse tombstones — on the stated grounds
// that "the verifier ignores deleted_at on these tables, so a tombstone
// accomplishes nothing". That was true of the tables it was written for and false
// here the moment the reader filtered `deleted_at IS NULL`: a peer could tombstone
// the row carrying a revocation and hide it from every node that had not already
// installed it. The reader ignores deleted_at now, which makes the shared floor's
// claim true again.
func TestFleet_ATombstoneCannotBuryARevocation(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, victim := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	serial := hostSerial(t, victim)

	revokeOn(t, c, a, serial)
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	// What the host being revoked does with the peer credentials it still holds.
	if err := b.DB.Execute(ctx,
		`UPDATE cluster_crl SET deleted_at = ?, updated_at = ?`, b.DB.NowTS(), b.DB.NowTS()); err != nil {
		t.Fatalf("tombstone the CRL row: %v", err)
	}

	if _, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir); err != nil {
		t.Fatalf("SyncClusterCRL on %s: %v", b.Name, err)
	}
	if !pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatalf("%s stopped enforcing the revocation of %s after the row was tombstoned — "+
			"a revocation must not be removable by anyone who can write to the table",
			b.Name, victim.Name)
	}
}

// TestFleet_SquattedRowsCannotBlockAGenuineRevocation.
//
// The table was keyed by CRL NUMBER, and the number is a wall-clock second — so
// the number of the next revocation is predictable within a second. A host about
// to be removed could insert rows for the next hour's worth of numbers and every
// genuine publication after that would lose: INSERT OR IGNORE on the replicated
// apply path, a primary-key error locally.
//
// The key is the hash of the CRL now, so occupying the row a future CRL will land
// in means producing that CRL's exact bytes, signature included.
func TestFleet_SquattedRowsCannotBlockAGenuineRevocation(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, victim := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	serial := hostSerial(t, victim)

	// The squatter, writing before the operator acts.
	for i := 0; i < 32; i++ {
		if err := corrosion.PublishCRL(ctx, a.DB, fmt.Sprintf("not a CRL at all #%d", i)); err != nil {
			t.Fatalf("squat row %d: %v", i, err)
		}
	}

	revokeOn(t, c, a, serial) // must still publish
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	if _, err := corrosion.SyncClusterCRL(ctx, b.DB, b.PKIDir); err != nil {
		t.Fatalf("SyncClusterCRL on %s: %v", b.Name, err)
	}
	if !pki.IsCertRevoked(b.PKIDir, serial) {
		t.Fatalf("%s never installed the revocation of %s after the table was squatted",
			b.Name, victim.Name)
	}
}

// Publishing the same CRL twice is documented as inert, and `lv host rm` tells the
// operator a publish failure means the revocation did not reach the cluster. A
// primary-key collision reported as an error made that message a lie on any retry.
func TestFleet_RepublishingTheSameCRLIsANoOp(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, victim := c.Node("node-0"), c.Node("node-1")

	revokeOn(t, c, a, hostSerial(t, victim))
	crlPEM, err := os.ReadFile(filepath.Join(a.PKIDir, "crl.pem"))
	if err != nil {
		t.Fatalf("read the CRL: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := corrosion.PublishCRL(ctx, a.DB, string(crlPEM)); err != nil {
			t.Fatalf("republish #%d reported failure for a CRL already published: %v", i, err)
		}
	}
}
