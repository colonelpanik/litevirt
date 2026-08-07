package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestPeerBootstrap_AClusterThatHasNotMetYetCanReplicate.
//
// Multi-node by necessity, and the reason this was missed for so long: the harness
// pre-seeds every node with every other node's host row (crossRegisterHosts), so a
// fleet cluster starts in a state a real one has to REACH. Peer mTLS accepted only
// a CN naming a live host row, hosts are learned by replication, and replication is
// what the check gates — so a genuinely fresh cluster, where each node holds
// exactly its own row, could never converge.
//
// Found on the lab, where four freshly provisioned nodes sat refusing each other
// with "replication RPC requires peer mTLS" until all four rows were seeded onto
// all four nodes by hand. This deletes the harness's head start to get the real
// starting state.
func TestPeerBootstrap_AClusterThatHasNotMetYetCanReplicate(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	// Undo the harness's cross-registration: each node knows only itself, which is
	// what `lv host init` + `lv host add` actually produce.
	for _, n := range c.Nodes {
		for _, other := range c.Nodes {
			if other.Name == n.Name {
				continue
			}
			if err := n.DB.Execute(ctx, `DELETE FROM hosts WHERE name = ?`, other.Name); err != nil {
				t.Fatalf("un-register %s on %s: %v", other.Name, n.Name, err)
			}
		}
		names, err := hostNames(ctx, n.DB)
		if err != nil {
			t.Fatalf("read hosts on %s: %v", n.Name, err)
		}
		if len(names) != 1 {
			t.Fatalf("%s should know only itself, knows %v", n.Name, names)
		}
	}

	// A REPLICATION RPC from a node b has never heard of must be accepted, or
	// nothing can ever teach b that a exists. ListHosts would not do: it is allowed
	// for client-role callers too, so it passes either way.
	_, err := c.PeerClient(a, b).PushMutations(ctx, &pb.ReplicateRequest{Sender: a.Name})
	if err != nil {
		t.Fatalf("replication between two nodes that do not know each other was refused: %v\n"+
			"peers are learned by replication and this is what gates replication, so a "+
			"cluster in this state can never leave it", err)
	}
}

// TestPeerBootstrap_ARemovedHostStaysRefused.
//
// The property the CN check exists for, across two nodes rather than one: after a
// host is decommissioned its certificate must stop being accepted, and the fix for
// the deadlock above must not have traded that away. Removal tombstones the row, so
// "removed" is still distinguishable from "never seen".
func TestPeerBootstrap_ARemovedHostStaysRefused(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	if _, err := c.PeerClient(a, b).PushMutations(ctx, &pb.ReplicateRequest{Sender: a.Name}); err != nil {
		t.Fatalf("baseline replication failed: %v", err)
	}

	// b decommissions a.
	if err := b.DB.Execute(ctx,
		`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		"2026-07-30T00:00:00Z", b.DB.NowTS(), a.Name); err != nil {
		t.Fatalf("tombstone %s on %s: %v", a.Name, b.Name, err)
	}

	_, err := c.PeerClient(a, b).PushMutations(ctx, &pb.ReplicateRequest{Sender: a.Name})
	if err == nil {
		t.Fatalf("%s still accepts replication from %s after removing it\n"+
			"a decommissioned node's certificate has to stop working — that is the one "+
			"thing the host-row check is for", b.Name, a.Name)
	}
	if !strings.Contains(err.Error(), "PermissionDenied") && !strings.Contains(err.Error(), "permission") {
		t.Errorf("want a permission failure for a removed peer, got %v", err)
	}
}

// TestPeerBootstrap_ARemovedHostCanReturnOnlyWithAFreshCertificate.
//
// A deliberate re-add has to clear the replicated tombstone without reviving
// the identity that was removed. This needs three daemons to prove both sides:
// the admitting node records the new serial, a peer learns that admission by
// replication, and the peer refuses the old certificate even before it has
// received the CRL. Once the CRL arrives, the fresh identity must still work.
func TestPeerBootstrap_ARemovedHostCanReturnOnlyWithAFreshCertificate(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b, peer := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	oldSerial, err := pki.CertSerial(filepath.Join(a.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("read old certificate serial: %v", err)
	}
	oldPKIDir := filepath.Join(t.TempDir(), "old-identity")
	if err := os.MkdirAll(oldPKIDir, 0o700); err != nil {
		t.Fatalf("create old identity directory: %v", err)
	}
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		if err := copyFile(filepath.Join(a.PKIDir, name), filepath.Join(oldPKIDir, name)); err != nil {
			t.Fatalf("preserve old %s: %v", name, err)
		}
	}
	oldIdentity := &Node{Name: a.Name, PKIDir: oldPKIDir}

	// Model the converged host-removal tombstone. Fixed timestamps ensure the
	// later admission wins deterministically when b's state is merged into peer.
	for _, n := range []*Node{a, b, peer} {
		if err := n.DB.Execute(ctx,
			`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			"2026-07-30T00:00:00Z", "2026-07-30T00:00:00Z", a.Name); err != nil {
			t.Fatalf("tombstone %s on %s: %v", a.Name, n.Name, err)
		}
	}

	// The CA issues a different identity for the same host name, as host add
	// does when intentionally returning a removed machine to the cluster.
	c.mintHostCert(a)
	freshSerial, err := pki.CertSerial(filepath.Join(a.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("read fresh certificate serial: %v", err)
	}
	if strings.EqualFold(oldSerial, freshSerial) {
		t.Fatalf("replacement certificate reused removed serial %s", oldSerial)
	}

	if _, err := c.SelfClient(b).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: a.Name, Address: a.Address, CertSerial: freshSerial,
	}); err != nil {
		t.Fatalf("admit fresh identity on %s: %v", b.Name, err)
	}
	if err := corrosion.RegisterHost(ctx, a.DB, corrosion.HostRecord{
		Name: a.Name, Address: a.Address, SSHUser: "root", SSHPort: 22,
		GRPCPort: a.Port, State: "active", CertSerial: freshSerial,
	}); err != nil {
		t.Fatalf("fresh host could not clear its local tombstone at startup: %v", err)
	}
	peer.DB.MergeStateBytesLWW(pullDump(t, c, b))

	// No CRL has reached peer yet. Rejection here therefore proves that the
	// replicated admission binds the host name to the replacement serial.
	if _, err := c.PeerClient(oldIdentity, peer).PushMutations(ctx,
		&pb.ReplicateRequest{Sender: a.Name}); err == nil {
		t.Fatal("peer accepted the removed certificate after learning the fresh admission")
	}
	if _, err := c.PeerClient(a, peer).PushMutations(ctx,
		&pb.ReplicateRequest{Sender: a.Name}); err != nil {
		t.Fatalf("peer refused the freshly admitted certificate: %v", err)
	}

	// Finish the removal path by publishing and replicating the revocation.
	oldSerialInt := hostSerial(t, oldIdentity)
	revokeOn(t, c, b, oldSerialInt)
	peer.DB.MergeStateBytesLWW(pullDump(t, c, b))
	if _, err := corrosion.SyncClusterCRL(ctx, peer.DB, peer.PKIDir); err != nil {
		t.Fatalf("install replicated CRL on %s: %v", peer.Name, err)
	}
	if !pki.IsCertRevoked(peer.PKIDir, oldSerialInt) {
		t.Fatalf("%s did not enforce revocation of the removed identity", peer.Name)
	}
	if _, err := c.PeerClient(oldIdentity, peer).PushMutations(ctx,
		&pb.ReplicateRequest{Sender: a.Name}); err == nil {
		t.Fatal("peer accepted the removed certificate after installing its CRL")
	}
	if _, err := c.PeerClient(a, peer).PushMutations(ctx,
		&pb.ReplicateRequest{Sender: a.Name}); err != nil {
		t.Fatalf("CRL for the removed serial also blocked the fresh identity: %v", err)
	}
}

func hostNames(ctx context.Context, db *corrosion.Client) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT name FROM hosts WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// TestPeerBootstrap_OutboundPeerRPCsWorkBeforeConvergence.
//
// The inbound half of peer trust was fixed without the outbound half. Accepting an
// RPC from a peer whose row has not replicated is only useful if you can also DIAL
// one: grpcapi's peerClient did a bare GetHost and gave up with "host %q not found
// in cluster state", so on a genuinely fresh cluster every outbound grpcapi peer
// call still failed — self-upgrade version pings, cluster-state digest fanout,
// anti-entropy triggers, backup sink pushes, console forwarding.
//
// corrosion already solved this: resolvePeerTarget falls back to the gossip
// membership address, and its doc comment names this exact case, which is why the
// replicator and anti-entropy were never deadlocked. grpcapi held a second,
// half-implemented copy of the same lookup.
//
// The harness pre-seeds every host row (crossRegisterHosts), which is what hid both
// halves; this deletes that head start to reach the real starting state.
func TestPeerBootstrap_OutboundPeerRPCsWorkBeforeConvergence(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	// a has never heard of b — no replicated row, only gossip membership, which is
	// what a node actually has for a peer that has just been provisioned.
	if err := a.DB.Execute(ctx, `DELETE FROM hosts WHERE name = ?`, b.Name); err != nil {
		t.Fatalf("un-register %s on %s: %v", b.Name, a.Name, err)
	}
	a.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: b.Name, Addr: fmt.Sprintf("%s:7946", b.Address)}}
	})

	_, conn, err := a.Server.PeerClientForTests(ctx, b.Name)
	if err != nil {
		t.Fatalf("dialling a peer whose row has not replicated failed: %v\n"+
			"the inbound side accepts this peer, so refusing to dial it leaves the fix "+
			"half-done: every outbound grpcapi peer RPC fails until the hosts table "+
			"converges, on exactly the fresh cluster that cannot converge without them", err)
	}
	if conn != nil {
		_ = conn.Close()
	}
}

// TestPeerBootstrap_DiallingAnEntirelyUnknownPeerStillFails — the fallback is to
// gossip, not to guesswork. A name in neither the hosts table nor the membership
// has no address, and must still be an error rather than a dial to nowhere.
func TestPeerBootstrap_DiallingAnEntirelyUnknownPeerStillFails(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 1})
	defer c.Stop()

	if _, conn, err := c.Nodes[0].Server.PeerClientForTests(ctx, "ghost-node"); err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dialling a peer that is in neither cluster state nor gossip succeeded")
	}
}
