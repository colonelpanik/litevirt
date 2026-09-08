// The FOURTH cheap proxy for a complete host set, and the boundary that is left
// once it is gone.
//
// Round three of this review closed the participant set over each peer's
// ListHosts answer, which is a filtered read: it drops `deleted_at IS NULL`
// rows, and a forced host removal does not power a machine off. So a holder
// TOMBSTONED on a peer was invisible to a set that had been "closed" — closed
// over the filter rather than over the cluster — and the row-count comparison
// meant to cover that residue was balanced out by a local-only witness. Both
// checks passed and the address was freed.
//
// The set is now closed over the `hosts` ROWS each participant actually holds,
// read from the state dump the anti-entropy RPCs already serve, which is a bare
// `SELECT *` and therefore carries the tombstones ListHosts drops. The first two
// scenarios here are that fix, from both sides — the sweep that frees an address
// and the bind that hands one out.
//
// The third is the boundary, and it is SKIPPED rather than weakened: a holder
// known only to another node's GOSSIP membership, with no `hosts` row anywhere
// this node can read. Rows cannot prove anything about it, and no RPC carries a
// peer's memberlist view, so closing it needs a new field or RPC on the wire.
// The scenario stays here, intact, so that landing one is a one-line change.

package fleet

import (
	"context"
	"net"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetSweepDoesNotFreeAnAddressAPeerOnlyTombstoneHolds.
//
// The holder is running the domain that holds the MAC. The node running the
// sweep has NO row for it — the row was lost, as replication lag or a database
// loss leaves it — and its gossip does not name it either. The only record of
// the holder anywhere the sweeper can read is on the peer, TOMBSTONED.
//
// The arithmetic is the whole point. A local-only witness makes the sweeper's
// `hosts` row count equal to the peer's, so the count comparison reads as
// agreement; the witness is excluded from the participant set, so it does not
// even get asked; and the peer's ListHosts answer omits the tombstone, so a
// closure built on that answer learns nothing and closes. Every cheap check
// passes and the live holder's address is freed.
func TestFleetSweepDoesNotFreeAnAddressAPeerOnlyTombstoneHolds(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, peer, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	holder.Rejoin()
	ctx := context.Background()

	if err := sweeper.DB.Execute(ctx, "DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: peer.Name, Addr: net.JoinHostPort(peer.Address, "7946")}}
	})
	// The balance: a host the sweeper knows and the peer does not, so the two
	// `hosts` tables are the same SIZE over different members — and a witness at
	// that, so the participant filter drops it before anything is dialled.
	if err := corrosion.InsertHost(ctx, sweeper.DB, corrosion.HostRecord{
		Name: "local-only-witness", Address: "203.0.113.8", GRPCPort: 7443, Role: "witness",
		SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	// The only peer-side record of the holder is a tombstone: ListHosts omits it
	// while the table's digest still counts it.
	if err := peer.DB.Execute(ctx,
		"UPDATE hosts SET deleted_at = '2026-09-01T00:00:00Z' WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed live holder's address: %v", nb.Released())
	}
}

// TestFleetBindDoesNotHandOutTheAddressOfAPeerOnlyTombstonedHolder is the same
// invisible holder reached from the other side.
//
// The bind's inventory corroboration and the sweeper's negative proof are one
// claim about the cluster read in two directions, so a holder the bind cannot
// see is a holder whose address the next guest created is handed. The binder has
// no `hosts` row for the holder and does not see it in gossip; the peer's only
// record of it is tombstoned.
//
// Either safe outcome passes — a refused bind or a suspended one. What must not
// happen is a live binding that leases the incumbent's live address to a
// newcomer.
func TestFleetBindDoesNotHandOutTheAddressOfAPeerOnlyTombstonedHolder(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
	c := NewClusterWithNetBox(t, 3, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	binder, peer, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)

	ctx := context.Background()
	if err := binder.DB.Execute(ctx, "DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	binder.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: peer.Name, Addr: net.JoinHostPort(peer.Address, "7946")}}
	})
	if err := peer.DB.Execute(ctx,
		"UPDATE hosts SET deleted_at = '2026-09-01T00:00:00Z' WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}

	assertBindHandsOutNoHeldAddress(t, c, binder)
}

// TestFleetSweepDoesNotFreeAnAddressAGossipOnlyHolderHolds is the BOUNDARY of
// what a row-based membership proof can establish, and it is knowingly open.
//
// No node the sweeper can read has a `hosts` row for the holder — not the
// sweeper, not the peer — and the sweeper's own gossip does not name it. The
// only record of its existence anywhere is the PEER's memberlist view, and that
// is not on the wire in any form: ListHosts and ClusterStatus.hosts are both
// table-derived, GetStateDigest is counts, and PingResponse carries capabilities
// and a clock. So there is no question the sweeper can ask that would reveal it.
//
// It is skipped rather than deleted, and rather than "fixed" by delegating the
// proof to peers, because that fix is unsound in ways the outcome here would
// hide:
//
//   - delegation cannot be routed through the one helper both proofs use, so it
//     would strengthen the sweeper and leave the bind — which corroborates over
//     digests and dumps, not over the proof RPC — exactly as it is. Whatever the
//     sweeper needs to reclaim, the bind needs to go live;
//   - bounding it to one hop needs the REQUEST to say "do not delegate further",
//     and OrphanProofRequest has no field for that. The only carrier left is
//     out-of-band metadata: a field in everything but the schema, silently
//     absent from any peer that does not set it, and if it is ever lost the
//     delegation recurses across the cluster;
//   - and one hop is not enough anyway. A holder in a THIRD node's gossip, where
//     that node is itself only in the peer's gossip, is two hops away. Making
//     depth exhaustion report an incomplete proof restores soundness only if a
//     delegate can tell which participants the original caller already knows,
//     which it cannot — so the rule has to be approximated by a local set
//     difference, which is closing over a filtered source all over again.
//
// What closes this soundly is a declared way to ask a peer for its gossip
// membership; see the report accompanying this branch. Until then the proof's
// boundary is written down where it can be read, in gatherHostViews and here,
// rather than papered over.
func TestFleetSweepDoesNotFreeAnAddressAGossipOnlyHolderHolds(t *testing.T) {
	t.Skip("BLOCKED on a wire change: a peer's gossip membership is not exposed by any " +
		"RPC, and no sound one-hop delegation exists without a field to bound it. See the " +
		"doc comment above and gatherHostViews in internal/grpcapi/netbox_sweeper.go.")

	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, peer, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	holder.Rejoin()
	ctx := context.Background()
	for _, n := range []*Node{sweeper, peer} {
		if err := n.DB.Execute(ctx, "DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
			t.Fatal(err)
		}
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: peer.Name, Addr: net.JoinHostPort(peer.Address, "7946")}}
	})

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed address held by host known in peer gossip: %v", nb.Released())
	}
}
