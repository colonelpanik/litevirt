// The FOURTH cheap proxy for a complete host set, and what replaced the last of
// them.
//
// Round three of this review closed the participant set over each peer's
// ListHosts answer, which is a filtered read: it drops `deleted_at IS NULL`
// rows, and a forced host removal does not power a machine off. So a holder
// TOMBSTONED on a peer was invisible to a set that had been "closed" — closed
// over the filter rather than over the cluster — and the row-count comparison
// meant to cover that residue was balanced out by a local-only witness. Both
// checks passed and the address was freed.
//
// Closing the set over each participant's `hosts` ROWS, read out of the state
// dump, fixed those two. It could not fix the third, and the reason was
// structural: a holder known only to another node's GOSSIP membership has no row
// anywhere, so no table-derived answer — ListHosts, ClusterStatus.hosts, a state
// digest, a state dump — can name it.
//
// All three are now closed over each participant's own MEMBERSHIP VIEW
// (GetMembershipView): its `hosts` rows, tombstones included and each carrying
// the role the exclusions turn on, plus its gossip members, plus an explicit
// completeness flag. The state-dump path is gone rather than kept alongside it —
// two mechanisms answering one question is how the count-versus-content
// confusion survived three rounds here.
//
// The scenarios below are that fix from three directions: the sweep that frees
// an address, the bind that hands one out, and the gossip-only holder no row can
// see.

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
// agreement, and the peer's ListHosts answer omits the tombstone, so a closure
// built on that answer learns nothing and closes. Every cheap check passes and
// the live holder's address is freed.
//
// The witness's ROLE is no longer part of why: rounds four and five removed the
// exclusion that skipped a witness from the fan-out, so today the witness IS
// asked what it knows and is excused only from the runtime scan. What keeps this
// scenario safe now is that the local-only witness has no daemon, so the closure
// cannot complete over it at all — the fail-closed direction. The role is
// retained here because the row-count arithmetic is what the scenario is about.
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
	// The peer's gossip does not name the holder either, so its TOMBSTONED ROW is
	// the only record of the holder anywhere: the outcome turns on that row and
	// not on the membership view's gossip half, which the scenario below covers.
	peer.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: sweeper.Name, Addr: net.JoinHostPort(sweeper.Address, "7946")}}
	})
	// The balance: a host the sweeper knows and the peer does not, so the two
	// `hosts` tables are the same SIZE over different members. Its role is
	// `witness` only to keep it out of the RUNTIME scan; it is asked what it
	// knows like any other host, and having no daemon it cannot answer — which
	// is what leaves the closure open here.
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
	// As above: with the holder out of the peer's gossip too, its tombstoned row
	// is the only thing that can reveal it.
	peer.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: binder.Name, Addr: net.JoinHostPort(binder.Address, "7946")}}
	})
	if err := peer.DB.Execute(ctx,
		"UPDATE hosts SET deleted_at = '2026-09-01T00:00:00Z' WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}

	assertBindHandsOutNoHeldAddress(t, c, binder)
}

// TestFleetSweepDoesNotFreeAnAddressAGossipOnlyHolderHolds is the shape no
// amount of reading ROWS could ever have reached.
//
// No node the sweeper can read has a `hosts` row for the holder — not the
// sweeper, not the peer — and the sweeper's own gossip does not name it either.
// The only record of its existence anywhere is the PEER's memberlist view, which
// no table records and therefore no table-derived answer can carry: ListHosts and
// ClusterStatus.hosts are both derived from `hosts`, GetStateDigest is counts,
// and a state dump is tables. Gossip has to be asked for directly.
//
// GetMembershipView asks for it, so the sweeper learns the holder's NAME from
// the peer and the reclamation stops — either because the holder answers that it
// holds the MAC, or because a host this node cannot resolve cannot be asked and
// an unanswered participant leaves the set unclosed. Both are the fail-closed
// direction, and the assertion is deliberately about the address rather than
// about which of the two happened.
//
// Delegation was considered as a cheaper fix and rejected as unsound, not merely
// unavailable: a peer answering CollectOrphanProof for its own gossip-only
// members cannot be routed through the one helper both proofs use, so it would
// strengthen the sweeper and leave the bind exactly as it is; OrphanProofRequest
// has no field to bound the hop, leaving only out-of-band metadata that is
// silently absent from any peer that does not set it; and one hop is not enough
// anyway, since a holder in a THIRD node's gossip is two hops away.
func TestFleetSweepDoesNotFreeAnAddressAGossipOnlyHolderHolds(t *testing.T) {
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
