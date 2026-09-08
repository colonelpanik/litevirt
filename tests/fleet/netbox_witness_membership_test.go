// A witness contributes MEMBERSHIP even though it never hosts a workload, and
// the sweeper's two host sets are two sets for that reason.
//
// Both scenarios here freed an address a live guest held, because the
// membership-discovery fan-out was derived from the set that excuses witnesses
// from a runtime scan:
//
//   - a host this node's `hosts` row still calls a witness, which has since been
//     made a worker and is running the domain. It was excluded from the fan-out
//     on that stale row, so the rule that a role counts only while every row
//     read agrees could never fire — the exclusion prevented the query that
//     would have refuted it.
//   - a genuine witness that is the only reachable node able to name the holder
//     at all. It runs the daemon, gossips and holds the replicated `hosts`
//     table, so it knows exactly what the proof was missing, and it was never
//     asked.
//
// Both run a real multi-node fleet: real gRPC, real host rows, real libvirt
// domains through libvirtfake. A single-package test cannot reach either shape,
// because both are about what ANOTHER node knows.

package fleet

import (
	"context"
	"net"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetSweepDoesNotFreeAnAddressAStaleWitnessRoleHides.
//
// Every node starts out recording the holder as a witness. The operator then
// promotes it to worker, and that write lands on the holder while the sweeper's
// copy is still behind replication — the ordinary shape of a mutable role, since
// `lv host config --role` writes one replicated row.
//
// The holder is running a domain with the orphan's MAC, so the address is held.
// The sweeper must ASK it: a role reading is corroborated only by every row read
// agreeing, and the holder's own row is the one that says worker.
func TestFleetSweepDoesNotFreeAnAddressAStaleWitnessRoleHides(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, holder := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", holder.Name); err != nil {
			t.Fatal(err)
		}
	}
	// The promotion lands on the holder alone; the sweeper's row stays stale.
	if _, err := c.SelfClient(holder).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: holder.Name, Role: "worker",
	}); err != nil {
		t.Fatal(err)
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	holder.Rejoin()

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed address held by worker omitted on stale local witness role: %v",
			nb.Released())
	}
}

// TestFleetSweepDoesNotFreeAnAddressOnlyAWitnessCanName.
//
// The witness here is a genuine witness — every row in the cluster agrees — so
// it is rightly excused from producing a runtime scan. It is not excused from
// being asked what it knows, and in this topology it is the only node that can
// answer: the sweeper's own row for the holder is gone and its gossip names the
// witness alone, so nothing else in the sweeper's reach records the holder's
// existence.
func TestFleetSweepDoesNotFreeAnAddressOnlyAWitnessCanName(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	if err := sweeper.DB.Execute(ctx,
		"DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: witness.Name, Addr: net.JoinHostPort(witness.Address, "7946")}}
	})

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("freed address of holder known to reachable witness: %v", nb.Released())
	}
}
