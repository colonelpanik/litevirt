package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
