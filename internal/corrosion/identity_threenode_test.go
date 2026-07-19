package corrosion

import (
	"context"
	"testing"
)

// Three-node old/new/new-relay interleaving tests for canonical_identity_v1. Two-node lane tests
// are insufficient (the plan): a per-node lane flip must stay convergent through relay topologies
// and arbitrary arrival orders. resolveIdentity reduces a natural-key group order-invariantly for
// equivalent content (identity_test.go), so these tests exercise that end-to-end across three
// independent DBs, including an OLD node that back-pressures until it upgrades. The rows here carry
// distinct instants (no content-tie fault), so the group always converges to one id.

// idNode is one node's state in the interleaving harness.
type idNode struct {
	c  *Client
	on bool // canonical_identity latched+enabled on this node
}

func newIDNode(t *testing.T, on bool) *idNode {
	t.Helper()
	c := mustTestClient(t)
	c.SetCanonicalIdentity(func() bool { return on })
	return &idNode{c: c, on: on}
}

// currentSnapRow reads a node's row for the natural key and rebuilds a dump row to ship. Only the
// natural key + id + updated_at drive resolution, so host_name is carried through unchanged.
func currentSnapRow(t *testing.T, n *idNode, vm, name string) ([]interface{}, bool) {
	t.Helper()
	rows, err := n.c.Query(context.Background(), "SELECT id, host_name, updated_at FROM snapshots WHERE vm_name = ? AND name = ?", vm, name)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if len(rows) != 1 {
		return nil, false
	}
	return snapshotDumpRow(rows[0].String("id"), vm, rows[0].String("host_name"), name, rows[0].String("updated_at")), true
}

// gossip ships `from`'s current natural-key row to `to` via an anti-entropy dump merge. On the OLD
// (canonical-off) receiver a colliding different id hits the secondary UNIQUE and is kept-local
// (back-pressure, no error) — modelling the pre-upgrade node staying non-destructive.
func gossip(t *testing.T, from, to *idNode, vm, name string) {
	t.Helper()
	row, ok := currentSnapRow(t, from, vm, name)
	if !ok {
		return
	}
	if err := to.c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name: "snapshots", Columns: snapshotDumpCols, Rows: [][]interface{}{row},
	}}}); err != nil {
		t.Fatalf("gossip merge: %v", err)
	}
}

func snapID(t *testing.T, n *idNode, vm, name string) string {
	t.Helper()
	rows, err := n.c.Query(context.Background(), "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", vm, name)
	if err != nil {
		t.Fatalf("read id: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 row for (%s,%s), got %d", vm, name, len(rows))
	}
	return rows[0].String("id")
}

// TestThreeNodeIdentity_ConvergesRegardlessOfOrder: three nodes independently mint a different id
// for one logical snapshot (id-1 newest). Under several gossip interleavings — including a relay
// where the old node's row is carried through a new node — the two upgraded nodes ALWAYS converge
// to the same winning id, and once the old node upgrades all three converge.
func TestThreeNodeIdentity_ConvergesRegardlessOfOrder(t *testing.T) {
	const (
		vm, name = "vm1", "snap1"
		tOld     = "1000000000000-0000-nold" // oldest
		t2       = "2000000000000-0000-nnn2"
		t1       = "3000000000000-0000-nnn1" // newest ⇒ id-1 is the global winner
	)

	// Each interleaving is a sequence of directed gossip steps between node indices
	// (0=old, 1=new1, 2=new2/relay). Every case ends with the two new nodes agreeing on id-1.
	interleavings := [][][2]int{
		// direct: old→new1, new2→new1, new1→new2, old→new2
		{{0, 1}, {2, 1}, {1, 2}, {0, 2}},
		// relay: old→new2 (relay), new2→new1, new1→new2, new2→new1
		{{0, 2}, {2, 1}, {1, 2}, {2, 1}},
		// new-first then old late: new1→new2, new2→new1, old→new1, old→new2, new1→new2
		{{1, 2}, {2, 1}, {0, 1}, {0, 2}, {1, 2}},
		// fully crossed: new2→new1, old→new1, new1→new2, old→new2, new1→new2, new2→new1
		{{2, 1}, {0, 1}, {1, 2}, {0, 2}, {1, 2}, {2, 1}},
	}

	for ci, steps := range interleavings {
		nodes := []*idNode{newIDNode(t, false), newIDNode(t, true), newIDNode(t, true)}
		seedSnapshot(t, nodes[0].c, "id-old", vm, name, tOld)
		seedSnapshot(t, nodes[1].c, "id-1", vm, name, t1)
		seedSnapshot(t, nodes[2].c, "id-2", vm, name, t2)

		for _, s := range steps {
			gossip(t, nodes[s[0]], nodes[s[1]], vm, name)
		}

		if got1, got2 := snapID(t, nodes[1], vm, name), snapID(t, nodes[2], vm, name); got1 != "id-1" || got2 != "id-1" {
			t.Fatalf("interleaving %d: new nodes diverged: new1=%q new2=%q (want id-1)", ci, got1, got2)
		}
		// The old node kept its own id (non-destructive back-pressure) until it upgrades.
		if got0 := snapID(t, nodes[0], vm, name); got0 != "id-old" {
			t.Fatalf("interleaving %d: old node must keep local until upgraded, got %q", ci, got0)
		}

		// Upgrade the old node; one more gossip of the winner collapses it too.
		nodes[0].on = true
		nodes[0].c.SetCanonicalIdentity(func() bool { return true })
		gossip(t, nodes[1], nodes[0], vm, name)
		if got0 := snapID(t, nodes[0], vm, name); got0 != "id-1" {
			t.Fatalf("interleaving %d: after upgrade the old node must converge to id-1, got %q", ci, got0)
		}
	}
}
