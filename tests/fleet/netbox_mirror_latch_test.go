// Fleet scenarios for the inventory mirror's CAPABILITY GATE.
//
// The mirror writes two tables an older build has never heard of —
// `netbox_objects` and `netbox_sync_queue`. A statement against a table that is
// in neither of an old peer's ledgers does not fail on that peer: the LWW apply
// path BACK-PRESSURES, which stalls the replication watermark for the WHOLE
// stream, not just those statements. So a single node upgraded and configured
// ahead of its peers must write neither, and the only thing that can decide
// that is the cluster-wide capability latch — the same contract every other
// hardening feature here honours: enabling on one node changes nothing.
//
// It cannot be shown in a single package. The latch is computed from what every
// live peer advertises over a real Ping, and "a latch that forms while the
// daemon is running" is a property of a real health.Checker, not of a bool.

package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// fleetClusterName is the `cluster` row name every fleet node is seeded with,
// and therefore the NetBox cluster the mirror resolves. Named here so a
// scenario can ask whether a cluster object was ever created at all — the
// cheapest proof that no sweep ran, because a sweep resolves its cluster before
// it reads either side of the diff and a converged sweep writes nothing else.
const fleetClusterName = "fleet"

// unlatchedMirrorCluster is a NetBox-configured, mirror-only cluster whose
// netbox_ipam_v1 latch has NOT been driven.
//
// gateAll wires a real health.Checker per node but does not close any latch:
// only an Enforced call does that, and DurablyLatched is a pure read. So this is
// the genuine mid-rolling-upgrade shape — the integration configured, the
// cluster-wide contract not yet formed.
func unlatchedMirrorCluster(t *testing.T) (*NetBoxFake, *Cluster, map[string]*health.Checker) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	c := New(t, Options{Nodes: 1, NetBoxURL: nb.URL(), SharedCRDT: true})
	gates := gateAll(t, c)
	mustCreateUnboundNetwork(t, c, c.Nodes[0], mirrorOnlyNetwork, "")
	return nb, c, gates
}

// TestMirrorWritesNothingBeforeTheLatchForms is the mixed-version contract.
//
// A node upgraded and configured while its peers are still on the old build
// must not start mirroring. Both halves are asserted from one fixture: the
// SWEEP (which writes netbox_objects) and the ENQUEUE a VM lifecycle path makes
// (which writes netbox_sync_queue). Either alone would leave the other's
// statements reaching an old peer.
func TestMirrorWritesNothingBeforeTheLatchForms(t *testing.T) {
	nb, c, _ := unlatchedMirrorCluster(t)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", mirrorOnlyNetwork)
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("an ungated pass must decline quietly, not error: %v", err)
	}

	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("%d virtual_machine object(s) mirrored before netbox_ipam_v1 latched", got)
	}
	// Nothing was even resolved: the sweep must stop before its first NetBox
	// call, not merely before its writes.
	if got := nb.ClusterID(fleetClusterName); got != 0 {
		t.Fatalf("the mirror resolved NetBox cluster %d before the latch formed", got)
	}
	// The other producer. DeleteVM enqueues the mirror's latency shortcut, which
	// is a replicated INSERT into a table an old peer does not know.
	mustDeleteVM(t, n, "vm-1")
	if got := pendingQueueItems(t, n, netboxsync.QueueKind); got != 0 {
		t.Fatalf("%d netbox_sync_queue row(s) written before netbox_ipam_v1 latched", got)
	}
}

// TestMirrorWritesNothingWithoutTheInventoryOptIn is the OTHER cluster-wide
// contract, and the one that makes the mirror optional.
//
// `netbox.mirror_inventory` is off on one of two nodes here, so netbox_mirror_v1
// cannot latch — and the node that DID opt in must still mirror nothing. That is
// the whole point of expressing the opt-in as a token instead of reading config:
// the sweep runs on whichever node holds the `netbox` leader lease, so a cluster
// that mirrored on the strength of one node's config would have its inventory
// appear and disappear with leadership, and every object the mirroring node
// created would be left to a successor that never reaps it.
//
// netbox_ipam_v1 IS latched, so the refusal can only be the mirror token's — and
// the IPAM half is asserted to keep working, because pure IPAM is the default
// shape rather than a broken one.
func TestMirrorWritesNothingWithoutTheInventoryOptIn(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	c := New(t, Options{Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true})
	// One node stays pure-IPAM. Two nodes, not one: a single-node cluster that
	// opted out would refuse locally, and this scenario is about the node that
	// opted IN being held back by a peer that did not.
	c.Nodes[1].Server.SetNetBoxMirrorInventory(false)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	// The IPAM half is unaffected: a bind still works, which is what "NetBox as
	// pure IPAM" has to mean.
	mustCreateBoundNetwork(t, c, n, orphanNetwork, orphanSubnet, orphanPrefixID)
	if gates[n.Name].Enforced(context.Background(), capabilities.NetBoxMirrorV1) {
		t.Fatal("netbox_mirror_v1 latched with mirror_inventory off on a peer")
	}

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)

	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("%d virtual_machine object(s) mirrored without a cluster-wide opt-in", got)
	}
	if got := nb.InterfaceCount(); got != 0 {
		t.Fatalf("%d vminterface object(s) mirrored without a cluster-wide opt-in", got)
	}
	// Nothing was even resolved: the pass must stop before its first NetBox
	// call, not merely before its writes.
	if got := nb.ClusterID(fleetClusterName); got != 0 {
		t.Fatalf("the mirror resolved NetBox cluster %d without a cluster-wide opt-in", got)
	}
	// …and the address the VM claimed is still in NetBox, carrying this
	// cluster's identity. Pure IPAM is the point of the default, so an
	// un-mirrored cluster whose addresses had also stopped being recorded would
	// be a different and much worse thing than "no inventory".
	if got := nb.Addresses(); len(got) == 0 {
		t.Fatal("a pure-IPAM cluster must still claim addresses in NetBox")
	}
	mustDeleteVM(t, n, "vm-1")
	if got := pendingQueueItems(t, n, netboxsync.QueueKind); got != 0 {
		t.Fatalf("%d netbox_sync_queue row(s) written without a cluster-wide opt-in", got)
	}
}

// TestMirrorStartsOnceTheLatchForms is the other half, and the reason the gate
// is read PER PASS rather than once at startup.
//
// A latch closes while the daemon runs — it is what the last node of a rolling
// upgrade completes — and nothing restarts the mirror when it does. A node that
// sampled the gate at startup would stay inert for as long as the process
// lived, which is the failure mode that turns a working rollout into a mirror
// nobody notices is dead.
func TestMirrorStartsOnceTheLatchForms(t *testing.T) {
	nb, c, gates := unlatchedMirrorCluster(t)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVM(t, n, "vm-1", mirrorOnlyNetwork)
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatal(err)
	}
	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("precondition: the pass before the latch mirrored %d object(s)", got)
	}

	// The rolling upgrade completes. Same process, same server, same reconciler
	// wiring — only the cluster-wide contracts changed. BOTH of them: the mirror
	// needs netbox_ipam_v1 for its v51 tables and netbox_mirror_v1 for the
	// inventory opt-in, and either one alone still leaves it inert.
	if !gates[n.Name].Enforced(ctx, capabilities.NetBoxIPAMV1) {
		t.Fatalf("%s: netbox_ipam_v1 failed to latch with the integration configured", n.Name)
	}
	if !gates[n.Name].DurablyLatched(capabilities.NetBoxIPAMV1) {
		t.Fatalf("%s: netbox_ipam_v1 latched only in memory", n.Name)
	}
	latchNetBoxMirror(t, c, gates)

	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the pass after the latch formed: %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("the mirror must begin on a later pass without a restart, mirrored %d object(s)", got)
	}
	if got := nb.InterfaceCount(); got != 1 {
		t.Fatalf("want the VM's interface mirrored too, got %d", got)
	}
}
