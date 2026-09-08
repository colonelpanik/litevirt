// Fleet scenarios for the NetBox inventory mirror.
//
// The mirror is a DESIRED-STATE DIFF driven by a leader-gated sweep. Three
// properties can only be shown multi-node, and every scenario here is one of
// them: exactly one of N masterless nodes writes; an outgoing leader stops
// mid-sweep rather than racing the incoming one; and the sweep — not the sync
// queue — is what makes the mirror correct.
//
// They run on a SHARED CRDT database on purpose. The leader lease is a
// `leader_election` row, so on the default per-node databases every node would
// hold its own copy of the lease and "exactly one writer" would be unprovable —
// the gate would read as held everywhere and the scenario would fail whether or
// not the gate existed.

package fleet

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

func TestExactlyOneNodeMirrors(t *testing.T) {
	nb, c := boundMirrorCluster(t, 3)

	mustCreateVM(t, c.Nodes[0], "vm-1", "bound")
	mustSyncAllNodes(t, c)

	// Three masterless nodes must not all write inventory.
	if n := nb.VMCount("vm-1"); n != 1 {
		t.Fatalf("want exactly one virtual_machine object, got %d", n)
	}
	if writers := nb.DistinctWriters(); len(writers) != 1 {
		t.Fatalf("want one writer, got %v", writers)
	}
}

func TestOutgoingLeaderStopsMidSweep(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)

	// More VMs than one write batch holds, so the lease is re-validated INSIDE
	// a single phase. With a fixture that fits in one batch, a check made once
	// per sweep and a check made per batch would both let the first batch
	// through and the scenario could not tell them apart.
	const vms = mirrorBatchSize + 5
	for i := 0; i < vms; i++ {
		mustCreateVM(t, c.Nodes[0], vmName(i), "bound")
	}
	c.Nodes[0].ExpireLeaderLeaseAfter(1) // lease lost after the first write batch

	_ = c.Nodes[0].SyncNetBoxMirror()

	// TTL is re-validated before each batch, so writes stop rather than racing
	// the incoming leader.
	if nb.VMCountAll() >= vms {
		t.Fatalf("an outgoing leader must stop writing when its lease expires, mirrored %d of %d",
			nb.VMCountAll(), vms)
	}
	// ...and it must have got far enough to be a genuine MID-sweep stop. A
	// mirror that wrote nothing at all would satisfy the check above while
	// proving nothing about the batch boundary.
	if nb.VMCountAll() == 0 {
		t.Fatal("nothing was mirrored at all — the scenario never reached a batch boundary")
	}
}

func TestSyncCorrectWithQueueEmptied(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)

	mustCreateVM(t, c.Nodes[0], "vm-1", "bound")
	// The latency shortcut, then the loss: a node that died mid-create never
	// enqueued at all, and one that enqueued may have had its item drained by a
	// peer that then died. Both leave the same empty queue.
	enqueueMirrorItem(t, c.Nodes[0], "vm-1")
	c.Nodes[0].ClearSyncQueue()

	mustSyncAllNodes(t, c)

	// The full sweep, not the queue, is the correctness mechanism.
	if nb.VMCount("vm-1") != 1 {
		t.Fatalf("the full sweep must mirror a VM whose queue entry was lost, got %d objects",
			nb.VMCount("vm-1"))
	}
}

// TestSecondSweepIssuesNoPatches is the generic guard against a field the
// mirror writes in one unit and reads back in another.
//
// NetBox's virtual_machine.disk is megabytes and it echoes a MAC UPPER-cased;
// either mismatch makes the diff see drift on state that never changed, and the
// mirror PATCHes the same objects on every sweep forever — burying NetBox's
// changelog and hammering its API. A converged mirror issues no writes at all.
//
// The VM carries a REAL DISK deliberately. Mirrored with no disks at all its
// `disk` is 0 on both sides of the diff, and 0 is the one value every unit
// agrees on — so this scenario passed while the field was written in gibibytes
// and read back as megabytes, which is how that bug survived to review.
func TestSecondSweepIssuesNoPatches(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)

	mustCreateVMWithDiskOnNetwork(t, c, c.Nodes[0], "vm-1", "bound")
	mustSyncAllNodes(t, c)
	if nb.VMCount("vm-1") != 1 || nb.InterfaceCount() != 1 {
		t.Fatalf("precondition: want one VM and one interface mirrored, got %d/%d",
			nb.VMCount("vm-1"), nb.InterfaceCount())
	}
	if got := nb.VMDisk("vm-1"); got <= 0 {
		t.Fatalf("precondition: the mirrored disk is %d, so the unit half of this "+
			"scenario would be vacuous", got)
	}

	before := nb.PatchCount()
	mustSyncAllNodes(t, c) // nothing changed in litevirt
	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("a second sweep over unchanged state issued %d PATCH requests, want 0 "+
			"(a field is being written in one unit and read back in another)", got)
	}
}

// TestMirroredDiskIsDecimalMegabytes pins the UNIT of the value the mirror
// writes, end to end from a real disk row.
//
// The round trip alone cannot do it: the fake echoes `disk` verbatim, so a value
// written in the wrong unit reads back in the wrong unit and compares equal to
// itself. Only an assertion on the number NetBox ends up holding can tell
// megabytes from gibibytes.
func TestMirroredDiskIsDecimalMegabytes(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)

	// A 64M disk: 67,108,864 bytes.
	mustCreateVMWithDiskOnNetwork(t, c, c.Nodes[0], "vm-1", "bound")
	mustSyncAllNodes(t, c)

	// NetBox's megabyte is DECIMAL (1 MB = 1,000,000 bytes) and the conversion
	// rounds UP, so 67,108,864 bytes is 68 MB — never 67, and never the 1 that
	// a gibibyte-rounded quota figure would have recorded.
	if got := nb.VMDisk("vm-1"); got != 68 {
		t.Fatalf("mirrored disk = %d, want 68 (decimal MB, rounded up from a 64 MiB disk)", got)
	}
}

// TestOrphanChecksAreNotStarvedByMirrorItems pins the queue-kind filter.
//
// One `netbox_sync_queue` now has two producers. The sweeper drains the oldest
// items and SKIPS a kind it does not own without acking it, so an unfiltered
// drain whose first batch is all mirror items never reaches an orphan check —
// and the orphan check is the only stuck-lease detector there is.
func TestOrphanChecksAreNotStarvedByMirrorItems(t *testing.T) {
	_, c := boundClusterWithOrphan(t, 2)
	n := c.Nodes[0]

	// Older than the orphan check, and more of them than one drain batch holds.
	seedOldMirrorQueueItems(t, n, 100)
	enqueueOrphanCheck(t, n, orphanIdentity(t, n))

	mustSweep(t, n)

	if got := pendingQueueItems(t, n, "orphan"); got != 0 {
		t.Fatalf("%d orphan checks still queued — mirror items at the head starved the "+
			"only stuck-lease detector there is", got)
	}
	// The sweeper must not ack another component's work either.
	if got := pendingQueueItems(t, n, netboxsync.QueueKind); got != 100 {
		t.Fatalf("the sweeper acked %d mirror items; they belong to the mirror", 100-got)
	}
}

// TestDualRunSemanticsUnchanged is the regression guard on the boundary between
// the two detectors that both ask "is this workload alive?".
//
// The orphan proof counts a STOPPED-but-defined domain as a holder — a defined
// domain can be started at any moment, so its address is not free. The dual-run
// detector must NOT: diskHolderVMs feeds an alert-grade pager, and a stopped
// domain on a second host is the normal aftermath of a migration, not a
// dual-writer. That is why the orphan proof got its own type instead of
// widening runtimeSnapshot. Both halves are asserted from ONE fixture, because
// asserting either alone would let the two be merged.
func TestDualRunSemanticsUnchanged(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[1].Virt.DefineStoppedDomain("ghost", orphanMAC)

	mustSweep(t, c.Nodes[0])
	if len(nb.Identities()) != 1 {
		t.Fatalf("a stopped-but-defined domain must block reclamation, released %v", nb.Released())
	}

	inv, err := c.SelfClient(c.Nodes[1]).GetRuntimeInventory(
		context.Background(), &pb.GetRuntimeInventoryRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInventory on %s: %v", c.Nodes[1].Name, err)
	}
	var seen bool
	for _, w := range inv.GetWorkloads() {
		if w.GetName() != "ghost" {
			continue
		}
		seen = true
		if w.GetDiskHolder() {
			t.Fatal("a stopped-but-defined domain must not be a dual-run disk holder — " +
				"every migration would page")
		}
	}
	if !seen {
		t.Fatal("the stopped domain is absent from the inventory — the assertion would be vacuous")
	}
}

// --- helpers -----------------------------------------------------------------

// mirrorBatchSize mirrors netboxsync's batchSize. It is duplicated rather than
// exported because the fixture only needs to be BIGGER than one batch; a
// scenario reaching into the package for the exact number would still be right
// if the constant changed.
const mirrorBatchSize = 20

// vmName names the i-th fixture VM.
func vmName(i int) string { return fmt.Sprintf("vm-%02d", i) }

// boundMirrorCluster is boundCluster on a SHARED database, so `leader_election`
// is one row the whole fleet contends for. See the file comment.
func boundMirrorCluster(t *testing.T, nodes int) (*NetBoxFake, *Cluster) {
	t.Helper()
	nb, c, _ := boundMirrorClusterGated(t, nodes)
	return nb, c
}

// boundMirrorClusterGated is boundMirrorCluster that also hands back the
// capability gates.
//
// A scenario driving a QUORUM-gated operation — a migration re-checks the
// split-brain execution gate twice on the source — has to reach the gate it
// wants to steer, and it must steer the one already wired rather than build a
// second Checker: the netbox_ipam_v1 latch these fixtures depend on lives in
// that value.
func boundMirrorClusterGated(t *testing.T, nodes int) (*NetBoxFake, *Cluster, map[string]*health.Checker) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	c := New(t, Options{Nodes: nodes, NetBoxURL: nb.URL(), SharedCRDT: true})
	gates := gateAll(t, c)
	// BOTH NetBox latches: the bind needs netbox_ipam_v1, and the mirror
	// additionally needs netbox_mirror_v1 — the inventory opt-in a pure-IPAM
	// cluster never forms.
	latchNetBoxBoth(t, c, gates)
	mustCreateBoundNetwork(t, c, c.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)
	publishClusterNamesEverywhere(t, c)
	return nb, c, gates
}

// publishClusterNamesEverywhere brings the fixture to the state a real cluster
// reaches on its own: every configured node has declared the NetBox cluster name
// it resolves.
//
// Required because the mirror now DECLINES a pass in which a live host has
// published nothing — it cannot prove `netbox.cluster_name` is uniform against a
// set it knows to be incomplete. In production every node publishes on its own
// first maintenance pass, so the window is one interval; in a fixture, a
// scenario that drives a pass on ONE node would sit in that window forever and
// be testing the wait rather than whatever it meant to test.
//
// It uses the production publisher (the revalidation pass), not a hand-written
// row, so a scenario cannot be made to pass by a fixture that publishes
// something the daemon would not.
func publishClusterNamesEverywhere(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := n.Server.RevalidateBindingsOnce(context.Background()); err != nil {
			t.Fatalf("publish pass on %s: %v", n.Name, err)
		}
	}
}

// mustCreateVM creates a one-NIC VM pinned to n.
func mustCreateVM(t *testing.T, n *Node, name, netName string) *pb.VM {
	t.Helper()
	return mustCreateVMOnNetwork(t, n.cluster, n, name, netName)
}

// mustSyncAllNodes drives ONE mirror pass on EVERY node, CONCURRENTLY.
//
// Every node runs a pass, exactly as every configured node runs the loop in
// production; the leader gate — not the caller — is what makes one of them the
// writer.
//
// Concurrent is load-bearing, not incidental. Driven one after another, an
// UNGATED mirror produces the same NetBox state as a gated one: the second node
// finds the first node's object by identity and adopts it, so search-before-
// create alone would make the scenario pass with the leader gate deleted. N
// tickers do not take turns, and a race between three searches that all come
// back empty is exactly what the gate exists to prevent.
func mustSyncAllNodes(t *testing.T, c *Cluster) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, len(c.Nodes))
	for i, n := range c.Nodes {
		wg.Add(1)
		go func(i int, n *Node) {
			defer wg.Done()
			errs[i] = n.SyncNetBoxMirror()
		}(i, n)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("mirror sync on %s: %v", c.Nodes[i].Name, err)
		}
	}
}

// enqueueMirrorItem records the latency shortcut a lifecycle operation leaves
// for the mirror.
func enqueueMirrorItem(t *testing.T, n *Node, key string) {
	t.Helper()
	if err := corrosion.EnqueueSync(context.Background(), n.DB, netboxsync.QueueKind, key, "upsert"); err != nil {
		t.Fatalf("enqueue mirror item on %s: %v", n.Name, err)
	}
}

// enqueueOrphanCheck records the item a failed create-compensation leaves for
// the sweeper — the same row internal/grpcapi's enqueueOrphanCheck writes.
func enqueueOrphanCheck(t *testing.T, n *Node, identity string) {
	t.Helper()
	if err := corrosion.EnqueueSync(context.Background(), n.DB, "orphan", identity, "check"); err != nil {
		t.Fatalf("enqueue orphan check on %s: %v", n.Name, err)
	}
}

// seedOldMirrorQueueItems plants count mirror items STRICTLY OLDER than
// anything enqueued afterwards.
//
// The backdating is what makes the scenario deterministic. EnqueueSync stamps
// created_at at second resolution, so a hundred items and an orphan check
// written in the same test tick all tie, and `ORDER BY created_at` is then free
// to return them in any order — the starvation would appear or not appear at
// random.
func seedOldMirrorQueueItems(t *testing.T, n *Node, count int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < count; i++ {
		if err := corrosion.EnqueueSync(ctx, n.DB, netboxsync.QueueKind, fmt.Sprintf("mirror-%03d", i), "upsert"); err != nil {
			t.Fatalf("enqueue mirror item %d on %s: %v", i, n.Name, err)
		}
	}
	if err := n.DB.Execute(ctx,
		`UPDATE netbox_sync_queue SET created_at = '2000-01-01T00:00:00Z' WHERE kind = ?`,
		netboxsync.QueueKind); err != nil {
		t.Fatalf("backdate mirror queue items on %s: %v", n.Name, err)
	}
}

// TestMirrorNICNameCollisionIsSuffixed drives netboxsync's interface-name collision
// suffix against a NetBox that enforces the constraint the suffix exists for.
//
// NetBox requires an interface name to be unique WITHIN a virtual machine, and
// the mirror derives that name POSITIONALLY — "eth" + the NIC's ordinal. Two
// NICs of one VM can genuinely share an ordinal: the legacy `vm_interfaces`
// table is keyed by (vm_name, network_name) and its `ordinal` column defaults
// to 0, so a row written by a peer that never set one — an older build, a
// restore, any writer that filled the record positionally for a single NIC —
// lands on ordinal 0 next to the NIC CreateVM already wrote there. Both derive
// "eth0", and the second POST is a 400 that aborts the whole sweep, leaving
// every later phase — deletes included — unrun.
//
// The fixture is that exact shape: one NIC through CreateVM, and a second
// legacy row on another network with the SAME ordinal and a distinct MAC. The
// two assertions are separate properties. DISTINCT names prove the suffix ran;
// a converged second sweep proves the suffixed name is also STABLE — a suffix
// derived from anything per-sweep would satisfy the first check and then PATCH
// the interface on every pass forever.
func TestMirrorNICNameCollisionIsSuffixed(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	// The colliding NIC: ordinal 0, same as the one CreateVM wrote.
	insertLegacyNIC(t, n, "vm-1", "second-net", 0, "52:54:00:cc:dd:ee")

	if nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, "vm-1"); err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	} else if len(nics) != 2 {
		t.Fatalf("precondition: the VM must carry 2 NICs for the names to collide, got %d", len(nics))
	}

	mustSyncAllNodes(t, c)

	names := nb.InterfaceNames()
	if len(names) != 2 {
		t.Fatalf("both NICs must be mirrored, NetBox holds %d interfaces %v "+
			"(a 400 on the second create aborts the sweep)", len(names), names)
	}
	if names[0] == names[1] {
		t.Fatalf("two interfaces of one VM share the name %q — "+
			"NetBox does not allow that and neither may the mirror", names[0])
	}
	// Both must still be the ordinal-0 name plus a suffix, not two arbitrary
	// strings: a derivation that renamed one NIC to "eth1" would be unique and
	// WRONG, since nothing in the guest ever called it that.
	for _, name := range names {
		if !strings.HasPrefix(name, "eth0") {
			t.Fatalf("interface named %q, want the ordinal-0 name with a collision suffix; got %v",
				name, names)
		}
	}

	before := nb.PatchCount()
	mustSyncAllNodes(t, c)
	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("a second sweep over the same colliding NICs issued %d PATCHes, want 0 — "+
			"the collision suffix is not stable across sweeps", got)
	}
	if names2 := nb.InterfaceNames(); !reflect.DeepEqual(names2, names) {
		t.Fatalf("the second sweep changed the interface names: %v -> %v", names, names2)
	}
}

// insertLegacyNIC writes one `vm_interfaces` row directly — the pre-v42 shape a
// peer that knows nothing of `vm_nics` still writes, and the only way to
// produce a duplicate ordinal, which no RPC on the create path will do.
func insertLegacyNIC(t *testing.T, n *Node, vmName, network string, ordinal int, mac string) {
	t.Helper()
	if err := corrosion.InsertInterface(context.Background(), n.DB, corrosion.InterfaceRecord{
		VMName:      vmName,
		NetworkName: network,
		Ordinal:     ordinal,
		MAC:         mac,
	}); err != nil {
		t.Fatalf("insert legacy NIC row for %s: %v", vmName, err)
	}
}
