// Fleet scenarios for the inventory mirror's LIFECYCLE half: a VM that is
// deleted, renamed or migrated.
//
// All three are convergence properties of the DESIRED-STATE DIFF, and all three
// are invisible to a single-package test:
//
//   - DELETE removes the NetBox object rather than parking it offline, and takes
//     its interfaces with it. Only a real DeleteVM over gRPC leaves the state
//     the diff is then computed against.
//   - RENAME must UPDATE the existing objects. litevirt's own NIC id is derived
//     from the VM name and re-derived by corrosion.RenameVM, so a mirror keyed
//     on that id would fork a second interface here; the identity is keyed on
//     the MAC precisely so it does not.
//   - MIGRATION moves the host link and NOTHING else. The address and the
//     interface stay exactly as they were — a migration that re-claimed an
//     address would hand the guest a new one for a move that never touched the
//     guest.
//
// They run on boundMirrorCluster (a SHARED CRDT database) for the reason its own
// file comment gives: the leader lease is a `leader_election` row, and on
// per-node databases every node would hold its own copy of it.

package fleet

import (
	"context"
	"reflect"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The DCIM device ids the two fixture hosts are modelled as. Distinct and
// non-zero so "the link moved" is distinguishable from "the link was cleared",
// which is what a device lookup that silently failed would produce.
const (
	srcDeviceID = 91
	dstDeviceID = 92
)

func TestDeletedVMRemovedFromNetBox(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	if nb.VMCount("vm-1") != 1 || nb.InterfaceCount() != 1 {
		t.Fatalf("precondition: want one VM and one interface mirrored, got %d/%d",
			nb.VMCount("vm-1"), nb.InterfaceCount())
	}

	mustDeleteVM(t, n, "vm-1")
	mustSyncAllNodes(t, c)

	// DELETED, not parked offline. NetBox's changelog retains the history, so
	// leaving a permanently-offline object behind buys nothing and makes every
	// VM litevirt has ever run accumulate in the inventory.
	if got := nb.VMCount("vm-1"); got != 0 {
		t.Fatalf("virtual_machine objects for a deleted VM = %d, want 0 — "+
			"a deleted VM must be removed from NetBox, not left stale", got)
	}
	if got := nb.InterfaceCount(); got != 0 {
		t.Fatalf("%d interface objects survive their deleted VM, want 0", got)
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("address assignments survive their deleted VM: %v", ids)
	}
}

// TestSameNameRecreationConvergesRatherThanStallingTheMirror.
//
// Delete a VM and recreate it under the same name before the next sweep. The new
// incarnation has a new UUID, so a new identity, so the diff calls for a CREATE
// — and NetBox enforces one VM name per cluster, so that create is a 400 while
// the old object still holds the name. The old object is in this sweep's delete
// set, but deletes run in the last phase, and the pass aborts on the 400 before
// reaching it. Every subsequent pass does the same: a PERMANENT stall on an
// ordinary operation, which is why three passes are driven here rather than one.
//
// What resolves it is proof from the identity, not a reordering of every delete:
// the occupying object carries this cluster's fingerprint and a UUID absent from
// the desired set, which makes it a superseded incarnation of that name and the
// one removal allowed to run ahead of a create.
func TestSameNameRecreationConvergesRatherThanStallingTheMirror(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	if nb.VMCount("vm-1") != 1 {
		t.Fatalf("precondition: want the first incarnation mirrored, got %d",
			nb.VMCount("vm-1"))
	}
	firstIdentities := nb.VMIdentities()

	// No mirror pass between the delete and the create, which is the window an
	// operator recreating a VM by hand goes straight through.
	mustDeleteVM(t, n, "vm-1")
	mustCreateVM(t, n, "vm-1", orphanNetwork)

	for i := 0; i < 3; i++ {
		if err := n.SyncNetBoxMirror(); err != nil {
			t.Fatalf("mirror pass %d cannot replace the old same-name incarnation: %v", i, err)
		}
	}

	// CONVERGED, not merely un-errored: one object under that name, and it is
	// the NEW incarnation.
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects named vm-1 = %d, want exactly 1", got)
	}
	after := nb.VMIdentities()
	if len(after) != 1 {
		t.Fatalf("VM identities in NetBox = %v, want exactly the new incarnation's", after)
	}
	if after[0] == firstIdentities[0] {
		t.Fatalf("NetBox still holds the SUPERSEDED incarnation %s; the name was freed for "+
			"an object that was never created", after[0])
	}
	if got := nb.InterfaceCount(); got != 1 {
		t.Fatalf("interface objects = %d, want 1 — the superseded VM's interfaces go with it "+
			"and the new incarnation gets its own", got)
	}
}

func TestRenameDoesNotForkAnInterface(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	before := nb.InterfaceIDs()
	if len(before) != 1 {
		t.Fatalf("precondition: want one interface mirrored, got %v", before)
	}

	mustRenameVM(t, n, "vm-1", "vm-renamed")
	mustSyncAllNodes(t, c)

	// The identity map keys interfaces on MAC. Keying on DeterministicNICID —
	// derived from the VM name and re-derived by RenameVM — would fork a
	// duplicate here.
	//
	// The IDS, not just the count: an interface deleted and re-created under the
	// new name leaves the count at one while everything referencing the old
	// object — an address assignment, an operator's own relations — is gone.
	if after := nb.InterfaceIDs(); !reflect.DeepEqual(after, before) {
		t.Fatalf("interfaces after a rename = %v, want the SAME objects %v — "+
			"a rename must update the interface, not fork or replace it", after, before)
	}
}

// TestRenameUpdatesTheVMNameInNetBox is the other half of the rename, and the
// reason "did not fork" is not enough on its own: a mirror that did nothing at
// all would satisfy it.
func TestRenameUpdatesTheVMNameInNetBox(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)

	mustRenameVM(t, n, "vm-1", "vm-renamed")
	mustSyncAllNodes(t, c)

	if got := nb.VMCount("vm-renamed"); got != 1 {
		t.Fatalf("virtual_machine objects named vm-renamed = %d, want 1 — "+
			"the new name never reached NetBox", got)
	}
	if got := nb.VMCount("vm-1"); got != 0 {
		t.Fatalf("%d virtual_machine objects still carry the OLD name, want 0", got)
	}
}

func TestMigrationKeepsAddressAndInterface(t *testing.T) {
	nb, c := migratableMirrorCluster(t, 2)
	src, dst := c.Nodes[0], c.Nodes[1]

	mustCreateVM(t, src, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	addr := vmNICIP(t, src, "vm-1")
	if addr == "" {
		t.Fatal("precondition: the VM must hold a NetBox address, or the assertion is vacuous")
	}
	ifaces := nb.InterfaceIDs()
	addresses := nb.Addresses()

	mustMigrateVM(t, c, src, "vm-1", dst.Name)
	mustSyncAllNodes(t, c)

	// owner_host is "" for VMs, so migration touches no lease. Only the host
	// link changes.
	if got := vmNICIP(t, dst, "vm-1"); got != addr {
		t.Fatalf("address changed across migration: %q -> %q", addr, got)
	}
	if got := nb.Addresses(); !reflect.DeepEqual(got, addresses) {
		t.Fatalf("NetBox holds %v after the migration, want %v — a migration must not "+
			"claim a second address for a NIC that never moved", got, addresses)
	}
	if got := nb.InterfaceIDs(); !reflect.DeepEqual(got, ifaces) {
		t.Fatalf("interfaces after a migration = %v, want the SAME objects %v — "+
			"migration must not fork an interface", got, ifaces)
	}
	if got := leaseCount(t, dst, orphanNetwork); got != 1 {
		t.Fatalf("%d live leases on %q after a migration, want 1", got, orphanNetwork)
	}
}

// TestMigrationMovesTheDeviceLink is the positive half of the migration, for the
// same reason the rename needs one: "the address did not change" is satisfied by
// a mirror that never ran.
//
// It also pins the migration's queue entry, which is the only assertion in this
// file that the enqueue site exists at all — every other property here holds via
// the full sweep whether or not anything was ever queued.
func TestMigrationMovesTheDeviceLink(t *testing.T) {
	nb, c := migratableMirrorCluster(t, 2)
	src, dst := c.Nodes[0], c.Nodes[1]
	nb.AddDevice(src.Name, srcDeviceID)
	nb.AddDevice(dst.Name, dstDeviceID)

	mustCreateVM(t, src, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	if got := nb.VMDevice("vm-1"); got != srcDeviceID {
		t.Fatalf("precondition: mirrored VM's device = %d, want %d (the source host)", got, srcDeviceID)
	}

	mustMigrateVM(t, c, src, "vm-1", dst.Name)
	if got := pendingQueueItems(t, src, netboxsync.QueueKind); got == 0 {
		t.Fatal("a migration must queue the VM for the mirror — the object is stale " +
			"until the next full sweep otherwise")
	}
	mustSyncAllNodes(t, c)

	if got := nb.VMDevice("vm-1"); got != dstDeviceID {
		t.Fatalf("mirrored VM's device = %d after migrating to %s, want %d — "+
			"the host link must follow the VM", got, dst.Name, dstDeviceID)
	}
}

// TestQueueLossStillConvergesOnFullSweep is the queue's whole contract, on the
// irreversible operation.
//
// A node that dies mid-delete never enqueues, and a peer that drained an item may
// have died before acting on it. Both leave the same empty queue, and the full
// sweep — not the queue — is what makes the mirror right.
func TestQueueLossStillConvergesOnFullSweep(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)

	mustDeleteVM(t, n, "vm-1")
	// The latency shortcut the delete left, and then the loss. Asserting it was
	// there first is what stops this scenario from proving nothing: clearing an
	// already-empty queue is not a loss.
	if got := pendingQueueItems(t, n, netboxsync.QueueKind); got == 0 {
		t.Fatal("a delete must queue the VM for the mirror — clearing an empty queue proves nothing")
	}
	n.ClearSyncQueue()

	mustSyncAllNodes(t, c)

	if got := nb.VMCount("vm-1"); got != 0 {
		t.Fatalf("virtual_machine objects = %d, want 0 — the full sweep must converge "+
			"a delete whose queue entry was lost", got)
	}
	if got := nb.InterfaceCount(); got != 0 {
		t.Fatalf("%d interface objects survive, want 0", got)
	}
}

// TestDeleteSucceedsWhenTheMirrorEnqueueFails pins the enqueue's failure
// direction.
//
// The queue is a latency optimisation over an operation that has already
// committed: the VM's disks are gone, its addresses are released and its row is
// tombstoned. Failing the RPC at that point would report a delete that DID
// happen as an error, and an operator retrying it gets NotFound — while the full
// sweep would have covered the mirror anyway.
func TestDeleteSucceedsWhenTheMirrorEnqueueFails(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)

	breakSyncQueue(t, n)

	if _, err := c.SelfClient(n).DeleteVM(context.Background(),
		&pb.DeleteVMRequest{Name: "vm-1"}); err != nil {
		t.Fatalf("DeleteVM with an unwritable sync queue: %v — the enqueue is a latency "+
			"optimisation and must never fail an operation that has already committed", err)
	}
	if vm, err := corrosion.GetVM(context.Background(), n.DB, "vm-1"); err != nil || vm != nil {
		t.Fatalf("the VM row survived the delete: vm=%v err=%v", vm, err)
	}

	// ...and the sweep still converges over the same broken queue: nothing in it
	// branches on what the drain returned.
	mustSyncAllNodes(t, c)
	if got := nb.VMCount("vm-1"); got != 0 {
		t.Fatalf("virtual_machine objects = %d, want 0", got)
	}
}

// --- helpers -----------------------------------------------------------------

// mustDeleteVM deletes a VM through the real RPC, on the node that owns it.
func mustDeleteVM(t *testing.T, n *Node, name string) {
	t.Helper()
	if _, err := n.cluster.SelfClient(n).DeleteVM(context.Background(),
		&pb.DeleteVMRequest{Name: name}); err != nil {
		t.Fatalf("DeleteVM %s on %s: %v", name, n.Name, err)
	}
}

// mustRenameVM renames a VM the only way litevirt renames one: corrosion.RenameVM,
// which is what CutoverVM drives.
//
// There is no rename RPC — a rename reaches the cluster state through the
// cutover path — and driving the cutover here would prove something else
// entirely: cutover REPLACES a VM with its `-next` twin, a different incarnation
// with its own uuid and MAC, which the mirror correctly sees as a delete plus a
// create. What this file is about is the same VM under a new name, which is
// exactly what RenameVM produces: the spec uuid is preserved, the MAC is
// preserved, and the name-DERIVED vm_nics id is re-derived.
func mustRenameVM(t *testing.T, n *Node, oldName, newName string) {
	t.Helper()
	if err := corrosion.RenameVM(context.Background(), n.DB, oldName, newName); err != nil {
		t.Fatalf("RenameVM %s -> %s on %s: %v", oldName, newName, n.Name, err)
	}
}

// migratableMirrorCluster is boundMirrorCluster with the split-brain EXECUTION
// gate answered "yes" on every node.
//
// A migration re-checks that gate twice on the source, and the fleet harness
// runs no peer-probe loop, so the REAL health.Checker counts one live voting
// member out of two and refuses every move with no_quorum — whatever the mirror
// does. Quorum is not what these scenarios are about and has its own fleet
// coverage; everything else, the netbox_ipam_v1 latch the binding and the mirror
// both depend on included, is still the real Checker's own answer.
func migratableMirrorCluster(t *testing.T, nodes int) (*NetBoxFake, *Cluster) {
	t.Helper()
	nb, c, gates := boundMirrorClusterGated(t, nodes)
	for _, n := range c.Nodes {
		n.Server.SetGate(quorumGranted{&fleetGate{Checker: gates[n.Name], reach: c.reach}})
	}
	return nb, c
}

// quorumGranted is the fleet's capability gate with ONLY the quorum half
// answered yes. Every capability question still goes to the real Checker.
type quorumGranted struct{ *fleetGate }

func (quorumGranted) ExecutionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}

func (quorumGranted) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}

// mustMigrateVM migrates a VM through the real streaming RPC and fails on any
// terminal error.
func mustMigrateVM(t *testing.T, c *Cluster, at *Node, vmName, targetHost string) {
	t.Helper()
	if err := migrateAt(t, c, at, vmName, targetHost); err != nil {
		t.Fatalf("MigrateVM %s -> %s from %s: %v", vmName, targetHost, at.Name, err)
	}
}

// breakSyncQueue makes every netbox_sync_queue write fail.
//
// Bluntly, by removing the table: the enqueue is one unexported call on a path
// with no seam of its own, and what matters is only that it returns an error
// while the operation around it has already committed. A queue whose table is
// gone is also a real state — a half-applied schema migration produces it.
func breakSyncQueue(t *testing.T, n *Node) {
	t.Helper()
	if err := n.DB.Execute(context.Background(), `DROP TABLE netbox_sync_queue`); err != nil {
		t.Fatalf("drop netbox_sync_queue on %s: %v", n.Name, err)
	}
}

// TestCutoverQueuesTheSurvivingName pins WHICH name a cutover hands the mirror.
//
// A cutover promotes the `-next` twin onto the original name, so the moment the
// rename lands, nothing answers to the `-next` name any more. Queueing it would
// name a VM that does not exist — one replicated write, per cutover, saying
// nothing an operator reading the table could act on.
//
// One row is also SUFFICIENT. The queue is a trigger, not a work list: the sweep
// it wakes reconciles the whole cluster, and the replaced incarnation and the
// promoted one carry distinct identities, so the same pass retires one object
// and mirrors the other whichever name woke it.
//
// The fixture has no VM under the original name, which is the case the cutover
// path completes: with a replaced row present the rename collides with its own
// tombstone on the `vms.name` unique constraint and the RPC returns before it
// reaches any enqueue at all — a pre-existing cutover defect, noted on
// TestCutoverReleasesTheReplacedVMsLease and out of scope here.
func TestCutoverQueuesTheSurvivingName(t *testing.T) {
	_, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "app-next", orphanNetwork)
	if got := pendingQueueItems(t, n, netboxsync.QueueKind); got != 0 {
		t.Fatalf("precondition: %d mirror items queued before the cutover, want 0", got)
	}

	if _, err := c.SelfClient(n).CutoverVM(context.Background(),
		&pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("CutoverVM: %v", err)
	}

	keys := queuedKeys(t, n, netboxsync.QueueKind)
	if len(keys) != 1 {
		t.Fatalf("a cutover queued %d mirror items %v, want exactly 1 — the sweep one item "+
			"triggers already covers both incarnations", len(keys), keys)
	}
	if keys[0] != "app" {
		t.Fatalf("the cutover queued %q; only the SURVIVING name means anything after the "+
			"rename — nothing answers to %q any more", keys[0], "app-next")
	}
	if vm, err := corrosion.GetVM(context.Background(), n.DB, "app"); err != nil || vm == nil {
		t.Fatalf("the cutover must leave a VM under the surviving name: vm=%v err=%v", vm, err)
	}
}

// queuedKeys is the un-acked keys of one queue kind, oldest first.
func queuedKeys(t *testing.T, n *Node, kind string) []string {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), n.DB, kind, 200)
	if err != nil {
		t.Fatalf("DrainSyncQueue on %s: %v", n.Name, err)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Key)
	}
	return out
}
