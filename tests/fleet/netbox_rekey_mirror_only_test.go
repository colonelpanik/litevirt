// Fleet scenarios for the CLUSTER-SCOPED, network-less identity re-key.
//
// `lv netbox rekey <network>` re-stamps identities under the fingerprint the
// BINDING row recorded. A cluster that uses NetBox purely for INVENTORY has no
// binding at all — StartNetBoxMirror needs a client and nothing else — so that
// form has nothing to look up and refuses. A fingerprint move there makes every
// virtual_machine and vminterface unfindable by identity, and the next sweep
// tries to duplicate the whole inventory into a cluster whose VM names are
// already taken.
//
// The network-less form closes that. Its pin comes from the LOCAL INDEX:
// `netbox_objects.litevirt_key` IS the identity string, and those rows are
// written only by this cluster's own mirror into this cluster's own replicated
// database, so a fingerprint appearing in one is provably ours. That is the
// whole safety argument, and it is what these scenarios exist to hold:
//
//   - a mirror-only cluster can re-key at all, and its next sweep converges;
//   - the pin genuinely comes from the index, so an object carrying a
//     fingerprint the index has never seen is left alone;
//   - a second installation sharing the NetBox is untouched;
//   - a cluster with nothing stale in its index rewrites NOTHING, rather than
//     falling back to "everything that is not current" — which is the mutation
//     that would seize a co-tenant's objects.
//
// None of it is reachable from a single-package test: every assertion is about
// a real cluster fingerprint derived from a real replicated CA row, and two of
// them need two clusters.

package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// mirrorOnlyNetwork is an UNBOUND network — no NetBox prefix, no binding row.
// It is what makes these clusters mirror-only rather than bound.
const mirrorOnlyNetwork = "unbound"

// foreignFingerprint is a fingerprint no cluster in this file derives and no
// local index ever records. Sixteen hex characters, matching the shape
// corrosion.ClusterFingerprint produces, so nothing rejects it as malformed
// before the pin filter gets to decide.
const foreignFingerprint = "f0f0f0f0f0f0f0f0"

// foreignUUID is the VM uuid the co-tenant object carries. Any value works; a
// fixed one keeps failure output stable.
const foreignUUID = "00000000-0000-4000-8000-000000000001"

// ── helpers ─────────────────────────────────────────────────────────────────

// rekeyInventoryOnly drives RekeyBinding with an EMPTY network — the
// cluster-scoped, inventory-only form — returning the error unchanged so the
// refusal scenarios can assert on it.
func rekeyInventoryOnly(c *Cluster, n *Node) error {
	_, err := c.SelfClient(n).RekeyBinding(context.Background(),
		&pb.RekeyBindingRequest{})
	return err
}

func mustRekeyInventoryOnly(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	if err := rekeyInventoryOnly(c, n); err != nil {
		t.Fatalf("cluster-scoped RekeyBinding on %s: %v", n.Name, err)
	}
}

// mustCreateUnboundNetwork is mustCreateBoundNetwork without the prefix.
//
// Same type and PF, and for the same reason (see mustCreateBoundNetwork):
// "sriov" is the one network type Provision returns from without touching the
// host. Omitting NetboxPrefixId is the whole difference, and it is what leaves
// the cluster with no netbox_bindings row.
//
// The subnet is a parameter (pass "" where it does not matter) because the
// bind-time adoption scenarios need the PRE-LINK shape of the very network they
// then bind — same name, same subnet, no prefix — and a VM addressed by hand on
// it needs the subnet to derive its static cloud-init network-config.
func mustCreateUnboundNetwork(t *testing.T, c *Cluster, n *Node, name, subnet string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: name, Type: "sriov", Pf: "ens1f0", Subnet: subnet,
	}); err != nil {
		t.Fatalf("CreateNetwork(%s) on %s: %v", name, n.Name, err)
	}
}

// assertNoBindings is the precondition that makes every scenario here about the
// mirror-only case. Without it a fixture that quietly acquired a binding would
// exercise the per-binding path and pass for the wrong reason.
func assertNoBindings(t *testing.T, n *Node) {
	t.Helper()
	bs, err := corrosion.ListBindings(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ListBindings on %s: %v", n.Name, err)
	}
	if len(bs) != 0 {
		t.Fatalf("precondition: this cluster must have NO bindings, got %d", len(bs))
	}
}

// mirrorOnlyClusterOn wires one NetBox-configured cluster to an existing fake
// and gives it an unbound network. Separate from mirrorOnlyCluster so the
// two-installation scenario can build a SECOND cluster against the same fake.
//
// The distinct name prefix is load-bearing there: node names are the in-memory
// database names, so two clusters both calling their node "node-0" would share
// one database, one cluster row and one fingerprint.
func mirrorOnlyClusterOn(t *testing.T, nb *NetBoxFake, namePrefix string) *Cluster {
	t.Helper()
	return mirrorOnlyClusterNamed(t, nb, namePrefix, "")
}

// mirrorOnlyClusterNamed is mirrorOnlyClusterOn with a NetBox cluster name of
// its own, which is what a second installation sharing one NetBox needs — see
// Options.NetBoxClusterName.
func mirrorOnlyClusterNamed(t *testing.T, nb *NetBoxFake, namePrefix, netboxCluster string) *Cluster {
	t.Helper()
	c := New(t, Options{
		Nodes: 1, NetBoxURL: nb.URL(), NamePrefix: namePrefix,
		NetBoxClusterName: netboxCluster,
	})
	// The mirror is gated on netbox_ipam_v1 exactly as a prefix binding is: its
	// statements are replicated, and an older peer carries neither of its
	// tables. It is ALSO gated on netbox_mirror_v1, the inventory opt-in, which
	// is a separate contract a pure-IPAM cluster never forms. A mirror-only
	// cluster has no binding to latch either of them, so both are driven here —
	// the config uniformity they require is satisfied, because every node of this
	// fixture is NetBox-configured and opted into mirroring.
	latchNetBoxBoth(t, c, gateAll(t, c))
	mustCreateUnboundNetwork(t, c, c.Nodes[0], mirrorOnlyNetwork, "")
	return c
}

// mirrorOnlyCluster is a one-node cluster that mirrors inventory into NetBox
// and has NO bound network, with one VM already mirrored: one virtual_machine,
// one vminterface, and the two netbox_objects rows that name them.
func mirrorOnlyCluster(t *testing.T, vmName string) (*NetBoxFake, *Cluster) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	c := mirrorOnlyClusterOn(t, nb, "")
	n := c.Nodes[0]

	mustCreateVM(t, n, vmName, mirrorOnlyNetwork)
	mustSyncAllNodes(t, c)

	assertNoBindings(t, n)
	if nb.VMCount(vmName) != 1 || nb.InterfaceCount() != 1 {
		t.Fatalf("precondition: want one VM and one interface mirrored, got %d/%d",
			nb.VMCount(vmName), nb.InterfaceCount())
	}
	if got := objectRefFingerprints(t, n); got[clusterFP(t, n)] != 2 {
		t.Fatalf("precondition: want two local index rows under this cluster's fingerprint, got %v", got)
	}
	return nb, c
}

// netboxClusterOf is the NetBox cluster id this cluster's mirror writes into.
//
// Resolved through netboxsync.ClusterName, the same function the mirror and the
// re-key both use. Hard-coding the name here would let the two drift apart with
// a seeded co-tenant object landing in a cluster nothing enumerates — a vacuous
// "it was left alone".
func netboxClusterOf(t *testing.T, nb *NetBoxFake, n *Node) int {
	t.Helper()
	name, err := netboxsync.ClusterName(context.Background(), n.DB, n.cluster.opts.NetBoxClusterName)
	if err != nil {
		t.Fatalf("ClusterName on %s: %v", n.Name, err)
	}
	id := nb.ClusterID(name)
	if id == 0 {
		t.Fatalf("no NetBox cluster named %q yet — a seed into cluster 0 is enumerated by nothing", name)
	}
	return id
}

// seedForeignVM plants a co-tenant's virtual_machine in the SAME NetBox cluster
// this node's mirror writes into, under a fingerprint no local index records.
func seedForeignVM(t *testing.T, nb *NetBoxFake, n *Node, name string) (id int, identity string) {
	t.Helper()
	identity = netbox.Identity(foreignFingerprint, foreignUUID, "")
	id = nb.SeedVM(name, netboxClusterOf(t, nb, n), identity)
	return id, identity
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestRekeyInventoryWithNoBindings is the gap this closes.
//
// The per-network form looks its pin up by network and refuses an unbound one,
// so before this there was no command at all for a cluster that mirrors
// inventory without binding a prefix. A fingerprint move left every object
// carrying a fingerprint the cluster no longer answers to: BuildActual filters
// actual state by identity, so the next sweep sees an empty cluster, emits a
// create for everything, and is refused by NetBox's per-cluster VM-name
// uniqueness — with no way to repair it.
func TestRekeyInventoryWithNoBindings(t *testing.T) {
	nb, c := mirrorOnlyCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	if newFP == oldFP {
		t.Fatal("the cluster fingerprint did not move — the scenario would be vacuous")
	}

	mustRekeyInventoryOnly(t, c, n)

	// Both NetBox halves, asserted separately: a re-key that rewrote VMs and
	// skipped interfaces leaves the interfaces unfindable, and the sweep then
	// tries to create a second one on a VM that already has it.
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q", got, newFP)
	}
	// The LOCAL index is the identity string too — a stranded row makes every
	// adopt re-search NetBox and leaves parentVMID with nothing to resolve.
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}

	// The property all of that exists for: the next sweep converges, writing
	// nothing and duplicating nothing.
	before := nb.PatchCount()
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the sweep after a re-key must converge, got %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects after the re-key sweep = %d, want 1", got)
	}
	if got := nb.InterfaceCount(); got != 1 {
		t.Fatalf("vminterface objects after the re-key sweep = %d, want 1", got)
	}
	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("the sweep after a re-key issued %d PATCHes, want 0 — the objects were "+
			"not recognised by their rewritten identity", got)
	}
}

// TestRekeyInventoryDerivesThePinFromTheLocalIndex is the scenario that says
// WHERE the old fingerprint may come from, and it is the whole safety argument
// for the network-less form.
//
// With no binding there is no recorded pin, and the tempting substitute —
// "rewrite everything that is not the current fingerprint" — is the forbidden
// mutation: ListVMsByCluster hands this cluster every object in a NetBox
// cluster it may be sharing, so that rule stamps a co-tenant's inventory with
// this cluster's identity.
//
// The local index is the answer because netbox_objects rows are written only by
// this cluster's own mirror into its own replicated database. So the assertion
// is a NEGATIVE one: an object carrying a fingerprint that appears nowhere in
// the index is enumerated, considered, and left exactly as it was.
func TestRekeyInventoryDerivesThePinFromTheLocalIndex(t *testing.T) {
	nb, c := mirrorOnlyCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	foreignID, foreignIdentity := seedForeignVM(t, nb, n, "vm-elsewhere")

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)

	mustRekeyInventoryOnly(t, c, n)

	// Ours moved.
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if got := netboxFingerprints(t, nb); got[newFP] != 2 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want two under the new %q", got, newFP)
	}
	// Theirs did not. The seeded object sits in the SAME NetBox cluster, so it
	// WAS enumerated: only the pin stands between it and a rewrite.
	if got := nb.VMIdentity(foreignID); got != foreignIdentity {
		t.Fatalf("the co-tenant object's identity = %q, want %q untouched — the pin must come "+
			"from the LOCAL INDEX, which has never carried %q, not from \"anything that is "+
			"not the live fingerprint\"", got, foreignIdentity, foreignFingerprint)
	}
}

// TestRekeyInventoryLeavesAnotherClustersObjectsAlone is the same property with
// a real second installation rather than a seeded object.
//
// Two litevirt clusters can share one NetBox and — mirroring under the same
// cluster name — one NetBox cluster object. The seeded variant proves the rule;
// this proves the consequence an operator actually cares about: the untouched
// installation's own sweep still recognises its inventory and creates nothing.
func TestRekeyInventoryLeavesAnotherClustersObjectsAlone(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	a := mirrorOnlyClusterOn(t, nb, "")
	b := mirrorOnlyClusterOn(t, nb, "peer-")

	mustCreateVM(t, a.Nodes[0], "vm-a", mirrorOnlyNetwork)
	mustCreateVM(t, b.Nodes[0], "vm-b", mirrorOnlyNetwork)
	mustSyncAllNodes(t, a)
	mustSyncAllNodes(t, b)
	assertNoBindings(t, a.Nodes[0])
	assertNoBindings(t, b.Nodes[0])

	fpB := clusterFP(t, b.Nodes[0])
	if got := netboxFingerprints(t, nb); got[fpB] != 2 {
		t.Fatalf("precondition: want two of the second cluster's objects mirrored, got %v", got)
	}

	a.MoveClusterFingerprint()
	newFPA := clusterFP(t, a.Nodes[0])
	mustRekeyInventoryOnly(t, a, a.Nodes[0])

	if got := netboxFingerprints(t, nb); got[fpB] != 2 || got[newFPA] != 2 {
		t.Fatalf("inventory identities by fingerprint = %v, want two under each of the "+
			"re-keyed cluster's new %q and the untouched second cluster's %q", got, newFPA, fpB)
	}
	if got := objectRefFingerprints(t, b.Nodes[0]); got[fpB] != 2 {
		t.Fatalf("the second cluster's local index = %v, want both rows under its own %q", got, fpB)
	}
	if err := b.Nodes[0].SyncNetBoxMirror(); err != nil {
		t.Fatalf("the second cluster's sweep must be unaffected by a peer's re-key, got %v", err)
	}
	if got := nb.VMCount("vm-b"); got != 1 {
		t.Fatalf("the second cluster's virtual_machine objects = %d, want 1", got)
	}
}

// TestRekeyInventoryOnAConsistentClusterChangesNothing pins the fail-closed
// half: no non-live fingerprint in the local index means there is nothing this
// command may rewrite, NOT a licence to rewrite by some other rule.
//
// A co-tenant's object is present precisely so the assertion has teeth. With an
// empty pin set the only remaining rule is "anything that is not the live
// fingerprint", and that rule would seize the co-tenant's VM here while every
// assertion about this cluster's own objects stayed green.
func TestRekeyInventoryOnAConsistentClusterChangesNothing(t *testing.T) {
	nb, c := mirrorOnlyCluster(t, "vm-1")
	n := c.Nodes[0]
	fp := clusterFP(t, n)

	foreignID, foreignIdentity := seedForeignVM(t, nb, n, "vm-elsewhere")

	// No fingerprint move: every index row already carries the live fingerprint.
	before := nb.PatchCount()
	mustRekeyInventoryOnly(t, c, n)

	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("a re-key on a consistent cluster issued %d PATCHes, want 0", got)
	}
	if got := nb.VMIdentity(foreignID); got != foreignIdentity {
		t.Fatalf("the co-tenant object's identity = %q, want %q untouched", got, foreignIdentity)
	}
	if got := objectRefFingerprints(t, n); got[fp] != 2 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both still under %q", got, fp)
	}
}

// TestRekeyInventoryOnlyRewritesNetBoxBeforeTheLocalIndex pins the ORDER on the
// network-less path.
//
// 6A's TestRekeyRewritesNetBoxBeforeTheLocalIndex pins it for the bound form,
// but that scenario reaches the ordering through rekeyBinding and cannot see
// this entry point at all — a network-less form that ran its two halves the
// other way round would leave it green.
//
// The order is the same and so is the reasoning. NetBox rewritten with a stale
// local index is a LEAK, and the recoverable direction: parentVMID prefers the
// parent id read from actual state, so parenting still resolves and the next
// adopt re-records the row. Local rewritten with NetBox stale is a COLLISION:
// the sweep finds nothing under the new identity, emits a create, and NetBox
// refuses it because a VM name is unique within its cluster.
//
// The stakes are higher here, not lower: there is no binding to suspend, so the
// only thing standing between a half-done re-key and a broken mirror is that
// the recoverable half is the one that happens first.
func TestRekeyInventoryOnlyRewritesNetBoxBeforeTheLocalIndex(t *testing.T) {
	nb, c := mirrorOnlyCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	vmIDs := nb.VMIDs()
	if len(vmIDs) != 1 {
		t.Fatalf("precondition: want exactly one VM object to refuse, got %v", vmIDs)
	}

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)

	// A DEFINITE refusal on the VM object only — the inventory rewrite stops on
	// the first object, before the local index is reached.
	nb.SetOnPatch(func(id int) error {
		if id == vmIDs[0] {
			return errNetBoxPatchRefused
		}
		return nil
	})
	err := rekeyInventoryOnly(c, n)
	nb.SetOnPatch(nil)
	if err == nil {
		t.Fatal("a refused inventory rewrite must fail the re-key")
	}

	if got := objectRefFingerprints(t, n); got[newFP] != 0 || got[oldFP] != 2 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both still under the old %q — "+
			"a local index rewritten ahead of NetBox is a COLLISION: the sweep finds nothing "+
			"under the new identity and its create is refused by NetBox's name uniqueness",
			got, oldFP)
	}

	// Re-running is the recovery, and it must finish BOTH sides — which is also
	// what proves the failed run left a re-runnable state rather than a pin the
	// second run can no longer match.
	mustRekeyInventoryOnly(t, c, n)
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the sweep after the completed re-key must converge, got %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects = %d, want 1", got)
	}
}

// TestRekeyInventoryRepairsAnAlreadyAdvancedPin is the case an index-derived
// pin closes that a binding-derived one structurally cannot.
//
// A build that re-keyed ADDRESSES only — the shape before the inventory half
// existed — rewrote the addresses, advanced the binding's pin to the new
// fingerprint and resumed. The inventory and the local index were left behind.
// From then on the per-network form can do nothing: its pin equals the live
// fingerprint, so it short-circuits, and rewriting whatever is not current is
// the one rule it may not use.
//
// The local index is untouched by all of that, so it still records the old
// fingerprint — and the cluster-scoped form repairs what the per-network form
// has no pin for. Both halves are asserted, because "the network-less form
// fixed it" means nothing without "the other one could not".
func TestRekeyInventoryRepairsAnAlreadyAdvancedPin(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)

	// The state that build left: the pin advanced and the binding live, with
	// inventory and index still under the old fingerprint. (It also rewrote the
	// addresses; those are not what either form touches here.)
	advanced := binding(t, n, orphanPrefixID)
	advanced.ClusterFingerprint = newFP
	advanced.Suspended = false
	advanced.SuspendReason = ""
	if err := corrosion.UpsertBinding(context.Background(), n.DB, advanced); err != nil {
		t.Fatalf("advance the binding pin on %s: %v", n.Name, err)
	}

	// The per-network form is out of moves.
	mustRekey(t, c, n, orphanNetwork)
	if got := netboxFingerprints(t, nb); got[oldFP] != 2 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both still under the "+
			"old %q — the per-network form's pin now equals the live fingerprint, and "+
			"re-stamping everything that is not current is the forbidden rule", got, oldFP)
	}

	mustRekeyInventoryOnly(t, c, n)

	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the sweep after the repair must converge, got %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects after the repair sweep = %d, want 1", got)
	}
}

// TestRekeyInventoryRefusedWithNoLocalIndex is the other end of the same rule.
//
// An EMPTY index records no previous fingerprint at all, so there is nothing to
// derive a pin from — and the command refuses instead of guessing. Reporting
// success would be worse than the refusal: an operator whose index was lost
// while NetBox still holds stranded inventory would be told the re-key worked.
func TestRekeyInventoryRefusedWithNoLocalIndex(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	c := mirrorOnlyClusterOn(t, nb, "")
	n := c.Nodes[0]

	c.MoveClusterFingerprint()

	err := rekeyInventoryOnly(c, n)
	if err == nil {
		t.Fatal("a re-key with no local index rows must refuse — nothing records the " +
			"fingerprint this cluster's objects carry")
	}
	// The REASON, not merely an error: "network is required" is also an error,
	// and a scenario that accepted it would have passed before the network-less
	// form existed at all.
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "identity index") {
		t.Fatalf("refusal = %q, want one naming the empty local identity index", msg)
	}
	if nb.PatchCount() != 0 {
		t.Fatalf("a refused re-key must rewrite nothing, got %d PATCHes", nb.PatchCount())
	}
}

// TestRekeyWithANetworkStillRekeysThatBinding is the behaviour-preservation
// guard for the form that already existed.
//
// The network-less branch is new; adding it must not change what `lv netbox
// rekey <network>` does. All three halves are asserted together — addresses,
// inventory, and the resume — because the bound form's contract is that the
// binding goes live only once every one of them is done.
func TestRekeyWithANetworkStillRekeysThatBinding(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	mustRevalidate(t, n)
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("precondition: a moved cluster fingerprint must suspend the binding")
	}

	mustRekey(t, c, n, orphanNetwork)

	if got := nb.Identities(); len(got) != 1 || identityFingerprint(t, got[0]) != newFP {
		t.Fatalf("ip-address identities = %v, want one carrying the new fingerprint %q", got, newFP)
	}
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatalf("the bound form must resume the binding once everything is rewritten; "+
			"reason = %q", bindingSuspendReason(t, n, orphanPrefixID))
	}
}
