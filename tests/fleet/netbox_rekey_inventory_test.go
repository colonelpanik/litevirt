// Fleet scenarios for the identity re-key over INVENTORY objects.
//
// P1's re-key rewrote `ipam.ip-address` identities and nothing else, because VM
// and interface objects did not exist yet. The identity is
// `lv:<cluster-fingerprint>:<vm-uuid>:<mac>` and the fingerprint is derived from
// the CA certificate in the replicated `cluster` row, so a fingerprint that
// moves moves on EVERY object litevirt owns — the virtual_machine and
// vminterface objects the P2 mirror writes included, and the local
// `netbox_objects` index whose litevirt_key IS that identity string. (Only an
// out-of-band rewrite of that row moves it; see Cluster.MoveClusterFingerprint.)
//
// Three properties, and none of them is reachable from a single-package test
// because each needs a real cluster fingerprint derived from a real replicated
// `cluster` row:
//
//   - the re-key rewrites inventory as well as addresses, so the next sweep
//     still finds its own objects instead of trying to create a second set;
//   - NetBox is rewritten BEFORE the local index, never the other way round;
//   - the old-fingerprint pin is what says which objects are ours, so a second
//     cluster sharing one NetBox is untouched.

package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The netbox_objects kinds the mirror records. Literals rather than an import:
// internal/netboxsync keeps them unexported, and they are a REPLICATED column
// value — a scenario that followed a renamed constant would stop noticing that
// the on-disk kind had changed under it.
const (
	refKindVM  = "vm"
	refKindNIC = "nic"
)

// mirroredCluster is boundMirrorCluster with one VM already mirrored: one
// virtual_machine, one vminterface, one address, and the two netbox_objects
// rows that name them. It is the state every re-key scenario here starts from.
func mirroredCluster(t *testing.T, name string) (*NetBoxFake, *Cluster) {
	t.Helper()
	nb, c := boundMirrorCluster(t, 1)
	mustCreateVM(t, c.Nodes[0], name, orphanNetwork)
	mustSyncAllNodes(t, c)
	if nb.VMCount(name) != 1 || nb.InterfaceCount() != 1 {
		t.Fatalf("precondition: want one VM and one interface mirrored, got %d/%d",
			nb.VMCount(name), nb.InterfaceCount())
	}
	if got := objectRefFingerprints(t, c.Nodes[0]); got[clusterFP(t, c.Nodes[0])] != 2 {
		t.Fatalf("precondition: want two local index rows under this cluster's fingerprint, got %v", got)
	}
	return nb, c
}

// objectRefFingerprints groups every LIVE netbox_objects row by the cluster
// component of its litevirt_key.
//
// The key is the identity string, so the local index carries the fingerprint
// exactly as the NetBox objects do — and is stranded by a fingerprint move in
// exactly the same way.
func objectRefFingerprints(t *testing.T, n *Node) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, kind := range []string{refKindVM, refKindNIC} {
		refs, err := corrosion.ListObjectRefs(context.Background(), n.DB, kind)
		if err != nil {
			t.Fatalf("ListObjectRefs(%s) on %s: %v", kind, n.Name, err)
		}
		for _, r := range refs {
			out[identityFingerprintOf(t, r.LitevirtKey)]++
		}
	}
	return out
}

// identityFingerprintOf is identityFingerprint for an identity that may carry
// an EMPTY MAC.
//
// A VM identity is Identity(fp, uuid, "") — "lv:<fp>:<uuid>:" — which has only
// three non-empty fields. identityFingerprint's four-field check rejects it, so
// a scenario reusing it would fail on the VM half of every index assertion for
// a reason that has nothing to do with the re-key.
func identityFingerprintOf(t *testing.T, identity string) string {
	t.Helper()
	parts := strings.Split(identity, ":")
	if len(parts) < 4 || parts[0] != "lv" || parts[1] == "" {
		t.Fatalf("identity %q is not in the lv:<fp>:<uuid>:<mac> form", identity)
	}
	return parts[1]
}

// netboxFingerprints groups every INVENTORY identity in the fake by its cluster
// component — the NetBox-side counterpart of objectRefFingerprints.
func netboxFingerprints(t *testing.T, nb *NetBoxFake) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, id := range append(nb.VMIdentities(), nb.InterfaceIdentities()...) {
		out[identityFingerprintOf(t, id)]++
	}
	return out
}

// TestRekeyRewritesInventoryIdentitiesToo is the whole point of the task.
//
// Rewriting only address identities leaves every virtual_machine and
// vminterface carrying the OLD fingerprint. BuildActual filters actual state by
// the identity fingerprint, so the next sweep sees an empty cluster, Diff emits
// a create for every object, and litevirt tries to duplicate its own inventory —
// which NetBox's per-cluster VM-name uniqueness then refuses, taking the whole
// sweep down with it. Either way the mirror is broken until a human intervenes.
func TestRekeyRewritesInventoryIdentitiesToo(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	mustRevalidate(t, n)
	mustRekey(t, c, n, orphanNetwork)

	// Both halves, asserted separately: a re-key that rewrote VMs and skipped
	// interfaces would leave the interfaces unfindable and the sweep would try
	// to create a second one on a VM that already has it.
	if got := nb.VMIdentities(); len(got) != 1 || identityFingerprintOf(t, got[0]) != newFP {
		t.Fatalf("virtual_machine identities = %v, want one carrying the new fingerprint %q", got, newFP)
	}
	if got := nb.InterfaceIdentities(); len(got) != 1 || identityFingerprintOf(t, got[0]) != newFP {
		t.Fatalf("vminterface identities = %v, want one carrying the new fingerprint %q", got, newFP)
	}
	// The LOCAL index is the identity string too — a stranded row makes the
	// mirror re-adopt by search on every sweep and, on the NIC path, leaves
	// parentVMID with nothing to resolve.
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

// TestRekeyRewritesNetBoxBeforeTheLocalIndex pins the ORDER of the two halves,
// which is not an implementation detail and is not reversible.
//
// NetBox rewritten, local index stale is a LEAK, and the recoverable direction:
// parentVMID prefers the parent id read from actual state, so parenting still
// resolves and the next adopt re-records the row under the new identity.
//
// Local rewritten, NetBox stale is a COLLISION. BuildActual finds nothing under
// the new identity, Diff emits a vm/create, and NetBox refuses it — a VM name is
// unique within its cluster. The mirror then fails on every sweep with the
// inventory it already owns sitting right there.
//
// So the scenario fails the NetBox rewrite partway and asserts the local rows
// were not rewritten ahead of it.
func TestRekeyRewritesNetBoxBeforeTheLocalIndex(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	vmIDs := nb.VMIDs()
	if len(vmIDs) != 1 {
		t.Fatalf("precondition: want exactly one VM object to refuse, got %v", vmIDs)
	}

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	mustRevalidate(t, n)

	// A DEFINITE refusal on the VM object only: the addresses ahead of it are
	// rewritten, the inventory rewrite stops on the first object.
	nb.SetOnPatch(func(id int) error {
		if id == vmIDs[0] {
			return errNetBoxPatchRefused
		}
		return nil
	})
	err := rekey(c, n, orphanNetwork)
	nb.SetOnPatch(nil)
	if err == nil {
		t.Fatal("a refused inventory rewrite must fail the re-key")
	}

	if got := objectRefFingerprints(t, n); got[newFP] != 0 || got[oldFP] != 2 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want all %d still under the old %q — "+
			"a local index rewritten ahead of NetBox is a COLLISION: the sweep finds nothing "+
			"under the new identity and its create is refused by NetBox's name uniqueness",
			got, 2, oldFP)
	}
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a partial re-key must leave the binding suspended")
	}

	// Re-running is the recovery, and it must finish BOTH sides.
	mustRekey(t, c, n, orphanNetwork)
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

// TestRekeyLeavesAnotherClustersInventoryAlone is why the rewrite is filtered on
// the binding's OLD pin rather than on "anything that is not the new value".
//
// Two litevirt installations can share one NetBox, and — mirroring under the
// same cluster name — the same NetBox cluster object, so ListVMsByCluster hands
// one cluster's re-key the OTHER cluster's inventory. Only the fingerprint pin
// stands between them. A re-key that rewrote every object it enumerated would
// stamp a second installation's VMs with this cluster's identity: that
// installation's sweep then finds nothing of its own, tries to re-create it, and
// is refused by the name it already holds.
func TestRekeyLeavesAnotherClustersInventoryAlone(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	a := NewClusterWithNetBox(t, 1, nb)
	latchNetBoxBoth(t, a, gateAll(t, a))
	// A distinct node-name prefix gives the second cluster its own in-memory
	// database, and therefore its own cluster row, CA and fingerprint. Without
	// it both "clusters" would share one database and the scenario could not
	// fail.
	b := NewClusterWithNetBoxNamed(t, 1, nb, "peer-")
	latchNetBoxBoth(t, b, gateAll(t, b))

	mustCreateBoundNetwork(t, a, a.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)
	mustCreateBoundNetwork(t, b, b.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)
	mustCreateVM(t, a.Nodes[0], "vm-a", orphanNetwork)
	mustCreateVM(t, b.Nodes[0], "vm-b", orphanNetwork)
	mustSyncAllNodes(t, a)
	mustSyncAllNodes(t, b)

	fpB := clusterFP(t, b.Nodes[0])
	if got := netboxFingerprints(t, nb); got[fpB] != 2 {
		t.Fatalf("precondition: want two of the second cluster's objects mirrored, got %v", got)
	}

	a.MoveClusterFingerprint()
	newFPA := clusterFP(t, a.Nodes[0])
	mustRevalidate(t, a.Nodes[0])
	mustRekey(t, a, a.Nodes[0], orphanNetwork)

	if got := netboxFingerprints(t, nb); got[fpB] != 2 || got[newFPA] != 2 {
		t.Fatalf("inventory identities by fingerprint = %v, want two under each of the "+
			"re-keyed cluster's new %q and the untouched second cluster's %q", got, newFPA, fpB)
	}
	if got := objectRefFingerprints(t, b.Nodes[0]); got[fpB] != 2 {
		t.Fatalf("the second cluster's local index = %v, want both rows under its own %q", got, fpB)
	}
	// The behaviour the fingerprints stand for: the untouched cluster's own
	// sweep still recognises its inventory and creates nothing.
	if err := b.Nodes[0].SyncNetBoxMirror(); err != nil {
		t.Fatalf("the second cluster's sweep must be unaffected by a peer's re-key, got %v", err)
	}
	if got := nb.VMCount("vm-b"); got != 1 {
		t.Fatalf("the second cluster's virtual_machine objects = %d, want 1", got)
	}
}
