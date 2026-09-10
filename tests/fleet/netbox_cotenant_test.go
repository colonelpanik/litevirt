// Fleet scenarios for two litevirt installations sharing one NetBox.
//
// Identity keeps the two apart everywhere it is consulted: BuildActual admits
// only objects carrying this cluster's fingerprint, and Diff re-filters deletes
// by it. What identity does NOT reach is the NetBox CLUSTER OBJECT, which is
// resolved by NAME — and a NetBox cluster is the scope in which NetBox enforces
// its own uniqueness rule: one VM name per cluster.
//
// So two installations that share a cluster name share the namespace their VM
// names live in, and the first same-named VM makes the second installation's
// create a 400. That error fails the whole sweep, on every pass, for as long as
// both VMs exist — the mirror never converges again, and nothing about it
// self-heals.
//
// Neither half is reachable from a single package: both need two real clusters,
// each with its own replicated database and its own CA-derived fingerprint,
// mirroring into one NetBox.

package fleet

import (
	"testing"
)

// peerClusterName is the NetBox cluster the second installation mirrors into
// when it is configured with a name of its own.
const peerClusterName = "fleet-peer"

// TestTwoClustersMirrorSameNamedVMs is the fix an operator can actually reach.
//
// Two installations, one NetBox, a VM name they both use — which is the norm,
// not the exception: "web-01" is not a fleet-unique name and litevirt never
// promised it was. Given a NetBox cluster of its own, each installation mirrors
// its own inventory and neither sweep fails.
func TestTwoClustersMirrorSameNamedVMs(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	a := mirrorOnlyClusterOn(t, nb, "")
	b := mirrorOnlyClusterNamed(t, nb, "peer-", peerClusterName)

	// The SAME name in both installations. The existing two-cluster scenarios
	// use distinct names and so never reach NetBox's uniqueness rule at all.
	mustCreateVM(t, a.Nodes[0], "vm-1", mirrorOnlyNetwork)
	mustCreateVM(t, b.Nodes[0], "vm-1", mirrorOnlyNetwork)

	mustSyncAllNodes(t, a)
	mustSyncAllNodes(t, b)

	if got := nb.VMCountAll(); got != 2 {
		t.Fatalf("virtual_machine objects = %d, want one per installation", got)
	}
	if got := nb.VMCount("vm-1"); got != 2 {
		t.Fatalf("objects named vm-1 = %d, want one in each cluster", got)
	}
	// Each under its own identity, which is what keeps the delete half safe.
	fps := netboxFingerprints(t, nb)
	fpA, fpB := clusterFP(t, a.Nodes[0]), clusterFP(t, b.Nodes[0])
	if fps[fpA] != 2 || fps[fpB] != 2 {
		t.Fatalf("inventory identities by fingerprint = %v, want two under each of %q and %q",
			fps, fpA, fpB)
	}

	// And it stays converged: a second pass on each side issues nothing and
	// fails nothing.
	mustSyncAllNodes(t, a)
	mustSyncAllNodes(t, b)
	if got := nb.VMCountAll(); got != 2 {
		t.Fatalf("a second pass took the object count to %d", got)
	}
}

// TestNameCollisionDoesNotWedgeTheSweep is the guard for the misconfiguration
// itself.
//
// Two installations left on one NetBox cluster still collide — NetBox's rule is
// not negotiable — but the mirror must not spend the rest of its life posting a
// create it can prove will be rejected. It skips exactly the colliding VM,
// converges everything else, and reports the pass as unconverged so the
// staleness alert carries the operator to the log line that names the fix.
func TestNameCollisionDoesNotWedgeTheSweep(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	a := mirrorOnlyClusterOn(t, nb, "")
	b := mirrorOnlyClusterOn(t, nb, "peer-") // same NetBox cluster as a

	mustCreateVM(t, a.Nodes[0], "vm-1", mirrorOnlyNetwork)
	mustSyncAllNodes(t, a)
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("precondition: the first installation mirrored %d objects named vm-1", got)
	}

	// The second installation holds a VM of the same name, and one of its own.
	mustCreateVM(t, b.Nodes[0], "vm-1", mirrorOnlyNetwork)
	mustCreateVM(t, b.Nodes[0], "vm-2", mirrorOnlyNetwork)

	// The sweep must not FAIL. A 400 on the colliding create aborts the pass at
	// the first error, so everything after it — including the VM that would have
	// mirrored perfectly well — never converges either.
	if err := b.Nodes[0].SyncNetBoxMirror(); err != nil {
		t.Fatalf("a name collision must not fail the sweep: %v", err)
	}

	// The non-colliding VM converged.
	if got := nb.VMCount("vm-2"); got != 1 {
		t.Fatalf("the second installation's non-colliding VM mirrored %d objects, want 1", got)
	}
	// The colliding one did not, and — this is the part that matters — the
	// first installation's object was neither duplicated nor taken over.
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("objects named vm-1 = %d, want the first installation's one, untouched", got)
	}
	// Two identities per installation and no more: a VM and its interface. The
	// second installation's pair belongs to vm-2, so a colliding create that
	// landed — or a re-stamp of the co-tenant's object — shows up here as a
	// third.
	fps := netboxFingerprints(t, nb)
	fpA, fpB := clusterFP(t, a.Nodes[0]), clusterFP(t, b.Nodes[0])
	if fps[fpA] != 2 || fps[fpB] != 2 {
		t.Fatalf("inventory identities by fingerprint = %v, want exactly two under each of "+
			"%q and %q — a collision must neither duplicate nor re-stamp a co-tenant's object",
			fps, fpA, fpB)
	}
}
