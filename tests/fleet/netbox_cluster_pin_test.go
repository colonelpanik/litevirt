// Fleet scenarios for the `netbox.cluster_name` uniformity pin.
//
// The hazard is multi-node by construction and cannot be shown in one package.
// `netbox.cluster_name` names the NetBox `virtualization.cluster` this
// installation mirrors into, and the mirror sweep runs on whichever node holds
// the `netbox` leader lease — so set non-uniformly, whichever node leads decides
// that sweep. Objects are created under one cluster and deleted under another as
// leadership moves, and the ones left behind are invisible to every sweep
// resolving the other name.
//
// A single-package test can move one server's override and observe a refusal.
// What it cannot show is the thing that makes the refusal worth having: TWO
// nodes, one of them wrong, the lease going to either of them, and the outcome
// being one cluster object rather than two.

package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// pinnedClusterName is the NetBox cluster every node of these fixtures is
// configured for, and therefore the name the first bind pins.
const pinnedClusterName = "pinned-site"

// wrongClusterName is what the misconfigured node resolves instead.
const wrongClusterName = "other-site"

// TestMisconfiguredNodeMirrorsNothingAndTheClusterStaysWhole is the scenario the
// pin exists for.
//
// Two nodes, both opted into mirroring, both latched — and one of them
// configured for the wrong NetBox cluster. The misconfigured node must mirror
// nothing at all, and NetBox must end the scenario holding exactly ONE cluster
// object, which is the observable that says the inventory did not fork.
//
// The lease is handed to the misconfigured node deliberately. Left to chance, a
// scenario where the correctly-configured node happened to win would pass with
// the check deleted — the whole failure mode is that a disagreement only shows
// up when the wrong node leads.
func TestMisconfiguredNodeMirrorsNothingAndTheClusterStaysWhole(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	gates := gateAll(t, c)
	latchNetBoxBoth(t, c, gates)

	good, bad := c.Nodes[0], c.Nodes[1]
	mustCreateBoundNetwork(t, c, good, orphanNetwork, orphanSubnet, orphanPrefixID)
	// Both nodes declare the name they resolve, which at this point is the same
	// one — the state a converged cluster is in before anybody's config is
	// touched, and the state the mirror now requires before it will run at all.
	//
	// It also sets the WINDOW this scenario is about. `bad`'s configuration
	// changes below, but its published row still carries the agreeing value
	// until `bad` runs a pass of its own; until then the PIN is the only check
	// that can see the disagreement, which is exactly the case the pin exists
	// for. Once `bad` republishes, the per-host check sees it too and stops BOTH
	// nodes — that is netbox_cluster_uniformity_test.go's scenario, not this one.
	publishClusterNamesEverywhere(t, c)

	// The pin, recorded by the bind above.
	b, err := corrosion.GetBindingByPrefix(context.Background(), good.DB, orphanPrefixID)
	if err != nil || b == nil {
		t.Fatalf("GetBindingByPrefix: %+v err=%v", b, err)
	}
	if b.NetBoxCluster != pinnedClusterName {
		t.Fatalf("the bind pinned %q, want %q", b.NetBoxCluster, pinnedClusterName)
	}

	// One node's config is changed out from under the cluster — an operator
	// editing one file, or a node brought up from a stale config.
	bad.Server.SetNetBoxClusterName(wrongClusterName)

	mustCreateVM(t, good, "vm-1", orphanNetwork)

	// The misconfigured node leads. It must write nothing: no cluster object of
	// its own, no VM, and not the lease row it would have taken to become the
	// writer.
	stealNetBoxLease(t, bad, bad.Name)
	if err := bad.SyncNetBoxMirror(); err != nil {
		t.Fatalf("a mismatching pass must decline quietly, not error: %v", err)
	}
	if got := nb.ClusterID(wrongClusterName); got != 0 {
		t.Fatalf("the misconfigured node created NetBox cluster %d under the wrong name", got)
	}
	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("the misconfigured node mirrored %d virtual_machine object(s)", got)
	}

	// The correctly-configured node still mirrors, into the pinned cluster. A
	// refusal that had spread to the whole cluster would be a worse outcome than
	// the flap it prevents.
	stealNetBoxLease(t, good, good.Name)
	if err := good.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the agreeing node's pass: %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("the agreeing node must mirror, got %d object(s) for vm-1", got)
	}
	if nb.ClusterID(pinnedClusterName) == 0 {
		t.Fatal("the agreeing node did not resolve the pinned NetBox cluster")
	}
	// The whole point: ONE cluster object, not two.
	if got := nb.ClusterID(wrongClusterName); got != 0 {
		t.Fatalf("the inventory forked: NetBox holds cluster %d under %q as well",
			got, wrongClusterName)
	}
}

// TestMisconfiguredNodeRaisesAClusterNameCondition is the operator-visible half,
// across nodes.
//
// The refusal alone is a mirror that silently stops on one node: nothing else
// litevirt reports changes, no workload is disturbed, and the lease may sit with
// the healthy node for days before anyone notices the inventory went stale. So
// the misconfigured node raises a durable health condition about ITSELF, naming
// both values — and the agreeing node's own passes must not resolve it, which is
// the part a single-node test cannot reach.
func TestMisconfiguredNodeRaisesAClusterNameCondition(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	latchNetBoxBoth(t, c, gateAll(t, c))

	good, bad := c.Nodes[0], c.Nodes[1]
	mustCreateBoundNetwork(t, c, good, orphanNetwork, orphanSubnet, orphanPrefixID)
	bad.Server.SetNetBoxClusterName(wrongClusterName)

	ctx := context.Background()
	// Every configured node runs maintenance; only the misconfigured one has a
	// finding to report. Revalidation is not leader-gated precisely so the node
	// that may never lead can still say so.
	if err := bad.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
		t.Fatalf("maintenance on the misconfigured node: %v", err)
	}

	cond, ok := fleetNetBoxCondition(t, bad, "netbox_cluster_name_mismatch", bad.Name)
	if !ok {
		t.Fatal("the misconfigured node raised no netbox_cluster_name_mismatch condition")
	}
	if cond.SubjectKind != "host" {
		t.Errorf("subject_kind = %q, want %q", cond.SubjectKind, "host")
	}
	if cond.Reporter != bad.Name {
		t.Errorf("reporter = %q, want the misconfigured node %q", cond.Reporter, bad.Name)
	}
	for _, want := range []string{pinnedClusterName, wrongClusterName, orphanNetwork} {
		if !strings.Contains(cond.Evidence, want) {
			t.Errorf("evidence %q does not name %q", cond.Evidence, want)
		}
	}
	// The agreeing node has no finding of its own.
	if _, ok := fleetNetBoxCondition(t, bad, "netbox_cluster_name_mismatch", good.Name); ok {
		t.Error("the correctly-configured node raised a mismatch condition")
	}

	// …and its passes do not resolve the misconfigured node's. Enough of them to
	// clear a finding it owned.
	for i := 0; i < 4; i++ {
		if err := good.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
			t.Fatalf("maintenance on the agreeing node, pass %d: %v", i, err)
		}
	}
	after, ok := fleetNetBoxCondition(t, bad, "netbox_cluster_name_mismatch", bad.Name)
	if !ok {
		t.Fatal("the agreeing node's clean passes deleted the peer's finding")
	}
	if after.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("the agreeing node resolved the peer's finding while the misconfiguration stood")
	}
}

// fleetNetBoxCondition finds one NetBox health condition by code and subject,
// resolved rows included, so a scenario can assert on the LIFECYCLE rather than
// on presence.
func fleetNetBoxCondition(t *testing.T, n *Node, code, subject string) (corrosion.HealthCondition, bool) {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), n.DB, true)
	if err != nil {
		t.Fatalf("ListHealthConditions on %s: %v", n.Name, err)
	}
	for _, h := range all {
		if h.Evaluator == "netbox" && h.Code == code && h.SubjectID == subject {
			return h, true
		}
	}
	return corrosion.HealthCondition{}, false
}
