// Fleet scenarios for the PER-HOST half of the `netbox.cluster_name` uniformity
// enforcement.
//
// The binding pin (netbox_cluster_pin_test.go) covers a cluster with a bound
// network. It cannot cover the shape where the hazard is purest: a cluster that
// mirrors inventory with NO bound network at all has no binding row, so no pin
// and no enforcement — and mirroring is the only thing such a cluster does with
// NetBox, so a disagreement there has nothing else to be diluted by.
//
// This is multi-node by construction and a single package cannot show it: the
// fault is TWO nodes publishing two values, which needs two real databases
// replicating to each other.

package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestMirrorOnlyClusterRefusesALiveClusterNameDisagreement is section F's whole
// point: no binding exists, so the pin has nothing to compare, and the only
// evidence of non-uniformity is what each node published.
//
// BOTH nodes must refuse. Neither of two nodes holding two values is
// authoritative, so a design where only one of them stopped would still fork the
// inventory the moment the lease moved to the other.
func TestMirrorOnlyClusterRefusesALiveClusterNameDisagreement(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	latchNetBoxBoth(t, c, gateAll(t, c))

	good, bad := c.Nodes[0], c.Nodes[1]
	mustCreateUnboundNetwork(t, c, good, mirrorOnlyNetwork, "")
	mustCreateVM(t, good, "vm-1", mirrorOnlyNetwork)

	// The precondition that makes this the mirror-only shape rather than the
	// per-binding one.
	assertNoBindings(t, good)
	assertNoBindings(t, bad)

	bad.Server.SetNetBoxClusterName(wrongClusterName)

	ctx := context.Background()
	// Each node publishes what it resolves on its own maintenance pass. Both,
	// because a comparison needs two opinions to exist before either can see
	// the other.
	for _, n := range []*Node{good, bad} {
		if err := n.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
			t.Fatalf("maintenance on %s: %v", n.Name, err)
		}
	}
	published, err := corrosion.ListNetBoxHostConfig(ctx, good.DB)
	if err != nil {
		t.Fatalf("ListNetBoxHostConfig: %v", err)
	}
	if published[good.Name] != pinnedClusterName || published[bad.Name] != wrongClusterName {
		t.Fatalf("the two nodes did not publish their own resolved names: %v", published)
	}

	// Now neither may mirror. mustSyncAllNodes runs a pass on every node, so the
	// lease lands wherever it lands — which is the point: a check that only held
	// for one of the two would pass here by luck.
	mustSyncAllNodes(t, c)

	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("%d virtual_machine object(s) mirrored while two live nodes resolved "+
			"different NetBox clusters", got)
	}
	if got := nb.InterfaceCount(); got != 0 {
		t.Fatalf("%d vminterface object(s) mirrored under a live cluster-name disagreement", got)
	}
	// Not even resolved: the pass must stop before its first NetBox call, or the
	// disagreeing node would CREATE the cluster object it should never write to.
	for _, name := range []string{pinnedClusterName, wrongClusterName} {
		if got := nb.ClusterID(name); got != 0 {
			t.Fatalf("the mirror resolved NetBox cluster %d under %q despite the disagreement",
				got, name)
		}
	}
}

// TestMirrorOnlyClusterRaisesTheDisagreementOnBothNodes is the operator-visible
// half. A mirror that stopped and said nothing is worse than one that never
// started: no workload is disturbed, nothing else litevirt reports changes, and
// the inventory just goes stale.
func TestMirrorOnlyClusterRaisesTheDisagreementOnBothNodes(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	latchNetBoxBoth(t, c, gateAll(t, c))

	good, bad := c.Nodes[0], c.Nodes[1]
	mustCreateUnboundNetwork(t, c, good, mirrorOnlyNetwork, "")
	assertNoBindings(t, good)
	bad.Server.SetNetBoxClusterName(wrongClusterName)

	ctx := context.Background()
	// Twice, so both nodes have seen the other's published value.
	for i := 0; i < 2; i++ {
		for _, n := range []*Node{good, bad} {
			if err := n.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
				t.Fatalf("maintenance on %s pass %d: %v", n.Name, i, err)
			}
		}
	}

	for _, n := range []*Node{good, bad} {
		cond, ok := fleetNetBoxCondition(t, n, "netbox_cluster_name_disagreement", n.Name)
		if !ok {
			t.Fatalf("%s raised no netbox_cluster_name_disagreement about itself", n.Name)
		}
		if cond.SubjectKind != "host" {
			t.Errorf("%s: subject_kind = %q, want %q", n.Name, cond.SubjectKind, "host")
		}
		if cond.Reporter != n.Name {
			t.Errorf("%s: reporter = %q, want itself", n.Name, cond.Reporter)
		}
		// Both values and the peer holding the other one. Without the host name
		// an operator on a large cluster has two strings and nowhere to go.
		peer := bad.Name
		if n == bad {
			peer = good.Name
		}
		for _, want := range []string{pinnedClusterName, wrongClusterName, peer} {
			if !strings.Contains(cond.Evidence, want) {
				t.Errorf("%s: evidence %q does not name %q", n.Name, cond.Evidence, want)
			}
		}
		// ...and STRUCTURALLY, in the evidence's host list, so a UI or an alert
		// can route the finding at the node holding the other value rather than
		// grepping a sentence for host names.
		var ev struct {
			Detail string   `json:"detail"`
			Hosts  []string `json:"hosts"`
		}
		if err := json.Unmarshal([]byte(cond.Evidence), &ev); err != nil {
			t.Fatalf("%s: evidence is not decodable: %v", n.Name, err)
		}
		if len(ev.Hosts) != 1 || ev.Hosts[0] != peer {
			t.Errorf("%s: evidence hosts = %v, want [%s]", n.Name, ev.Hosts, peer)
		}
	}

	// The finding resolves once the configuration is corrected, on both nodes.
	bad.Server.SetNetBoxClusterName(pinnedClusterName)
	for i := 0; i < netboxFleetCleanPasses; i++ {
		for _, n := range []*Node{good, bad} {
			if err := n.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
				t.Fatalf("maintenance on %s clean pass %d: %v", n.Name, i, err)
			}
		}
	}
	for _, n := range []*Node{good, bad} {
		after, ok := fleetNetBoxCondition(t, n, "netbox_cluster_name_disagreement", n.Name)
		if !ok {
			t.Fatalf("%s: the condition row vanished rather than resolving", n.Name)
		}
		if after.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("%s: a corrected disagreement left the finding at %q", n.Name, after.Lifecycle)
		}
	}
}

// TestMirrorOnlyClusterAgreeingNodesMirrorNormally is the negative control that
// keeps the two above honest: with the SAME fixture and agreeing names, the
// mirror does what it always did. Without it, a bug that stopped the mirror
// unconditionally would pass every assertion above.
func TestMirrorOnlyClusterAgreeingNodesMirrorNormally(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	latchNetBoxBoth(t, c, gateAll(t, c))

	n := c.Nodes[0]
	mustCreateUnboundNetwork(t, c, n, mirrorOnlyNetwork, "")
	mustCreateVM(t, n, "vm-1", mirrorOnlyNetwork)
	assertNoBindings(t, n)

	ctx := context.Background()
	for _, node := range c.Nodes {
		if err := node.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
			t.Fatalf("maintenance on %s: %v", node.Name, err)
		}
	}
	mustSyncAllNodes(t, c)

	if got := nb.VMCountAll(); got != 1 {
		t.Fatalf("agreeing nodes mirrored %d virtual_machine object(s), want 1", got)
	}
	if got := nb.ClusterID(pinnedClusterName); got == 0 {
		t.Fatal("agreeing nodes did not resolve the configured NetBox cluster")
	}
}

// netboxFleetCleanPasses mirrors internal/grpcapi's netboxCleanPasses, which is
// unexported. Deliberately a separate constant rather than a magic number: if
// the two ever diverge, the loop above simply runs more passes than it needs,
// which cannot make a resolution assertion pass falsely.
const netboxFleetCleanPasses = 3

// TestMirrorWaitsForALiveHostThatHasNotPublished is the window the gate used to
// mirror straight through.
//
// The publication used to happen INSIDE the comparison, and an absent peer row
// was passed over on the argument that a node which has not published has not
// run the gate and so cannot be flapping anything. True of the peer; beside the
// point for the node doing the comparing, which went on to mirror against a set
// it knew was incomplete — and the value that peer is about to publish may
// disagree.
//
// Two real nodes are what make this observable: only one of them runs a pass,
// so the other's row genuinely does not exist yet, which no single-process
// fixture reproduces honestly.
func TestMirrorWaitsForALiveHostThatHasNotPublished(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	c := New(t, Options{
		Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true,
		NetBoxClusterName: pinnedClusterName,
	})
	latchNetBoxBoth(t, c, gateAll(t, c))

	first, quiet := c.Nodes[0], c.Nodes[1]
	mustCreateUnboundNetwork(t, c, first, mirrorOnlyNetwork, "")
	mustCreateVM(t, first, "vm-1", mirrorOnlyNetwork)
	assertNoBindings(t, first)

	ctx := context.Background()
	// ONLY the first node runs. The second is live — it has a host row and it is
	// voting-eligible — and it has published nothing.
	stealNetBoxLease(t, first, first.Name)
	if err := first.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
		t.Fatalf("maintenance on %s: %v", first.Name, err)
	}
	if err := first.SyncNetBoxMirror(); err != nil {
		t.Fatalf("a pass that cannot establish uniformity must decline quietly: %v", err)
	}
	if got := nb.VMCountAll(); got != 0 {
		t.Fatalf("%d virtual_machine object(s) mirrored while a live host had published no "+
			"NetBox cluster name — the comparison cannot be complete", got)
	}
	// …and it says so, naming the host it is waiting for. A mirror that stopped
	// in silence would be the worst of both.
	h, ok := fleetNetBoxCondition(t, first, "netbox_cluster_name_unpublished", first.Name)
	if !ok {
		t.Fatal("a pass blocked on an unpublished peer must raise a health condition")
	}
	if !strings.Contains(h.Evidence, quiet.Name) {
		t.Fatalf("the evidence must name the host that has not published, got %q", h.Evidence)
	}

	// THE WINDOW CLOSES ON ITS OWN: the quiet node runs its own pass, publishes
	// the same name, and mirroring resumes. That is what keeps the fail-closed
	// wait bounded rather than a permanent stop.
	if err := quiet.Server.RunNetBoxMaintenanceOnce(ctx); err != nil {
		t.Fatalf("maintenance on %s: %v", quiet.Name, err)
	}
	stealNetBoxLease(t, first, first.Name)
	if err := first.SyncNetBoxMirror(); err != nil {
		t.Fatalf("mirror on %s: %v", first.Name, err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("once every live host has published, mirroring must resume; got %d object(s)", got)
	}
}
