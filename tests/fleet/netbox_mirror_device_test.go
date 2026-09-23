// The device link is BEST-EFFORT, and this is what that has to mean.
//
// The mirror hangs each virtual_machine off its host's DCIM device when the host
// is modelled in NetBox. NetBox validates that link: a VM may only name a device
// that belongs to the VM's own cluster. A host modelled by something ELSE — a
// bare-metal provisioner, a hand-built DCIM record — belongs to no virtualization
// cluster at all, which is the ordinary state of a NetBox that predates litevirt.
//
// Resolving such a device by name alone and attaching it turns an optional
// convenience into a 400 that fails the whole sweep, so NOTHING is mirrored:
// not the VM whose host is mis-modelled, and not any other VM in the cluster
// either, because the create phase aborts on the first refusal.
//
// These scenarios are fleet-level because the property is about a real HTTP
// exchange with NetBox's validation in it. A unit test with a stub writer can
// assert which id was passed; only a server that refuses the way NetBox refuses
// can show that the sweep survives.

package fleet

import (
	"strings"
	"testing"
)

// TestMirrorSkipsDeviceOutsideItsCluster is the regression: a host modelled in
// NetBox but belonging to no virtualization cluster must not be attached, and
// the sweep must still mirror the inventory.
func TestMirrorSkipsDeviceOutsideItsCluster(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	// The host IS in NetBox — and, like every host inventoried by something
	// other than litevirt, belongs to no cluster.
	nb.AddDevice(n.Name, 4242)

	mustCreateVM(t, n, "vm-1", "bound")

	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("sweep failed because of an unusable device link: %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("want the VM mirrored, got %d objects", got)
	}
	if got := nb.VMDeviceID("vm-1"); got != 0 {
		t.Fatalf("want no device link for an out-of-cluster device, got %d", got)
	}
}

// TestMirrorKeepsDeviceInsideItsCluster is the other half, and the one that
// stops the fix from being "never link a device at all": a host modelled in the
// mirror's OWN cluster is still linked.
func TestMirrorKeepsDeviceInsideItsCluster(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", "bound")
	// Resolve the cluster the mirror writes into by running one sweep, then
	// model the host inside it. Ordering matters: the cluster object does not
	// exist until a sweep creates it.
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	nb.AddDeviceInCluster(n.Name, 4242, nb.ClusterID("fleet"))

	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if got := nb.VMDeviceID("vm-1"); got != 4242 {
		t.Fatalf("want the in-cluster device linked, got %d", got)
	}
}

// TestMirrorSurvivesOneMisModelledHost is the blast-radius claim. The create
// phase aborts on the first refusal, so a single mis-modelled host stops the
// mirror for EVERY VM in the cluster — which is how a whole fleet's inventory
// went missing over one host's DCIM record.
func TestMirrorSurvivesOneMisModelledHost(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)

	nb.AddDevice(c.Nodes[0].Name, 4242) // mis-modelled: no cluster
	mustCreateVM(t, c.Nodes[0], "vm-on-bad-host", "bound")
	mustCreateVM(t, c.Nodes[1], "vm-on-good-host", "bound")

	mustSyncAllNodes(t, c)

	for _, name := range []string{"vm-on-bad-host", "vm-on-good-host"} {
		if got := nb.VMCount(name); got != 1 {
			t.Errorf("%s: want 1 mirrored object, got %d", name, got)
		}
	}
}

// TestFakeRefusesDeviceOutsideCluster proves the harness itself enforces the
// constraint. Without this the three scenarios above would pass against a fake
// that simply accepts any device id — which is exactly the hole the real bug
// slipped through.
func TestFakeRefusesDeviceOutsideCluster(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	nb.AddDevice(c.Nodes[0].Name, 4242)

	err := nb.CreateVMDirect("probe", nb.ClusterID("fleet"), 4242)
	if err == nil {
		t.Fatal("want the fake to refuse a device outside the cluster")
	}
	if !strings.Contains(err.Error(), "not assigned to this cluster") {
		t.Fatalf("want NetBox's own refusal, got %v", err)
	}
}
