// A mirrored VM needs a PRIMARY address, not merely an attached one.
//
// NetBox models "this machine's main address" as virtual_machine.primary_ip4,
// separately from the ip_address→vminterface assignment. Everything downstream
// reads the primary: NetBox's own UI column, the DNS integrations, and
// nb_inventory's ansible_host. A VM whose address is assigned to an interface
// but never made primary is, to all of them, a machine with no address.
//
// NetBox validates it — the address must be assigned to an interface of THAT VM
// — so it cannot be set on create, and it cannot name a foreign address. The
// fake enforces both; see primaryIPRefusalLocked.

package fleet

import (
	"strings"
	"testing"
)

// TestMirrorSetsPrimaryIPv4 is the regression: an address the mirror assigned
// must also become the VM's primary_ip4.
func TestMirrorSetsPrimaryIPv4(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", "bound")
	mustSyncAllNodes(t, c)

	ipID := nb.InterfaceAddressID("vm-1", "eth0")
	if ipID == 0 {
		t.Fatal("precondition: the mirror did not assign an address to the interface")
	}
	if got := nb.VMPrimaryIP4("vm-1"); got != ipID {
		t.Fatalf("primary_ip4 = %d, want %d (the address on its own interface) — "+
			"without it NetBox, its DNS integrations and nb_inventory all see a VM with no address",
			got, ipID)
	}
}

// TestMirrorPrimaryIPIsIdempotent: a converged mirror must not re-PATCH the
// primary on every sweep. Write-on-change is what keeps a 15-minute sweep from
// being a 15-minute write storm against NetBox.
func TestMirrorPrimaryIPIsIdempotent(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", "bound")
	mustSyncAllNodes(t, c)
	if nb.VMPrimaryIP4("vm-1") == 0 {
		t.Fatal("precondition: primary_ip4 was never set")
	}

	before := nb.PatchCount()
	mustSyncAllNodes(t, c)
	if after := nb.PatchCount(); after != before {
		t.Fatalf("a converged sweep issued %d PATCH(es); a mirror that rewrites "+
			"the primary every pass never converges", after-before)
	}
}

// TestMirrorClearsPrimaryIPWhenTheNICGoes: detaching the NIC that held the
// primary must not leave the VM pointing at a released address. NetBox would
// refuse the dangling reference anyway; the point is that the mirror converges
// rather than failing every sweep on it.
func TestMirrorClearsPrimaryIPWhenTheNICGoes(t *testing.T) {
	// operation_protocol_v1 as well as the mirror latches: a NIC detach refuses
	// outright without it, which is correct behaviour and not a test artifact.
	nb, c, gates := boundMirrorClusterGated(t, 1)
	latchOperationProtocol(t, c, gates)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", "bound")
	mustSyncAllNodes(t, c)
	if nb.VMPrimaryIP4("vm-1") == 0 {
		t.Fatal("precondition: primary_ip4 was never set")
	}

	mustDetachNIC(t, c, n, "vm-1", nb.InterfaceMAC("vm-1", "eth0"))
	mustSyncAllNodes(t, c)

	if got := nb.VMPrimaryIP4("vm-1"); got != 0 {
		t.Fatalf("primary_ip4 = %d after the NIC was detached, want cleared", got)
	}
}

// TestFakeRefusesAForeignPrimaryIP proves the HARNESS enforces NetBox's rule.
// Without it every scenario above would pass against a fake that accepts any
// id — which is exactly how the device/cluster refusal reached production.
func TestFakeRefusesAForeignPrimaryIP(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)

	mustCreateVM(t, c.Nodes[0], "vm-1", "bound")
	mustCreateVM(t, c.Nodes[1], "vm-2", "bound")
	mustSyncAllNodes(t, c)

	foreign := nb.InterfaceAddressID("vm-2", "eth0")
	if foreign == 0 {
		t.Fatal("precondition: vm-2 has no mirrored address")
	}
	err := nb.SetVMPrimaryIP4Direct("vm-1", foreign)
	if err == nil {
		t.Fatal("want the fake to refuse an address that belongs to another VM")
	}
	if !strings.Contains(err.Error(), "not assigned to this VM") {
		t.Fatalf("want NetBox's own refusal, got %v", err)
	}
}
