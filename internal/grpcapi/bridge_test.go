package grpcapi

import (
	"net"
	"testing"
)

func TestEnsureBridgeNilSeamAcceptsExistingInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		t.Skip("host has no network interfaces")
	}

	s := &Server{}
	if err := s.ensureBridge(interfaces[0].Name); err != nil {
		t.Fatalf("ensureBridge(%q): %v", interfaces[0].Name, err)
	}
}

// The two host-local bridge FACTS the NetBox DHCP gate reads are seams too, and
// the line joining each seam to production is the one nothing tested.
//
// Every other test in this package sets both fixtures, so production is the only
// caller that ever reaches the fall-through — which means replacing either body
// with a constant leaves the whole package green. For the uplink probe that
// constant is not hypothetical: `return true` is precisely the self-clearing bug
// the finding was rebuilt to fix. It says every bridge is uplinked, so
// netbox_dhcp_would_race resolves itself two passes later while a guest sits on
// an auto-created bridge with no gateway, holding an address NetBox believes is
// routable.
//
// A NAME NO HOST CARRIES is what makes this assertable with no root and no
// dependence on the machine's interfaces: BridgeExists is false for it, and
// BridgeHasUplink is false for it under its own fail-closed rule — there are no
// brif entries to enumerate, so there is nothing that could be an uplink.
func TestBridgeFactsFallThroughToTheHostProbe(t *testing.T) {
	s := &Server{}

	const absent = "lv-no-such-br0"
	if s.bridgeExistsHere(absent) {
		t.Errorf("bridgeExistsHere(%q) must ask the host, and the host does not have it. A "+
			"constant here would have the bind-time DHCP refusal deciding on a fixture in "+
			"production", absent)
	}
	if s.bridgeHasUplinkHere(absent) {
		t.Errorf("bridgeHasUplinkHere(%q) must ask the host, and a bridge that does not exist "+
			"has no uplink. A constant true is the self-clearing bug: the finding would resolve "+
			"itself while the misconfiguration it names still stood", absent)
	}

	// The other direction of the exists answer, so a constant false is caught
	// too. Any interface the host really has will do — the assertion is about
	// which code answers, not about which interfaces exist.
	if ifaces, err := net.Interfaces(); err == nil && len(ifaces) > 0 {
		present := ifaces[0].Name
		if !s.bridgeExistsHere(present) {
			t.Errorf("bridgeExistsHere(%q) must ask the host, and the host has it", present)
		}
	}

	// And a wired seam must still win, or the fixtures every other test in this
	// package depends on would be reading the real host instead.
	s.SetBridgeExists(func(string) bool { return true })
	s.SetBridgeHasUplink(func(string) bool { return true })
	if !s.bridgeExistsHere(absent) || !s.bridgeHasUplinkHere(absent) {
		t.Error("a wired seam must win over the host probe, or no test in this package controls " +
			"the facts the DHCP gate reads")
	}
}
