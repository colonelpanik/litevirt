package firewall

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func natHas(nat []NATRule, want NATRule) bool {
	for _, n := range nat {
		if n == want {
			return true
		}
	}
	return false
}

func isoBridges(iso []IsolationChain) map[string][]IsolationException {
	m := map[string][]IsolationException{}
	for _, c := range iso {
		m[c.Bridge] = c.Exceptions
	}
	return m
}

// TestIntentToNATIsolation_NetworkOwnsIsolation is the core ownership rule: only a
// net:<name> row can make a bridge isolated; an lb:<name> row contributes VIP:port
// exceptions and SNAT but never isolation authority.
func TestIntentToNATIsolation_NetworkOwnsIsolation(t *testing.T) {
	intents := []corrosion.HostFWIntent{
		// managed NAT network → masquerade, no isolation.
		{ScopeKey: "net:pub", Bridge: "br-pub", MasqueradeSubnet: "10.0.1.0/24"},
		// isolated network → base isolation drop.
		{ScopeKey: "net:iso", Bridge: "br-iso", Isolate: true},
		// LB on the isolated network → exceptions + SNAT, NO Isolate flag.
		{ScopeKey: "lb:web", Bridge: "br-iso",
			Exceptions:   []corrosion.HostFWException{{VIP: "10.100.0.50", Ports: []int{80, 443}}},
			SNATSubnet:   "10.100.0.0/24", SNATVIP: "10.100.0.50", SNATOutIface: "eth0"},
	}
	nat, iso := intentToNATIsolation(intents)

	if !natHas(nat, NATRule{Subnet: "10.0.1.0/24", Bridge: "br-pub"}) {
		t.Errorf("expected masquerade for br-pub; got %+v", nat)
	}
	// SNAT renders because br-iso IS isolated (net row).
	if !natHas(nat, NATRule{OutIface: "eth0", Subnet: "10.100.0.0/24", SNATTo: "10.100.0.50"}) {
		t.Errorf("expected SNAT for the isolated bridge; got %+v", nat)
	}
	b := isoBridges(iso)
	if _, ok := b["br-iso"]; !ok {
		t.Fatal("br-iso must be isolated (net intent)")
	}
	if _, ok := b["br-pub"]; ok {
		t.Error("br-pub is a NAT network, must not be isolated")
	}
	// The LB's exceptions must have merged onto the network's isolation drop.
	if len(b["br-iso"]) != 1 || b["br-iso"][0].VIP != "10.100.0.50" || len(b["br-iso"][0].Ports) != 2 {
		t.Errorf("LB exceptions should merge onto the isolated bridge; got %+v", b["br-iso"])
	}
}

// TestIntentToNATIsolation_StaleLBCannotIsolate is the HIGH-2 regression: an LB row
// on its own (no net isolation for the bridge) must NOT keep the bridge isolated,
// and its SNAT must NOT render.
func TestIntentToNATIsolation_StaleLBCannotIsolate(t *testing.T) {
	intents := []corrosion.HostFWIntent{
		// Only an LB row remains (the network's isolation intent was deleted). Even
		// if a legacy row still carried Isolate, lb scope must not confer authority.
		{ScopeKey: "lb:web", Bridge: "br-iso", Isolate: true,
			Exceptions: []corrosion.HostFWException{{VIP: "10.100.0.50", Ports: []int{80}}},
			SNATSubnet: "10.100.0.0/24", SNATVIP: "10.100.0.50", SNATOutIface: "eth0"},
	}
	nat, iso := intentToNATIsolation(intents)
	if len(iso) != 0 {
		t.Errorf("an LB row alone must not isolate any bridge; got %+v", iso)
	}
	if len(nat) != 0 {
		t.Errorf("SNAT must not render for a non-isolated bridge; got %+v", nat)
	}
}
