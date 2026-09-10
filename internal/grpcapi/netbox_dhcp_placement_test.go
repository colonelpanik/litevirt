package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/network"
)

// The provision-time DHCP refusal does not fail a placement, and its message
// must not say it does.
//
// THE SHAPE OF THE BUG. The refusal is correct inside Provision — it is hoisted
// above EnsureBridge, so a refused provision creates nothing and a retry refuses
// identically. It is nullified at the CALLER: provisionNetworkForVM's error is
// logged at warn level and the code carries on with the network name as the
// bridge, and the very next step creates that bridge through ensureBridge. Same
// shape in clone-from-template, in the reconciler after a failover, and in NIC
// hot-attach. So the guest lands on the host the refusal named, on a bridge
// litevirt just made: no DHCP server, no uplink, no gateway, holding an address
// NetBox believes is routable.
//
// That `slog.Warn` is PRE-EXISTING and untouched by this branch; making the
// placement genuinely fail is a change to four callers' error handling on a path
// with broad blast radius, and is not made here. What is fixed is the lie: the
// message said "until then no VM can be placed on <host>", which sends an
// operator looking for a failure that never happens.
//
// This test pins the text against the BEHAVIOUR, in one place, by driving both
// halves the caller drives — so the claim cannot drift from what the code does.
func TestABoundNetworkRefusalDoesNotPreventPlacement(t *testing.T) {
	s := boundDHCPNetworkOn(t, false)
	ctx := context.Background()

	// Provisioning reads the network's CONFIG BLOB, not the binding row (the
	// evaluator is the one that treats the row as authoritative), so seed the
	// config the way the create RPC writes it: json.Marshal of the def.
	bound := dhcpBoundNetworkDef
	bound.NetBoxPrefixID = adoptTestPrefix
	seedNetworkDef(t, s, bound.Interface, bound)

	// What the caller does with the bridge is what settles the claim, so record
	// it through the production seam rather than trusting a comment.
	var created []string
	s.SetBridgeEnsure(func(name string) error {
		created = append(created, name)
		return nil
	})

	// Step 1, exactly as CreateVM does it: provision, and keep the error.
	bridge := dhcpBoundNetworkDef.Interface
	provBridge, perr := provisionNetworkForVM(ctx, s.db, bridge, s.hostName)
	if perr == nil {
		t.Fatal("precondition: provisioning a bound network litevirt would serve DHCP for must refuse")
	}
	if !errors.Is(perr, network.ErrDHCPWouldRaceNetBox) {
		t.Fatalf("refusal must wrap ErrDHCPWouldRaceNetBox, got %v", perr)
	}
	if provBridge != "" {
		t.Fatalf("a refused provision must return no bridge, got %q", provBridge)
	}

	// Step 2, exactly as CreateVM does it: log the refusal, fall back to the
	// network name, and create the bridge.
	if err := s.ensureBridge(bridge); err != nil {
		t.Fatalf("the caller's bridge fallback failed: %v", err)
	}
	if len(created) != 1 || created[0] != bridge {
		t.Fatalf("the caller created %v; the refusal is followed by creating the very bridge it "+
			"declined to create — that is the behaviour the message has to describe", created)
	}

	// The behaviour is now observed. The message must match it.
	msg := perr.Error()
	if strings.Contains(msg, "no VM can be placed") {
		t.Fatalf("the refusal claims placement is prevented, one line after a placement "+
			"proceeded through it: %q", msg)
	}
	for _, want := range []string{"DOES NOT STOP A PLACEMENT", "no gateway"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must say what really happens (%q missing): %q", want, msg)
		}
	}
}

// The refusal is the ONLY thing standing between a bound prefix and litevirt's
// own dnsmasq, and this branch fixes a message, not a guard. So pin that the
// guard is intact: no host-local input starts a DHCP server on a bound network.
//
// startDHCPFor asks the same exported predicate, so the two cannot drift — but
// "cannot drift" is a claim about today's call graph, and this is the property
// that actually matters if it ever does.
func TestTheDHCPRaceRefusalItselfIsStillUnconditional(t *testing.T) {
	def := dhcpBoundNetworkDef
	def.NetBoxPrefixID = 7
	for _, f := range []network.DHCPHostFacts{
		{BridgePreExisted: false, IsGatewayHost: false},
		{BridgePreExisted: false, IsGatewayHost: true},
		{BridgePreExisted: true, IsGatewayHost: false},
		{BridgePreExisted: true, IsGatewayHost: true},
	} {
		if !network.DHCPWouldServe(def, f) {
			continue // litevirt starts no DHCP server here, so there is nothing to refuse
		}
		if err := network.BoundNetworkDHCPRefusal(def, f, "bound-net", def.Interface, "node-7"); err == nil {
			t.Fatalf("facts %+v would start dnsmasq over the bound prefix and were NOT refused", f)
		}
	}
}

// A NIC on a bound network still claims its address from NetBox even though the
// bridge is the auto-created one — which is why the finding has to persist. It
// is also the reason the finding is a WARNING and not an admission refusal:
// nothing here is a duplicate address, it is a guest with no route.
func TestTheAutoCreatedBridgeFindingDoesNotDependOnAnyClaim(t *testing.T) {
	def := dhcpBoundNetworkDef
	def.NetBoxPrefixID = 7

	// The bridge exists and carries nothing: the state a placement leaves.
	if err := network.BoundNetworkAutoBridgeFinding(def, true, false,
		"bound-net", def.Interface, "node-7"); err == nil {
		t.Fatal("an uplink-less bridge on a bound network litevirt would serve DHCP for must be reported")
	}
	// The operator's remedy: an infrastructure bridge with an uplink.
	if err := network.BoundNetworkAutoBridgeFinding(def, true, true,
		"bound-net", def.Interface, "node-7"); err != nil {
		t.Fatalf("an uplinked infrastructure bridge is the documented remedy and must clear: %v", err)
	}
	// The operator's other remedy: a definition litevirt serves no DHCP for.
	tagged := def
	tagged.VLAN = 100
	if err := network.BoundNetworkAutoBridgeFinding(tagged, true, false,
		"bound-net", tagged.Interface, "node-7"); err != nil {
		t.Fatalf("a tagged physical VLAN starts no DHCP server, so nothing is wrong: %v", err)
	}
	// An UNBOUND network is every network in every existing deployment: an
	// empty litevirt-made bridge there is the ordinary case, not a finding.
	unbound := def
	unbound.NetBoxPrefixID = 0
	if err := network.BoundNetworkAutoBridgeFinding(unbound, true, false,
		"plain-net", unbound.Interface, "node-7"); err != nil {
		t.Fatalf("an unbound network must never be reported: %v", err)
	}
	// And before any placement, when the bridge does not exist here, this
	// predicate says nothing — that state is the refusal's.
	if err := network.BoundNetworkAutoBridgeFinding(def, false, false,
		"bound-net", def.Interface, "node-7"); err != nil {
		t.Fatalf("a missing bridge is the refusal's finding, not this one: %v", err)
	}
}
