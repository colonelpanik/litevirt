package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// The bind-time half of the "litevirt's own DHCP would race NetBox" refusal.
//
// The predicate itself is pinned in internal/network (TestCheckDHCPBindConflict,
// and TestDHCPWouldServeMatchesProvisioning against real provisioning). What
// these pin is the bind: that the refusal is reached at all, that it claims
// NOTHING when it fires, and that the shapes an operator actually deploys stay
// bindable.

// bindDHCPServer wires a bind fixture whose host-local bridge answer is fixed by
// the test rather than by whatever interfaces this machine happens to have.
// bridgeExistsHere is the ONE host-local fact the bind can observe, so a fixture
// that let the real host decide it would make the two interesting cases pass or
// fail depending on the test machine.
func bindDHCPServer(t *testing.T, bridgeExistsHere bool) *Server {
	t.Helper()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	s.SetBridgeExists(func(string) bool { return bridgeExistsHere })
	return s
}

func TestBindRefusesANetworkLitevirtServesDHCPForOnEveryHost(t *testing.T) {
	// An isolated network has no uplink and no router, so a subnet alone starts
	// dnsmasq on EVERY host. The refusal must therefore not depend on the
	// binding node's own state — this fixture says the bridge already exists,
	// which is the assignment that makes the bridge case safe.
	s := bindDHCPServer(t, true)
	ctx := context.Background()
	def := compose.NetworkDef{Type: "isolated", Subnet: "10.0.5.0/24"}

	err := s.validateAndBindPrefix(ctx, "iso-net", 7, def)
	if err == nil {
		t.Fatal("want a refusal: dnsmasq serves this subnet on every host")
	}
	if !errors.Is(err, network.ErrDHCPWouldRaceNetBox) {
		t.Fatalf("want ErrDHCPWouldRaceNetBox, got %v", err)
	}
	if !strings.Contains(err.Error(), "every host") {
		t.Fatalf("the refusal must say it is a cluster-wide fact, not this node's state: %v", err)
	}
	// A refused bind must have claimed nothing — same property every other
	// pre-claim refusal in validateAndBindPrefix has.
	b, gerr := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if gerr != nil {
		t.Fatalf("GetBindingByPrefix: %v", gerr)
	}
	if b != nil {
		t.Fatalf("the refused bind claimed the prefix anyway: %+v", b)
	}
}

func TestBindRefusesOnThisNodesOwnBridgeEvidence(t *testing.T) {
	// A litevirt-managed bridge: a subnet ALONE starts dnsmasq, the --dhcp flag
	// is irrelevant. bridgePreExisted is host-local, and this node's own answer
	// is the only one a bind can obtain.
	s := bindDHCPServer(t, false)
	ctx := context.Background()
	def := compose.NetworkDef{Type: "bridge", Interface: "lv-net", Subnet: "10.0.5.0/24"}

	err := s.validateAndBindPrefix(ctx, "lv-net", 7, def)
	if err == nil {
		t.Fatal("want a refusal: litevirt would create this bridge and serve DHCP on it here")
	}
	if !errors.Is(err, network.ErrDHCPWouldRaceNetBox) {
		t.Fatalf("want ErrDHCPWouldRaceNetBox, got %v", err)
	}
	if !strings.Contains(err.Error(), "this host") {
		t.Fatalf("the refusal must say it is this node's own state, not a cluster-wide fact "+
			"— another host may already have the bridge: %v", err)
	}
}

func TestBindAllowsAnInfrastructureBridgeWithASubnet(t *testing.T) {
	// THE shape this refusal must not break: an existing infrastructure bridge
	// with a subnet recorded and no DHCP. dnsmasq does not start on a bridge it
	// did not create, and the subnet is what supplies a guest's prefix length
	// and default gateway, so refusing it would push operators into a shape
	// where guests get a /24 guess and no route.
	s := bindDHCPServer(t, true)
	ctx := context.Background()
	def := compose.NetworkDef{Type: "bridge", Interface: "br-infra", Subnet: "10.0.5.0/24"}

	if err := s.validateAndBindPrefix(ctx, "infra", 7, def); err != nil {
		t.Fatalf("an infrastructure bridge with a subnet must stay bindable: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("GetBindingByPrefix: %v (binding %+v)", err, b)
	}
}

func TestBindAllowsASubnetDisjointFromThePrefix(t *testing.T) {
	// dnsmasq serves the litevirt network's subnet; NetBox allocates from the
	// prefix. Disjoint ranges share no address, so there is nothing to collide
	// on and nothing to refuse — even on a shape that definitely starts dnsmasq.
	s := bindDHCPServer(t, false)
	ctx := context.Background()
	def := compose.NetworkDef{Type: "isolated", Subnet: "192.168.77.0/24"}

	if err := s.validateAndBindPrefix(ctx, "iso-disjoint", 7, def); err != nil {
		t.Fatalf("a subnet disjoint from the bound prefix must stay bindable: %v", err)
	}
}
