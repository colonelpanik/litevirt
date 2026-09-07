package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The operator surface for the provision-time DHCP refusal.
//
// That refusal is what closes the host-local half of the hazard, and it must
// stay — but its consequence is that a host whose bridge state makes dnsmasq
// serve a bound network can no longer place VMs there. The refusal itself only
// speaks when somebody has already hit it, from whichever node the scheduler
// picked. This makes it discoverable BEFORE that: every configured node
// evaluates its OWN bridge state against every bound network on each
// revalidation pass and raises a finding naming itself, the network and what to
// change.
//
// It is derivable in advance precisely because the refusal is now idempotent: a
// refused provision creates no bridge, so the state the evaluator reads is the
// state the provision would read (internal/network/dhcp_gate_host_test.go).

// dhcpBoundNetworkDef is the one shape that reaches the provision-time refusal:
// a managed bridge with a subnet, no VLAN, not host-isolated. Every other shape
// is refused at BIND time and cluster-wide, because its DHCP answer does not
// depend on which host is asking.
var dhcpBoundNetworkDef = compose.NetworkDef{
	Type: "bridge", Interface: "lv-dhcp-net", Subnet: "10.0.5.0/24",
}

// boundDHCPNetworkOn binds a prefix whose network WOULD have litevirt serve DHCP
// on a host lacking the bridge, and returns the server.
//
// The bind itself has to be allowed, which means the BINDING node must have the
// bridge — that is the one shape check 2b permits on this host's own evidence,
// and the shape whose whole point is that another host may differ.
func boundDHCPNetworkOn(t *testing.T, hostHasBridge bool) *Server {
	t.Helper()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	// The bind runs while the bridge EXISTS here, so litevirt would create no
	// bridge and start no dnsmasq — permitted.
	s.SetBridgeExists(func(string) bool { return true })

	def := dhcpBoundNetworkDef
	if err := s.validateAndBindPrefix(context.Background(), def.Interface, adoptTestPrefix, def); err != nil {
		t.Fatalf("the bind must be permitted on a host that already has the bridge: %v", err)
	}
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: def.Interface, Type: def.Type,
		Config: `{"type":"bridge","interface":"` + def.Interface + `","subnet":"` +
			def.Subnet + `","netbox_prefix_id":` + "7" + `}`,
	}); err != nil {
		t.Fatalf("persist network: %v", err)
	}
	// …and NOW this host's answer becomes the one under test.
	s.SetBridgeExists(func(string) bool { return hostHasBridge })
	return s
}

// TestAHostThatCannotProvisionABoundNetworkRaisesAFinding.
func TestAHostThatCannotProvisionABoundNetworkRaisesAFinding(t *testing.T) {
	s := boundDHCPNetworkOn(t, false)
	ctx := context.Background()

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	h, ok := netboxCondition(t, s, condNetBoxDHCPWouldRace, s.hostName)
	if !ok {
		t.Fatal("a host that would refuse to provision a bound network must say so in lv health, " +
			"not only when a placement fails there")
	}
	if h.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("the finding must be live, got %+v", h)
	}
	// Everything an operator needs: which host, which network, which prefix, and
	// what to change.
	for _, want := range []string{s.hostName, dhcpBoundNetworkDef.Interface, "7"} {
		if !strings.Contains(h.Evidence, want) {
			t.Fatalf("the evidence must name %q, got %q", want, h.Evidence)
		}
	}
	if !strings.Contains(h.Evidence, "no VM can be placed") {
		t.Fatalf("the evidence must state the consequence, got %q", h.Evidence)
	}
}

// TestAHostThatCanProvisionABoundNetworkRaisesNothing is the control. Every
// existing bound network in every existing deployment is on a host that has its
// bridge; a finding there would be permanent noise.
func TestAHostThatCanProvisionABoundNetworkRaisesNothing(t *testing.T) {
	s := boundDHCPNetworkOn(t, true)
	ctx := context.Background()

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h, ok := netboxCondition(t, s, condNetBoxDHCPWouldRace, s.hostName); ok &&
		h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a host that can provision the network must raise nothing, got %+v", h)
	}
}

// TestTheDHCPFindingClearsWhenTheBridgeAppears: the remedy the message names is
// "create the bridge here", so doing it has to resolve the finding — otherwise
// an operator who fixed it is left with a row that never goes away.
func TestTheDHCPFindingClearsWhenTheBridgeAppears(t *testing.T) {
	s := boundDHCPNetworkOn(t, false)
	ctx := context.Background()

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := netboxCondition(t, s, condNetBoxDHCPWouldRace, s.hostName); !ok {
		t.Fatal("precondition: the finding must be raised first")
	}

	s.SetBridgeExists(func(string) bool { return true })
	for i := 0; i < netboxCleanPasses; i++ {
		if err := s.RevalidateBindingsOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	h, ok := netboxCondition(t, s, condNetBoxDHCPWouldRace, s.hostName)
	if !ok {
		t.Fatal("the row must still exist, resolved")
	}
	if h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("creating the bridge must resolve the finding, got %+v", h)
	}
}

// TestAnUnboundNetworkNeverRaisesTheDHCPFinding: the hazard is NetBox and
// litevirt allocating from one range. Without a binding there is no second
// allocator, and litevirt serving DHCP on its own managed bridge is the ordinary
// case this product has always had.
func TestAnUnboundNetworkNeverRaisesTheDHCPFinding(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: adoptTestPrefix, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	ctx := context.Background()
	s.SetBridgeExists(func(string) bool { return false })
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "plain", Type: "bridge",
		Config: `{"type":"bridge","interface":"lv-plain","subnet":"10.0.5.0/24"}`,
	}); err != nil {
		t.Fatalf("persist network: %v", err)
	}

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h, ok := netboxCondition(t, s, condNetBoxDHCPWouldRace, s.hostName); ok &&
		h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("an unbound network must raise nothing, got %+v", h)
	}
}
