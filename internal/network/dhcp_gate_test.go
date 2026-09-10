package network

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestDHCPWouldServeMatchesProvisioning is the anti-drift guard: for every shape
// it can reach, it asserts that DHCPWouldServe's answer is EXACTLY what Provision
// does. The bind-time refusal decides from this predicate, and a predicate that
// merely resembled the provisioning gate would be the third comment on this
// branch that disagreed with the code it described.
//
// Provision is driven for real (exec and the DHCP starter stubbed) rather than
// re-asserting the predicate against itself, so a change to either side that the
// other did not follow fails here.
func TestDHCPWouldServeMatchesProvisioning(t *testing.T) {
	// A loopback interface always exists, so naming it makes bridgePreExisted
	// true without root; a name nothing can have makes it false.
	existing := testLoopbackInterface(t)
	const missing = "lv-no-such-br0"

	cases := []struct {
		name string
		def  compose.NetworkDef
		// facts is what Provision will observe on this host for this def. The
		// test asserts DHCPWouldServe(def, facts) == "Provision started dnsmasq".
		facts DHCPHostFacts
		// peerVTEP seeds a lower-sorting VTEP so isGatewayHost is false.
		peerVTEP bool
	}{{
		name:  "managed bridge with a subnet serves",
		def:   compose.NetworkDef{Type: "bridge", Interface: missing, Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{BridgePreExisted: false},
	}, {
		name:  "pre-existing bridge with a subnet does not serve",
		def:   compose.NetworkDef{Type: "bridge", Interface: existing, Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{BridgePreExisted: true},
	}, {
		name:  "pre-existing bridge with an explicit dhcp flag serves",
		def:   compose.NetworkDef{Type: "bridge", Interface: existing, Subnet: "10.0.5.0/24", DHCP: true},
		facts: DHCPHostFacts{BridgePreExisted: true},
	}, {
		name:  "managed bridge with no subnet does not serve",
		def:   compose.NetworkDef{Type: "bridge", Interface: missing},
		facts: DHCPHostFacts{BridgePreExisted: false},
	}, {
		name:  "physical VLAN does not serve",
		def:   compose.NetworkDef{Type: "bridge", Interface: missing, Subnet: "10.0.5.0/24", VLAN: 209, Underlay: existing},
		facts: DHCPHostFacts{BridgePreExisted: false},
	}, {
		name:  "host-isolated bridge does not serve",
		def:   compose.NetworkDef{Type: "bridge", Interface: missing, Subnet: "10.0.5.0/24", HostIsolation: true},
		facts: DHCPHostFacts{BridgePreExisted: false},
	}, {
		name:  "isolated network with a subnet serves whatever the bridge state",
		def:   compose.NetworkDef{Type: "isolated", Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{BridgePreExisted: true},
	}, {
		name:  "host-isolated isolated network does not serve",
		def:   compose.NetworkDef{Type: "isolated", Subnet: "10.0.5.0/24", HostIsolation: true},
		facts: DHCPHostFacts{BridgePreExisted: true},
	}, {
		name:  "vxlan gateway host serves",
		def:   compose.NetworkDef{Type: "vxlan", VNI: 42, Underlay: existing, Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{IsGatewayHost: true},
	}, {
		name:     "vxlan non-gateway host does not serve",
		def:      compose.NetworkDef{Type: "vxlan", VNI: 43, Underlay: existing, Subnet: "10.0.5.0/24"},
		facts:    DHCPHostFacts{IsGatewayHost: false},
		peerVTEP: true,
	}, {
		name:  "sriov does not serve",
		def:   compose.NetworkDef{Type: "sriov", PF: existing, Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{},
	}, {
		name:  "direct does not serve",
		def:   compose.NetworkDef{Type: "direct", Interface: existing, Subnet: "10.0.5.0/24"},
		facts: DHCPHostFacts{},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execCommand = func(name string, args ...string) ([]byte, error) { return nil, nil }
			defer func() { execCommand = defaultExec }()
			started := false
			startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error {
				started = true
				return nil
			}
			defer func() { startDHCPFunc = StartDHCP }()

			db, err := corrosion.NewTestClient()
			if err != nil {
				t.Fatalf("NewTestClient: %v", err)
			}
			ctx := context.Background()
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			if tc.peerVTEP {
				// Sorts before "host1", so host1 is not the gateway.
				if err := UpsertVTEP(ctx, db, tc.name, "aaa-peer", "10.9.9.9", tc.def.VNI); err != nil {
					t.Fatalf("seed peer VTEP: %v", err)
				}
			}
			if _, err := Provision(ctx, db, tc.name, tc.def, "10.0.0.1", "host1"); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if want := DHCPWouldServe(tc.def, tc.facts); started != want {
				t.Fatalf("Provision started dnsmasq = %v, but DHCPWouldServe(def, %+v) = %v — the "+
					"bind-time refusal reads the predicate, so the two must agree exactly",
					started, tc.facts, want)
			}
		})
	}
}

// TestDHCPHostFactsFullyEnumerated pins that the bind's fact enumeration covers
// every host-local input to the predicate. The bind cannot observe another
// host's facts, so it quantifies over them; a new field added to DHCPHostFacts
// without extending bindFactAssignments would be silently left at its zero
// value, and the quantification would stop being exhaustive without anything
// saying so.
func TestDHCPHostFactsFullyEnumerated(t *testing.T) {
	fields := reflect.TypeOf(DHCPHostFacts{}).NumField()
	for i := 0; i < fields; i++ {
		if k := reflect.TypeOf(DHCPHostFacts{}).Field(i).Type.Kind(); k != reflect.Bool {
			t.Fatalf("DHCPHostFacts field %d is a %s; the enumeration below assumes booleans",
				i, k)
		}
	}
	want := 1 << fields
	if got := len(bindFactAssignments); got != want {
		t.Fatalf("bindFactAssignments has %d entries but DHCPHostFacts has %d boolean fields "+
			"(%d assignments) — extend the enumeration, or the bind's quantification is no "+
			"longer exhaustive", got, fields, want)
	}
	seen := map[DHCPHostFacts]bool{}
	certain := 0
	for _, a := range bindFactAssignments {
		if seen[a.facts] {
			t.Fatalf("bindFactAssignments repeats %+v", a.facts)
		}
		seen[a.facts] = true
		if a.certain {
			certain++
		}
	}
	if certain == 0 {
		t.Fatal("no fact assignment is marked cluster-certain, so the bind would decide from the " +
			"binding node's own state alone and a bind of an isolated network would depend on " +
			"which node ran it")
	}
}

// TestCheckDHCPBindConflict pins the refusal rule itself, including every shape
// that must stay bindable. Over-refusal is not a safe default here: a bound
// network's subnet is what supplies the guest's prefix length and default
// gateway (staticIfaceGatewayAddress), so refusing every subnet would push
// operators into a shape where guests get a /24 guess and no route.
func TestCheckDHCPBindConflict(t *testing.T) {
	const prefix = "10.0.5.0/24"
	cases := []struct {
		name             string
		def              compose.NetworkDef
		bridgeExistsHere bool
		wantRefusal      bool
		wantMentions     string
	}{{
		name:        "isolated network with an overlapping subnet is refused on any node",
		def:         compose.NetworkDef{Type: "isolated", Subnet: "10.0.5.0/24"},
		wantRefusal: true, wantMentions: "every host",
	}, {
		name:             "explicit dhcp on a pre-existing bridge is refused on any node",
		def:              compose.NetworkDef{Type: "bridge", Interface: "br0", Subnet: "10.0.5.0/24", DHCP: true},
		bridgeExistsHere: true,
		wantRefusal:      true, wantMentions: "every host",
	}, {
		name:        "vxlan with an overlapping subnet is refused on any node",
		def:         compose.NetworkDef{Type: "vxlan", VNI: 42, Subnet: "10.0.5.0/24"},
		wantRefusal: true, wantMentions: "every host",
	}, {
		name:             "managed bridge is refused on this node's own evidence",
		def:              compose.NetworkDef{Type: "bridge", Interface: "lv-net", Subnet: "10.0.5.0/24"},
		bridgeExistsHere: false,
		wantRefusal:      true, wantMentions: "this host",
	}, {
		name:             "infrastructure bridge that already exists here is bindable",
		def:              compose.NetworkDef{Type: "bridge", Interface: "br0", Subnet: "10.0.5.0/24"},
		bridgeExistsHere: true,
		wantRefusal:      false,
	}, {
		name:             "physical VLAN is bindable",
		def:              compose.NetworkDef{Type: "bridge", Interface: "br0", Subnet: "10.0.5.0/24", VLAN: 100},
		bridgeExistsHere: false,
		wantRefusal:      false,
	}, {
		name:             "macvtap is bindable",
		def:              compose.NetworkDef{Type: "direct", Interface: "bond0.100", Subnet: "10.0.5.0/24"},
		bridgeExistsHere: false,
		wantRefusal:      false,
	}, {
		name:             "no subnet is bindable",
		def:              compose.NetworkDef{Type: "bridge", Interface: "lv-net"},
		bridgeExistsHere: false,
		wantRefusal:      false,
	}, {
		name:             "host-isolated is bindable",
		def:              compose.NetworkDef{Type: "bridge", Interface: "lv-net", Subnet: "10.0.5.0/24", HostIsolation: true},
		bridgeExistsHere: false,
		wantRefusal:      false,
	}, {
		name:             "a subnet disjoint from the prefix is bindable",
		def:              compose.NetworkDef{Type: "isolated", Subnet: "192.168.77.0/24"},
		bridgeExistsHere: false,
		wantRefusal:      false,
	}, {
		name:             "a subnet CONTAINING the prefix is refused",
		def:              compose.NetworkDef{Type: "isolated", Subnet: "10.0.0.0/16"},
		bridgeExistsHere: false,
		wantRefusal:      true,
	}, {
		name:             "an unparseable subnet is refused rather than assumed disjoint",
		def:              compose.NetworkDef{Type: "isolated", Subnet: "not-a-cidr"},
		bridgeExistsHere: false,
		wantRefusal:      true, wantMentions: "could not",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDHCPBindConflict(tc.def, prefix, tc.bridgeExistsHere)
			if tc.wantRefusal && err == nil {
				t.Fatalf("want a refusal for %+v", tc.def)
			}
			if !tc.wantRefusal && err != nil {
				t.Fatalf("want no refusal for %+v, got %v", tc.def, err)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrDHCPWouldRaceNetBox) {
				t.Fatalf("refusal must wrap ErrDHCPWouldRaceNetBox, got %v", err)
			}
			if tc.wantMentions != "" && !strings.Contains(err.Error(), tc.wantMentions) {
				t.Fatalf("refusal %q must say %q so an operator knows whether it is a "+
					"cluster-wide fact or this node's own state", err, tc.wantMentions)
			}
		})
	}
}

// TestProvisionRefusesDHCPOverABoundPrefix is the other half of the refusal, and
// the half that covers the hosts a bind cannot speak for. bridgePreExisted is
// host-local, so a bind validated on one node says nothing about a node that
// lacks the bridge — and that node is exactly where litevirt would start a
// second allocator over the bound prefix. Provisioning is where the fact is
// finally known, so provisioning refuses.
func TestProvisionRefusesDHCPOverABoundPrefix(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()
	started := false
	startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error {
		started = true
		return nil
	}
	defer func() { startDHCPFunc = StartDHCP }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type: "bridge", Interface: "lv-no-such-br1", Subnet: "10.0.5.0/24",
		NetBoxPrefixID: 7,
	}
	_, err = Provision(ctx, db, "bound-net", def, "10.0.0.1", "host1")
	if err == nil {
		t.Fatal("want Provision to refuse: this host would start a DHCP server over a bound prefix")
	}
	if !errors.Is(err, ErrDHCPWouldRaceNetBox) {
		t.Fatalf("refusal must wrap ErrDHCPWouldRaceNetBox, got %v", err)
	}
	if started {
		t.Fatal("dnsmasq was started anyway — the refusal must precede the start")
	}
}

// TestProvisionServesDHCPOnAnUnboundNetwork is the negative control: the refusal
// must be scoped to bound networks. Every existing network in every existing
// deployment is unbound, and a guard that stopped their DHCP server would be a
// far worse regression than the hazard it closes.
func TestProvisionServesDHCPOnAnUnboundNetwork(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()
	started := false
	startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error {
		started = true
		return nil
	}
	defer func() { startDHCPFunc = StartDHCP }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{Type: "bridge", Interface: "lv-no-such-br2", Subnet: "10.0.5.0/24"}
	if _, err := Provision(ctx, db, "unbound-net", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !started {
		t.Fatal("an unbound managed network must still get its DHCP server")
	}
}
