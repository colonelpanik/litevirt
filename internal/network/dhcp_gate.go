package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/litevirt/litevirt/internal/compose"
)

// litevirt's own DHCP server versus NetBox as the address authority.
//
// THE HAZARD. When Provision starts dnsmasq it derives the gateway as network+1
// and serves a pool spanning essentially the whole subnet (SubnetRange). None of
// that is a database row: no lease, no allocation, nothing NetBox is ever told.
// So if a bound NetBox prefix overlaps that subnet, NetBox's /available-ips/ and
// dnsmasq allocate from the same range with no knowledge of each other — and
// because the gateway is inside the pool's own network, NetBox will eventually
// offer a VM the gateway address itself.
//
// WHY A REFUSAL AND NOT A RESERVATION. The gateway is one address and could be
// reserved in NetBox the way bind-time adoption reserves the addresses guests
// already hold. The POOL cannot: it is dynamic, it spans the prefix, and
// reserving it would leave NetBox nothing to allocate — a bind that reserved the
// pool would be a bind with no purpose. So where dnsmasq serves, the only sound
// answer is to refuse the bind. See docs/networking.md for what this leaves
// open, which is not nothing: an LB VIP takes no lease either, and on the shapes
// this permits the gateway belongs to infrastructure litevirt does not manage
// and still is not reserved.
//
// ONE PREDICATE, TWO CALLERS. DHCPWouldServe is THE gate: Provision decides
// whether to start dnsmasq by calling it, and the bind-time refusal decides by
// calling it. A refusal that re-derived the rule would be a second copy of it,
// and this branch has already shipped comments that disagreed with the code they
// described. TestDHCPWouldServeMatchesProvisioning drives Provision for real and
// compares, so a change to either side that the other did not follow fails.

// ErrDHCPWouldRaceNetBox is the sentinel every refusal in this file wraps, so a
// caller can tell this specific precondition from the other bind-time refusals.
var ErrDHCPWouldRaceNetBox = errors.New("litevirt's own DHCP server would allocate from the bound prefix")

// DHCPHostFacts are the HOST-LOCAL runtime inputs to the DHCP-start decision.
//
// They are what makes this awkward: a bind is a cluster-wide decision, and these
// are answers only one host can give. Keeping them in a named struct rather than
// as bare parameters is what lets the bind QUANTIFY over them (bindFactAssignments)
// instead of guessing, and lets a test assert the quantification is exhaustive.
//
// Every field must be a bool, and every field must be reachable by
// bindFactAssignments — TestDHCPHostFactsFullyEnumerated pins both.
type DHCPHostFacts struct {
	// BridgePreExisted is whether the bridge already existed before litevirt
	// touched it. A pre-existing bridge is an infrastructure bridge, which must
	// not acquire a DHCP server it was never asked for; one litevirt created is
	// litevirt's to serve. Nothing in the schema records this, and it can differ
	// between two hosts running the identical network definition.
	BridgePreExisted bool
	// IsGatewayHost is whether this host is the elected anycast gateway for a
	// vxlan network (isGatewayHost: the lowest-sorting VTEP, or the only host).
	// Exactly one host in a cluster has it, so unlike BridgePreExisted its true
	// value is CERTAIN to occur somewhere.
	IsGatewayHost bool
}

// DHCPWouldServe reports whether Provision starts a dnsmasq DHCP server for def
// on a host observing f.
//
// This is the gate itself, not a model of it: the three sites in Provision that
// could start dnsmasq all route through startDHCPFor, which asks this function.
func DHCPWouldServe(def compose.NetworkDef, f DHCPHostFacts) bool {
	// A host-isolated network delivers addresses through cloud-init and gets no
	// DHCP server on any type; no subnet means there is no range to serve.
	if def.HostIsolation || def.Subnet == "" {
		return false
	}
	switch def.Type {
	case "", "bridge":
		// A VLAN puts the bridge on a physical network with its own router, so
		// litevirt serves nothing. Otherwise a subnet ALONE starts dnsmasq on a
		// litevirt-managed bridge — the --dhcp flag only matters for a bridge
		// that already existed.
		return def.VLAN == 0 && (!f.BridgePreExisted || def.DHCP)
	case "vxlan":
		// The elected gateway host serves the whole overlay.
		return f.IsGatewayHost
	case "isolated":
		// No uplink and no router, so litevirt is the only possible source of
		// addresses: a subnet always starts dnsmasq, on every host.
		return true
	default:
		// sriov and direct attach guests to hardware litevirt does not address;
		// any other type Provision refuses outright.
		return false
	}
}

// bindFactAssignments is every assignment of the host-local facts a bind must
// consider, with whether that assignment is CERTAIN to occur on at least one
// host of every cluster.
//
// This is how the cluster-wide question gets answered from the host-local
// predicate without a second copy of the rule: the bind evaluates DHCPWouldServe
// over these assignments rather than reasoning about the rule's shape. If some
// certain assignment serves, dnsmasq serves somewhere no matter which node ran
// the bind, and the refusal is a cluster-wide fact.
var bindFactAssignments = []struct {
	facts   DHCPHostFacts
	certain bool
	// why records the reasoning, so a later reader can check it rather than
	// trusting the boolean.
	why string
}{{
	facts: DHCPHostFacts{BridgePreExisted: true, IsGatewayHost: true},
	// Both halves occur: a cluster always has an elected vxlan gateway, and an
	// infrastructure bridge that already exists is the whole point of the
	// pre-existing case.
	certain: true,
	why:     "some host is always the elected vxlan gateway; a bridge that already exists is the infrastructure-bridge case",
}, {
	facts:   DHCPHostFacts{BridgePreExisted: true, IsGatewayHost: false},
	certain: true,
	why:     "every host but the elected gateway has IsGatewayHost false",
}, {
	facts: DHCPHostFacts{BridgePreExisted: false, IsGatewayHost: true},
	// NOT certain: whether litevirt has to create the bridge is host-local
	// operator state, and a cluster can be all-pre-existing.
	certain: false,
	why:     "whether litevirt creates the bridge is host-local operator state that no row records",
}, {
	facts:   DHCPHostFacts{BridgePreExisted: false, IsGatewayHost: false},
	certain: false,
	why:     "whether litevirt creates the bridge is host-local operator state that no row records",
}}

// CheckDHCPBindConflict is the bind-time refusal. It returns nil when binding
// prefixCIDR to a network defined by def is safe as far as litevirt's own DHCP
// server is concerned.
//
// bridgeExistsHere is the BINDING NODE's own answer, and it is the only
// host-local answer a bind can obtain. The hosts it cannot speak for are covered
// at provision time instead (startDHCPFor), where the fact is finally known on
// the host it belongs to.
//
// The refusal requires OVERLAP with the prefix. dnsmasq serves the litevirt
// network's subnet and NetBox allocates from the prefix; where those ranges are
// disjoint there is no shared address to collide on. Over-refusal is not a safe
// default here — a bound network's subnet is what supplies a guest's prefix
// length and default gateway (staticIfaceGatewayAddress), so refusing every
// recorded subnet would push operators into a shape where guests get a /24 guess
// and no route.
func CheckDHCPBindConflict(def compose.NetworkDef, prefixCIDR string, bridgeExistsHere bool) error {
	// Cluster-wide first: an assignment that always occurs somewhere makes the
	// answer independent of which node ran the bind, so report it as such.
	const remedy = "Bind a prefix that does not overlap, or define the network so litevirt serves " +
		"no DHCP on it: set a VLAN for a tagged physical network, use type direct, or drop the " +
		"subnet (a bound network allocates from the NetBox prefix, not from its own subnet)"
	const consequence = "dnsmasq assigns the gateway and leases a pool across that subnet without " +
		"recording a single row, so NetBox would offer those same addresses to the next VM — and " +
		"eventually the gateway itself"

	for _, a := range bindFactAssignments {
		if !a.certain || !DHCPWouldServe(def, a.facts) {
			continue
		}
		reason, overlaps := overlapReason(def.Subnet, prefixCIDR)
		if !overlaps {
			return nil
		}
		return fmt.Errorf("%w: litevirt serves DHCP for the subnet %s of network %q on every host "+
			"that can run it (%s), and %s. %s. %s",
			ErrDHCPWouldRaceNetBox, def.Subnet, def.Interface, a.why, reason, consequence, remedy)
	}
	// Then this node's own state, which speaks for this host only.
	if DHCPWouldServe(def, DHCPHostFacts{BridgePreExisted: bridgeExistsHere, IsGatewayHost: true}) {
		reason, overlaps := overlapReason(def.Subnet, prefixCIDR)
		if !overlaps {
			return nil
		}
		return fmt.Errorf("%w: litevirt would serve DHCP for the subnet %s of network %q on this "+
			"host — the bridge %q does not exist here, so litevirt creates it and starts dnsmasq "+
			"on it — and %s. %s. %s",
			ErrDHCPWouldRaceNetBox, def.Subnet, def.Interface, def.Interface, reason, consequence, remedy)
	}
	return nil
}

// overlapReason reports whether subnet may share an address with prefixCIDR, and
// the operator-facing reason it decided so.
//
// FAIL CLOSED on anything unparseable. "We could not read one of the two CIDRs"
// is not "they are disjoint", and a bind is the last point at which this can be
// refused cheaply.
func overlapReason(subnetCIDR, prefixCIDR string) (string, bool) {
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return fmt.Sprintf("the network subnet %q could not be parsed, so an overlap with NetBox "+
			"prefix %s cannot be ruled out", subnetCIDR, prefixCIDR), true
	}
	_, prefix, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return fmt.Sprintf("the NetBox prefix %q could not be parsed, so an overlap with the "+
			"network subnet %s cannot be ruled out", prefixCIDR, subnetCIDR), true
	}
	// Two CIDRs are either disjoint or nested, so containment either way is the
	// whole test.
	if subnet.Contains(prefix.IP) || prefix.Contains(subnet.IP) {
		return fmt.Sprintf("NetBox prefix %s overlaps it", prefixCIDR), true
	}
	return "", false
}

// BoundNetworkDHCPRefusal is the PROVISION-TIME refusal, exported so the one
// predicate serves both consumers that need it: Provision, which enforces it,
// and the health evaluator that makes it discoverable before a placement hits
// it. Two copies would drift, which is the mistake this file already exists to
// avoid.
//
// It returns nil unless def is bound to a NetBox prefix AND litevirt's own DHCP
// server would serve it on a host observing f.
//
// hostName IS IN THE MESSAGE, and that is the point of the parameter. This
// refusal surfaces on whichever node the scheduler picked, and the remedy —
// "make sure the bridge exists there, or define the network so litevirt serves
// no DHCP on it" — is not actionable without knowing which node is missing the
// bridge. A message that said "this host" left the operator to work that out
// from a log line on a node they had not been looking at.
//
// WHAT IT DOES NOT CLAIM, and used to. It said "until then no VM can be placed
// on <host>". That was untrue, and it was untrue in the direction that costs an
// operator time: EVERY caller of provisioning logs this refusal at warn level
// and then carries on with the network name as the bridge — CreateVM,
// clone-from-template, the reconciler restarting a VM after a failover, NIC
// hot-attach — and the next thing each of them does is create that very bridge
// through ensureBridge. So the placement SUCCEEDS, on the host the refusal
// named, and what the guest gets is a bridge litevirt just made: no DHCP server
// (that part of the refusal does hold), no uplink, no gateway, and a NetBox
// address that routes nowhere.
//
// The refusal is still worth making and still worth reading — it is the only
// thing that names the misconfiguration, and it is what the
// netbox_dhcp_would_race health finding reports — but it must describe what
// happens, so the message says the bridge gets created anyway. Making the
// placement actually fail is a change to four callers' error handling on a
// pre-existing path, and is deliberately not made here.
func BoundNetworkDHCPRefusal(def compose.NetworkDef, f DHCPHostFacts, networkName, bridge, hostName string) error {
	if def.NetBoxPrefixID == 0 || !DHCPWouldServe(def, f) {
		return nil
	}
	return fmt.Errorf(
		"%w: network %q is bound to NetBox prefix %d, and provisioning it on host %s would start "+
			"a DHCP server for subnet %s on bridge %s — dnsmasq would assign the gateway and "+
			"lease a pool across that subnet with no row NetBox can see, so the two would hand "+
			"the same addresses to different guests. Either create %s on %s as an infrastructure "+
			"bridge with an uplink (a bridge litevirt did not make gets no DHCP server), or define "+
			"the network so litevirt serves no DHCP on it at all: set a VLAN for a tagged physical "+
			"network, use type direct, or drop the subnet. THIS DOES NOT STOP A PLACEMENT: the "+
			"caller logs this refusal and creates %s itself, so a guest placed on %s gets that "+
			"bridge with no DHCP server, no uplink and no gateway while holding an address NetBox "+
			"believes is routable",
		ErrDHCPWouldRaceNetBox, networkName, def.NetBoxPrefixID, hostName, def.Subnet, bridge,
		bridge, hostName, bridge, hostName)
}

// BoundNetworkAutoBridgeFinding is the SECOND state of the same
// misconfiguration: the bridge the refusal declined to create exists now,
// because a placement created it.
//
// It exists because BoundNetworkDHCPRefusal cannot report that state and must
// not. Provisioning asks "would I start dnsmasq here", and once the bridge
// exists the honest answer is no — a pre-existing bridge gets no DHCP server,
// which is the whole shape the refusal steers an operator towards. So the
// refusal goes quiet, and the health finding built on it cleared itself two
// passes later while nothing had been fixed.
//
// The three conditions, and why each is needed:
//
//   - the network is BOUND, so NetBox is the address authority and a guest here
//     holds an address something else believes is routable;
//   - the definition is one litevirt WOULD serve DHCP for had it created the
//     bridge (DHCPWouldServe with BridgePreExisted false — the same predicate,
//     not a copy). This is the part an operator fixes: a VLAN, type direct, no
//     subnet, or unbinding all turn it off, and then this finding goes away
//     whatever the bridge looks like;
//   - the bridge that now exists has NO UPLINK. This is what separates the
//     remedy from the symptom. An infrastructure bridge enslaves a NIC, a bond,
//     a VLAN sub-interface or another bridge, so the router that owns the subnet
//     is reachable and the definition works as documented. A bridge litevirt
//     auto-created holds nothing but guest taps, so the guest has no gateway.
//
// Deliberately NOT called from Provision. Provisioning must keep succeeding on a
// host whose bridge exists — that is the supported configuration — and turning
// this into a provision-time refusal would fail placements on every correctly
// configured host that happens to have a bridge litevirt itself made earlier.
func BoundNetworkAutoBridgeFinding(def compose.NetworkDef, bridgeExists, bridgeHasUplink bool,
	networkName, bridge, hostName string) error {
	if def.NetBoxPrefixID == 0 || !bridgeExists || bridgeHasUplink {
		return nil
	}
	if !DHCPWouldServe(def, DHCPHostFacts{BridgePreExisted: false}) {
		return nil
	}
	return fmt.Errorf(
		"%w: network %q is bound to NetBox prefix %d, and bridge %s on host %s has no uplink — "+
			"nothing is enslaved to it that reaches the router for subnet %s, which is what a "+
			"bridge litevirt created for a placement looks like. Provisioning refused to create "+
			"it (litevirt would have started a DHCP server over the bound prefix) and the caller "+
			"created it anyway, so a guest here has an address from NetBox, no DHCP server and no "+
			"gateway. The definition is still unfixed: give %s an uplink on %s (a NIC, a bond, or "+
			"a VLAN sub-interface), or define the network so litevirt serves no DHCP on it — set a "+
			"VLAN, use type direct, or drop the subnet",
		ErrDHCPWouldRaceNetBox, networkName, def.NetBoxPrefixID, bridge, hostName, def.Subnet,
		bridge, hostName)
}

// startDHCPFor is the ONLY place Provision starts a DHCP server, and the second
// half of the refusal: the half that covers the hosts a bind could not speak
// for.
//
// BridgePreExisted is host-local and nothing records it, so a bind validated on
// one node says nothing about a node that lacks the bridge — and that node is
// exactly where litevirt would create a bridge and stand up a second allocator
// over the bound prefix. Provisioning is where the fact is finally known, so
// provisioning is where it is finally enforced. Failing the provision (rather
// than skipping the DHCP server) is deliberate: a network definition that only
// works on hosts which already have the bridge is a definition an operator has
// to fix, and silently omitting the DHCP server on one host would leave guests
// there with no addresses and no explanation.
func startDHCPFor(def compose.NetworkDef, f DHCPHostFacts, networkName, bridge, hostName, pidFile string) error {
	if err := BoundNetworkDHCPRefusal(def, f, networkName, bridge, hostName); err != nil {
		return err
	}
	if !DHCPWouldServe(def, f) {
		return nil
	}
	gw, rangeStart, rangeEnd, mask, err := SubnetRange(def.Subnet)
	if err != nil {
		return fmt.Errorf("derive DHCP range: %w", err)
	}
	if err := startDHCPFunc(bridge, gw, rangeStart, rangeEnd, mask, pidFile); err != nil {
		return fmt.Errorf("start DHCP on %s: %w", bridge, err)
	}
	return nil
}
