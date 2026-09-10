// Fleet scenarios for the DISCOVERY GATE: what happens when a guest turns out
// to be using an address litevirt never allocated, on a network bound to NetBox.
//
// This is the second half of bind-time adoption, and the half that covers what
// the bind deliberately lets through. A bind proceeds over a STOPPED VM whose
// NIC address litevirt has not recorded — a stopped guest holds nothing, and
// refusing there would refuse nearly every bind on a real cluster. The moment
// that VM is started, its guest may pick up an address from an external DHCP
// server, and the 30-second IP scanner is what finds out.
//
// Recording it used to be an unguarded write (corrosion.UpdateVMInterfaceIP from
// four call sites, one of them inside ListVMs). Now it is a CLAIM: the address
// is recorded only once NetBox has granted it to that NIC, and a refusal is
// surfaced instead of written.
//
// Both scenarios drive the PRODUCTION pass — grpcapi.IPScanner over real gRPC-
// created VMs, a real allocator and a real NetBox client — with only the ARP
// lookup stubbed, because a test process has no guest answering ARP. Every
// address here is in the fake's own band so the assertions cannot be satisfied
// by the builtin allocator.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// discoveryFreeIP is an address inside the bound prefix that NetBox holds no
// object for — the positive control's address. Outside the fake's sequential
// band so it cannot collide with an ordinary claim.
const discoveryFreeIP = "10.0.5.150"

// discoveryDNSDomain is the DNS domain the scanner publishes auto records under.
// Set on the node, because the scanner skips DNS entirely when it is empty and
// the DNS half of the gate would then be asserted over nothing.
const discoveryDNSDomain = "fleet.local"

// mustStartVM starts a VM through the real RPC.
func mustStartVM(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	if _, err := c.SelfClient(n).StartVM(context.Background(),
		&pb.StartVMRequest{Name: name}); err != nil {
		t.Fatalf("StartVM %s: %v", name, err)
	}
}

// vmNICMAC is the MAC of a VM's first NIC — what the stubbed ARP lookup is keyed
// on, read from the rows rather than guessed.
func vmNICMAC(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	ifaces, err := corrosion.GetVMInterfaces(context.Background(), n.DB, vmName)
	if err != nil || len(ifaces) == 0 {
		t.Fatalf("GetVMInterfaces(%s): %v (%d rows)", vmName, err, len(ifaces))
	}
	if ifaces[0].MAC == "" {
		t.Fatalf("VM %s has no MAC — a discovery keyed on it would never fire", vmName)
	}
	return ifaces[0].MAC
}

// stubDiscovery makes the node's address discovery answer `ip` for exactly one
// MAC, and nothing for every other. Scoped to one MAC deliberately: a stub that
// answered for all of them would also address the OTHER VMs in the scenario and
// the assertions could not tell which write came from where.
func stubDiscovery(n *Node, mac, ip string) {
	n.Server.SetNICIPDiscovery(func(m string) string {
		if strings.EqualFold(m, mac) {
			return ip
		}
		return ""
	})
}

// dnsValueFor is the address the auto DNS record for a VM points at, or "" when
// there is no live record.
//
// Its own query, because the DNS record is a SECOND assertion of the same
// address to a second reader (the daemon's resolver), and the two must not
// disagree: a name published for an address the NIC row was not allowed to
// carry is the drift the gate exists to prevent, arriving through a side door.
func dnsValueFor(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	name := dns.VMRecordName(vmName, "", discoveryDNSDomain)
	rows, err := n.DB.Query(context.Background(),
		`SELECT value FROM dns_records WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		t.Fatalf("read dns record %q: %v", name, err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("value")
}

// aStoppedGuestOnABoundNetwork builds the precondition both scenarios need, out
// of real RPCs only: a RUNNING VM on a BOUND network whose NIC carries no
// recorded address.
//
// It cannot be built any other way. A VM created on a bound network claims an
// address, so the only route to an unrecorded one is to create it while the
// network is unbound and bind afterwards — which the bind permits only for a
// STOPPED VM. Starting it again afterwards is what makes its guest live.
//
// It returns the VM's MAC.
func aStoppedGuestOnABoundNetwork(t *testing.T, c *Cluster, n *Node) string {
	t.Helper()

	n.Server.SetDNSDomain(discoveryDNSDomain)
	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMOnNetwork(t, c, n, "cold-guest", adoptNetName)
	if got := vmNICIP(t, n, "cold-guest"); got != "" {
		t.Fatalf("precondition: a VM on an UNBOUND network must get no address, got %q", got)
	}
	mac := vmNICMAC(t, n, "cold-guest")
	mustStopVM(t, c, n, "cold-guest")

	// The bind itself — and the judgement it encodes: a stopped guest holds no
	// address, so an unrecorded NIC on one does not refuse the bind.
	if err := relink(c, n, t); err != nil {
		t.Fatalf("a bind must proceed over a STOPPED VM whose address is unrecorded: %v", err)
	}
	if b := bindingFor(t, n); b == nil || b.Suspended {
		t.Fatalf("the binding must be live, got %+v", b)
	}

	mustStartVM(t, c, n, "cold-guest")
	if got := vmNICIP(t, n, "cold-guest"); got != "" {
		t.Fatalf("precondition: starting a VM must not address it, got %q — the scenario "+
			"needs a live guest whose address litevirt does not know", got)
	}
	return mac
}

// TestFleetDiscoveryClaimsAnAddressBeforeRecordingIt is the positive half.
//
// A running guest turns out to be using an address inside the bound prefix.
// Recording it is a claim, so after the pass NetBox holds an object for that
// address under that NIC's identity, litevirt holds the lease that makes it
// releasable, and only then does the NIC row carry it.
func TestFleetDiscoveryClaimsAnAddressBeforeRecordingIt(t *testing.T) {
	nb, c, n := adoptCluster(t)
	m := newSweepMetrics()
	n.Server.SetNetBoxMetrics(m)

	mac := aStoppedGuestOnABoundNetwork(t, c, n)
	stubDiscovery(n, mac, discoveryFreeIP)

	grpcapi.NewIPScanner(n.Server).ScanOnce(context.Background())

	if got := vmNICIP(t, n, "cold-guest"); got != discoveryFreeIP {
		t.Fatalf("NIC address = %q, want %s — an address NetBox granted must be recorded",
			got, discoveryFreeIP)
	}
	// It came from a CLAIM, not from the write going through unchanged: NetBox
	// has to hold the object, under this NIC's identity.
	want := vmNICIdentity(t, n, "cold-guest")
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != want {
		t.Fatalf("identities in NetBox = %v, want [%s]", ids, want)
	}
	if got := nb.Addresses(); len(got) != 1 || got[0] != discoveryFreeIP+"/24" {
		t.Fatalf("NetBox holds %v, want [%s/24]", got, discoveryFreeIP)
	}
	// And the lease, without which a DeleteVM has nothing to release the remote
	// object by.
	lease := leaseFor(t, n, adoptNetName, discoveryFreeIP)
	if lease == nil || lease.NetBoxIPID == 0 || lease.NetBoxPrefix != adoptPrefix {
		t.Fatalf("no live adopted lease for the discovered address, got %+v", lease)
	}
	if lease.VMName != "cold-guest" || lease.OwnerKind != "vm" {
		t.Fatalf("lease owner = %s/%s, want cold-guest/vm", lease.VMName, lease.OwnerKind)
	}
	if got := m.unclaimableDiscoveries(); len(got) != 0 {
		t.Fatalf("a granted discovery must record no refusal, got %v", got)
	}
	// The dependent write: a granted address IS published, so the negative
	// assertion in the refusal scenario cannot pass by DNS never working here.
	if got := dnsValueFor(t, n, "cold-guest"); got != discoveryFreeIP {
		t.Fatalf("DNS record = %q, want %s — a recorded address must be resolvable by name",
			got, discoveryFreeIP)
	}
}

// TestFleetDiscoveryDoesNotRecordAnAddressNetBoxWillNotGrant is the point of
// the gate.
//
// The guest comes up on an address NetBox has already given to ANOTHER VM —
// which is exactly what an external DHCP server does when it re-offers a lease
// it remembers. litevirt cannot fix that from here, and the one thing it must
// not do is write the address down as one it holds: the NIC row feeds
// cloud-init, the inventory mirror and every "is this address free" answer.
//
// So nothing is recorded, and the refusal is surfaced on
// litevirt_netbox_unclaimable_discoveries_total with reason=not_ours.
func TestFleetDiscoveryDoesNotRecordAnAddressNetBoxWillNotGrant(t *testing.T) {
	nb, c, n := adoptCluster(t)
	m := newSweepMetrics()
	n.Server.SetNetBoxMetrics(m)

	mac := aStoppedGuestOnABoundNetwork(t, c, n)

	// A second VM claims the fake's first address for real. THIS is what makes
	// the discovery below a collision rather than an ordinary claim.
	mustCreateVMOnNetwork(t, c, n, "newcomer", adoptNetName)
	if got := vmNICIP(t, n, "newcomer"); got != adoptFirstIP {
		t.Fatalf("precondition: the newcomer holds %q, want %s", got, adoptFirstIP)
	}
	newcomerIdentity := vmNICIdentity(t, n, "newcomer")

	// The stopped guest wakes up on the newcomer's address.
	stubDiscovery(n, mac, adoptFirstIP)
	postsBefore := nb.AddressPOSTs()

	grpcapi.NewIPScanner(n.Server).ScanOnce(context.Background())

	if got := vmNICIP(t, n, "cold-guest"); got != "" {
		t.Fatalf("DUPLICATE ADDRESS RECORDED: the NIC row now carries %q, which NetBox "+
			"holds for another VM — a discovered address must not be recorded unless "+
			"NetBox grants it", got)
	}
	if got := leaseFor(t, n, adoptNetName, adoptFirstIP); got == nil || got.VMName != "newcomer" {
		t.Fatalf("the lease for %s must still belong to the newcomer, got %+v", adoptFirstIP, got)
	}
	// NetBox is unchanged: still one object, still the newcomer's identity. The
	// claim was attempted (that is how the refusal is learned — enforce_unique
	// answers it), so what must hold is that it created nothing.
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != newcomerIdentity {
		t.Fatalf("identities in NetBox = %v, want only the newcomer's [%s]", ids, newcomerIdentity)
	}
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("NetBox holds %v, want only [%s/24]", got, adoptFirstIP)
	}
	if got := leaseCount(t, n, adoptNetName); got != 1 {
		t.Fatalf("%d live leases on the network, want 1 (the newcomer's)", got)
	}
	// The refusal is the only signal there is — no error reaches any caller and
	// the row simply stays empty — so it has to be counted, and under the reason
	// that says "something else is using this address".
	if got := m.unclaimableDiscoveries(); len(got) != 1 || got[0] != "not_ours" {
		t.Fatalf("unclaimable-discovery reasons = %v, want [not_ours]", got)
	}
	// It really did reach NetBox rather than being refused locally on a guess:
	// a local-only refusal would be a second, weaker gate that could not tell a
	// free address from a taken one.
	if got := nb.AddressPOSTs() - postsBefore; got != 1 {
		t.Fatalf("the pass made %d address POSTs, want 1 — the refusal must come from "+
			"NetBox's own answer", got)
	}
	// And no DNS record either. Publishing the name would assert the same
	// address to the resolver that the NIC row was refused, which is the drift
	// the gate exists to prevent reaching a second reader.
	if got := dnsValueFor(t, n, "cold-guest"); got != "" {
		t.Fatalf("a refused address was published in DNS as %q", got)
	}
}

// TestFleetListVMsDoesNotRecordADiscoveredAddressOnABoundNetwork pins the
// read-path half of the gate.
//
// ListVMs discovers and PERSISTED, which made a read RPC a writer of exactly
// the row SetVMIP refuses to write. It now records nothing on a bound network
// and reaches no NetBox address endpoint at all — a list must not POST once per
// undiscovered NIC — while still REPORTING the address, because the guest is
// using it and hiding it would help nobody.
func TestFleetListVMsDoesNotRecordADiscoveredAddressOnABoundNetwork(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mac := aStoppedGuestOnABoundNetwork(t, c, n)
	stubDiscovery(n, mac, discoveryFreeIP)
	requestsBefore := nb.AddressRequests()

	resp, err := c.SelfClient(n).ListVMs(context.Background(), &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}

	// REPORTED.
	var reported string
	for _, vm := range resp.Vms {
		if vm.Name != "cold-guest" {
			continue
		}
		for _, iface := range vm.Interfaces {
			if iface.NetworkName == adoptNetName {
				reported = iface.Ip
			}
		}
	}
	if reported != discoveryFreeIP {
		t.Fatalf("ListVMs reported address %q, want %s — the guest is using it and the "+
			"list must still show it", reported, discoveryFreeIP)
	}
	// NOT recorded, and NetBox not touched.
	if got := vmNICIP(t, n, "cold-guest"); got != "" {
		t.Fatalf("a read RPC recorded %q on a bound network; the claim is the IP scanner's "+
			"to make", got)
	}
	if got := nb.AddressRequests() - requestsBefore; got != 0 {
		t.Fatalf("ListVMs made %d ipam address requests, want 0", got)
	}
	if got := leaseCount(t, n, adoptNetName); got != 0 {
		t.Fatalf("a read RPC leased %d addresses, want 0", got)
	}
}

// TestFleetDiscoveryStillRecordsOnAnUnboundNetwork is the behaviour-preservation
// control, and the one that keeps the gate from being a regression.
//
// Discovery on an unbound network is the overwhelmingly common case — it is how
// every DHCP guest on every existing litevirt network gets its address into the
// inventory — and it must be untouched: recorded, with no NetBox involvement.
func TestFleetDiscoveryStillRecordsOnAnUnboundNetwork(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMOnNetwork(t, c, n, "dhcp-guest", adoptNetName)
	mac := vmNICMAC(t, n, "dhcp-guest")
	stubDiscovery(n, mac, discoveryFreeIP)

	grpcapi.NewIPScanner(n.Server).ScanOnce(context.Background())

	if got := vmNICIP(t, n, "dhcp-guest"); got != discoveryFreeIP {
		t.Fatalf("NIC address = %q, want %s — discovery on an UNBOUND network must record "+
			"as it always has", got, discoveryFreeIP)
	}
	if got := nb.AddressRequests(); got != 0 {
		t.Fatalf("an unbound discovery made %d ipam address requests, want 0", got)
	}
	if got := leaseCount(t, n, adoptNetName); got != 0 {
		t.Fatalf("an unbound discovery wrote %d leases, want 0 — VMs allocate nothing there", got)
	}
}

// TestFleetUnclaimableDiscoverySurfacesInHealth is the operator surface the
// refusal did not have.
//
// This is the most serious NetBox finding there is — reason=not_ours means
// NetBox holds that address for something else, so two things are using one
// address — and its only two signals were an ERROR log and a counter. Both are
// opt-in: the log has to be watched, the counter has to be scraped. `lv health`
// is what somebody actually reads during an incident, and it said nothing.
//
// The whole cycle: refuse, report, then clear once the address is claimable.
func TestFleetUnclaimableDiscoverySurfacesInHealth(t *testing.T) {
	_, c, n := adoptCluster(t)
	ctx := context.Background()

	mac := aStoppedGuestOnABoundNetwork(t, c, n)

	// Another VM holds the fake's first address for real, which is what makes
	// the discovery below a collision rather than an ordinary claim.
	mustCreateVMOnNetwork(t, c, n, "newcomer", adoptNetName)
	if got := vmNICIP(t, n, "newcomer"); got != adoptFirstIP {
		t.Fatalf("precondition: the newcomer holds %q, want %s", got, adoptFirstIP)
	}

	// Nothing yet — the finding must be produced by the refusal, not by the
	// evaluator running at all.
	if err := n.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h, ok := fleetNetBoxCondition(t, n, "netbox_discovery_unclaimable", n.Name); ok && h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a node that has refused nothing must raise nothing, got %+v", h)
	}

	// The stopped guest wakes up on the newcomer's address.
	stubDiscovery(n, mac, adoptFirstIP)
	grpcapi.NewIPScanner(n.Server).ScanOnce(ctx)
	if got := vmNICIP(t, n, "cold-guest"); got != "" {
		t.Fatalf("precondition: the refused address must not be recorded, got %q", got)
	}

	if err := n.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	h, ok := fleetNetBoxCondition(t, n, "netbox_discovery_unclaimable", n.Name)
	if !ok {
		t.Fatal("a guest using an address NetBox will not grant must raise a health condition")
	}
	if h.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("the finding must be live while the collision stands, got %+v", h)
	}
	if h.Severity != corrosion.SeverityWarning {
		t.Fatalf("severity = %q, want warning", h.Severity)
	}
	// The evidence has to name the guest and the address, or the operator has a
	// row and nowhere to go.
	if !strings.Contains(h.Evidence, "cold-guest") || !strings.Contains(h.Evidence, adoptFirstIP) {
		t.Fatalf("the evidence must name the VM and the address, got %q", h.Evidence)
	}
	// …and the reason, because reason=not_ours is the one that means two things
	// are using one address and the others do not.
	if !strings.Contains(h.Evidence, "not_ours") {
		t.Fatalf("the evidence must carry the bounded reason, got %q", h.Evidence)
	}

	// NOW THE COLLISION GOES AWAY: the guest is seen on a free address instead,
	// the claim succeeds, and two clean passes resolve the finding. A finding
	// that could not clear would be worse than none — an operator learns to
	// ignore a row that never goes away.
	stubDiscovery(n, mac, discoveryFreeIP)
	grpcapi.NewIPScanner(n.Server).ScanOnce(ctx)
	if got := vmNICIP(t, n, "cold-guest"); got != discoveryFreeIP {
		t.Fatalf("the claimable address must now be recorded, got %q", got)
	}
	for i := 0; i < 2; i++ {
		if err := n.Server.RevalidateBindingsOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	h, ok = fleetNetBoxCondition(t, n, "netbox_discovery_unclaimable", n.Name)
	if !ok {
		t.Fatal("the row must still exist, resolved")
	}
	if h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("two clean passes must resolve the finding, got %+v", h)
	}
}
