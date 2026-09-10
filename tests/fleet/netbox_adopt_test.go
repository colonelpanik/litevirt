// Fleet scenarios for BIND-TIME ADOPTION: teaching NetBox about the addresses
// litevirt's own VMs already hold inside a prefix, as part of binding it.
//
// The gap these close is a duplicate-address collision, and it is reachable by
// the most ordinary path there is — an operator links a subnet that already has
// VMs on it. NetBox's `/available-ips/` band means "no ip_address object
// exists", so an address a guest holds that NetBox has never heard of is an
// address NetBox will hand to the next VM created on that network.
//
// EVERY scenario here places the pre-existing address at 10.0.5.100 — the FIRST
// address NetBoxFake hands out. That is not incidental and it is what keeps the
// collision test non-vacuous: the fake allocates from a .100+ band and skips
// addresses it already holds, so a pre-existing guest parked anywhere else
// (10.0.5.50, say) would never be offered to anybody and the assertion would
// pass with the whole adoption loop deleted.
//
// The precondition is built entirely from real RPCs. A VM's existing address
// lives on its NIC rows — `vm_interfaces.ip` / `vm_nics.ip`, written from an
// explicit `Ip` on the attachment, or discovered from DHCP by the IP scanner —
// and NOT in `ip_allocations`, which on an unbound network only containers ever
// write. So the sequence is: create the network unbound, create a VM holding an
// address on it, delete the network record, and re-create it BOUND. The VM's NIC
// rows survive that (they name the network by name), which is exactly the state
// a relinked subnet is in.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/netbox"
)

// errRefusedByNetBox is the definite refusal the partial-adoption scenario
// makes NetBox return for one address: the object is NOT created, so there is
// nothing for a recovery lookup to find and the adoption is genuinely left
// partial.
var errRefusedByNetBox = errors.New("netbox refused this address")

const (
	adoptNetName = "relinked"
	adoptSubnet  = "10.0.5.0/24"
	adoptPrefix  = 7
	adoptVRF     = 3
	// adoptFirstIP is the fake's FIRST available address. A pre-existing guest
	// has to sit exactly here or the collision assertion is vacuous — see the
	// file comment.
	adoptFirstIP  = "10.0.5.100"
	adoptSecondIP = "10.0.5.101"
	adoptThirdIP  = "10.0.5.102"
)

// adoptCluster is the one-node NetBox cluster every scenario in this file runs
// on, with the prefix registered and netbox_ipam_v1 latched.
func adoptCluster(t *testing.T) (*NetBoxFake, *Cluster, *Node) {
	t.Helper()
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	return nb, c, c.Nodes[0]
}

// mustDeleteNetwork removes the network record, leaving the NIC rows of every
// VM on it untouched. Force, because the VMs are still attached — which is the
// whole point of the scenario.
func mustDeleteNetwork(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	if _, err := c.SelfClient(n).DeleteNetwork(context.Background(),
		&pb.DeleteNetworkRequest{Name: name, Force: true}); err != nil {
		t.Fatalf("DeleteNetwork(%s) on %s: %v", name, n.Name, err)
	}
}

// mustCreateVMHoldingIP creates a VM whose NIC carries an explicit address. On
// an UNBOUND network nothing is claimed and no lease is written — the address
// lands on the NIC rows only, which is precisely the state of a guest that was
// addressed by DHCP or by hand before anybody thought about NetBox.
func mustCreateVMHoldingIP(t *testing.T, c *Cluster, n *Node, name, netName, ip string) *pb.VM {
	t.Helper()
	vm, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: name, Cpu: 1, MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: n.Name},
			Network:   []*pb.NetworkAttachment{{Name: netName, Ip: ip}},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM %s holding %s on %q: %v", name, ip, netName, err)
	}
	if got := vmNICIP(t, n, name); got != ip {
		t.Fatalf("precondition: VM %s NIC holds %q, want %q — the scenario needs a "+
			"guest that already holds this address", name, got, ip)
	}
	if got := leaseCount(t, n, netName); got != 0 {
		t.Fatalf("precondition: an unbound network must lease nothing, got %d rows — "+
			"the whole gap is that this address is invisible to NetBox", got)
	}
	return vm
}

// relink is the operator's action under test: drop the network record and
// re-create it bound to the NetBox prefix.
func relink(c *Cluster, n *Node, t *testing.T) error {
	t.Helper()
	mustDeleteNetwork(t, c, n, adoptNetName)
	_, err := createBoundNetwork(c, n, adoptNetName, adoptSubnet, adoptPrefix)
	return err
}

// vmNICIdentity is the NetBox identity ONE VM's first NIC must be adopted
// under: the cluster fingerprint, the VM's incarnation uuid, and the NIC's MAC.
// Built here the same way the claim path builds it, from rows rather than from
// the assertion's own guess.
func vmNICIdentity(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	ctx := context.Background()
	fp, err := corrosion.ClusterFingerprint(ctx, n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, n.DB, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): %v", vmName, err)
	}
	uuid := vmSpecUUIDForTest(t, vm.Spec)
	nics, err := corrosion.MergedVMNICs(ctx, n.DB, vmName)
	if err != nil || len(nics) == 0 {
		t.Fatalf("MergedVMNICs(%s): %v (%d rows)", vmName, err, len(nics))
	}
	return netbox.Identity(fp, uuid, nics[0].MAC)
}

// vmSpecUUIDForTest pulls the incarnation uuid out of a stored spec.
func vmSpecUUIDForTest(t *testing.T, spec string) string {
	t.Helper()
	var sp struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(spec), &sp); err != nil {
		t.Fatalf("parse VM spec: %v", err)
	}
	if sp.UUID == "" {
		t.Fatal("VM spec carries no uuid — an identity built from it would name nothing")
	}
	return sp.UUID
}

// leaseFor reads the LIVE ip_allocations row for one address, or nil.
//
// Deliberately its OWN query rather than a call to corrosion.ListLeasesByNetwork.
// That reader's `deleted_at IS NULL` predicate is itself under test — a
// tombstoned lease read as live would silently suppress an adoption — and a
// helper that shared the predicate would move the failure onto its own
// precondition instead of onto the behaviour, which is the shape that lets a
// mutation look "caught" while proving nothing about the production path.
func leaseFor(t *testing.T, n *Node, network, ip string) *corrosion.LeaseRecord {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT vm_name, owner_kind,
		        COALESCE(netbox_ip_id, 0) AS netbox_ip_id,
		        COALESCE(netbox_prefix_id, 0) AS netbox_prefix_id
		 FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`, network, ip)
	if err != nil {
		t.Fatalf("read lease %s on %q: %v", ip, network, err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &corrosion.LeaseRecord{
		Network:      network,
		IP:           ip,
		VMName:       rows[0].String("vm_name"),
		OwnerKind:    rows[0].String("owner_kind"),
		NetBoxIPID:   rows[0].Int("netbox_ip_id"),
		NetBoxPrefix: rows[0].Int("netbox_prefix_id"),
	}
}

// bindingFor reads the binding row for the adoption prefix.
func bindingFor(t *testing.T, n *Node) *corrosion.BindingRecord {
	t.Helper()
	b, err := corrosion.GetBindingByPrefix(context.Background(), n.DB, adoptPrefix)
	if err != nil {
		t.Fatalf("GetBindingByPrefix: %v", err)
	}
	return b
}

// TestFleetBindAdoptsAnExistingVMAddress is the positive case: the address a
// guest already holds becomes an ip_address object in NetBox carrying that
// NIC's identity, the lease that makes it releasable is written, and the
// binding ends up LIVE.
func TestFleetBindAdoptsAnExistingVMAddress(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)
	want := vmNICIdentity(t, n, "incumbent")

	if err := relink(c, n, t); err != nil {
		t.Fatalf("re-linking a subnet that already has a VM on it must succeed: %v", err)
	}

	// NetBox now knows the address, under THIS NIC's identity — not under a
	// blank one, which would be unreclaimable, and not under a made-up one.
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("NetBox holds %v, want exactly [%s/24] — the address a guest "+
			"already holds must be adopted", got, adoptFirstIP)
	}
	ids := nb.Identities()
	if len(ids) != 1 || ids[0] != want {
		t.Fatalf("adopted identity = %v, want [%s]", ids, want)
	}

	// The lease is what makes it releasable: without it a DeleteVM has nothing
	// to release the remote object by, and the orphan sweep is the only way back.
	lease := leaseFor(t, n, adoptNetName, adoptFirstIP)
	if lease == nil {
		t.Fatalf("no live lease for %s — an adopted address must be leased locally", adoptFirstIP)
	}
	if lease.NetBoxIPID == 0 {
		t.Fatal("the adopted lease records no netbox_ip_id")
	}
	if lease.NetBoxPrefix != adoptPrefix {
		t.Fatalf("lease netbox_prefix_id = %d, want %d", lease.NetBoxPrefix, adoptPrefix)
	}
	if lease.VMName != "incumbent" || lease.OwnerKind != "vm" {
		t.Fatalf("lease owner = %s/%s, want incumbent/vm", lease.VMName, lease.OwnerKind)
	}

	// And the binding is LIVE, because every address adopted.
	b := bindingFor(t, n)
	if b == nil {
		t.Fatal("no binding row")
	}
	if b.Suspended {
		t.Fatalf("a fully-adopted bind must not stay suspended, reason: %q", b.SuspendReason)
	}
}

// TestFleetBoundNetworkDoesNotHandOutAnAdoptedAddress is the point of the whole
// task: after the bind, NetBox must not offer the incumbent's address to the
// next VM created on that network.
//
// With the adoption loop removed this fails for real — NetBox has never heard
// of 10.0.5.100, so `/available-ips/` offers it and two guests hold it.
func TestFleetBoundNetworkDoesNotHandOutAnAdoptedAddress(t *testing.T) {
	_, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)
	if err := relink(c, n, t); err != nil {
		t.Fatalf("relink: %v", err)
	}

	mustCreateVMOnNetwork(t, c, n, "newcomer", adoptNetName)

	got := vmNICIP(t, n, "newcomer")
	if got == adoptFirstIP {
		t.Fatalf("DUPLICATE ADDRESS: the new VM was handed %s, which the incumbent "+
			"already holds — the bind never taught NetBox about it", got)
	}
	// Positive half, so "it got nothing" cannot pass: the address must still
	// have come from NetBox's band, i.e. the binding really is serving claims.
	if got != adoptSecondIP {
		t.Fatalf("new VM address = %q, want %s (the next free address in NetBox's band)",
			got, adoptSecondIP)
	}
}

// TestFleetBindAdoptionIsIdempotent: re-running the bind over addresses that
// are already adopted must change nothing and POST nothing.
//
// Re-run through the same operator action (relink again). The lease survives a
// network delete carrying its netbox_ip_id, and that recorded id is what makes
// the second pass a no-op.
func TestFleetBindAdoptionIsIdempotent(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)
	if err := relink(c, n, t); err != nil {
		t.Fatalf("first relink: %v", err)
	}
	postsAfterFirst := nb.AddressPOSTs()
	if postsAfterFirst != 1 {
		t.Fatalf("first bind POSTed %d addresses, want 1", postsAfterFirst)
	}
	idBefore := leaseFor(t, n, adoptNetName, adoptFirstIP).NetBoxIPID

	if err := relink(c, n, t); err != nil {
		t.Fatalf("second relink over an already-adopted address must succeed: %v", err)
	}

	if got := nb.AddressPOSTs(); got != postsAfterFirst {
		t.Fatalf("a re-run POSTed %d addresses in total, want %d — an already-adopted "+
			"address must be skipped, not re-claimed", got, postsAfterFirst)
	}
	lease := leaseFor(t, n, adoptNetName, adoptFirstIP)
	if lease == nil || lease.NetBoxIPID != idBefore {
		t.Fatalf("re-run changed the lease's object id to %v, want %d unchanged", lease, idBefore)
	}
	if b := bindingFor(t, n); b == nil || b.Suspended {
		t.Fatalf("a re-run with nothing to do must leave the binding live, got %+v", b)
	}
}

// TestFleetBindRefusesAForeignIdentityAndAdoptsNothingAfterIt: an address in the
// prefix that NetBox already holds under ANOTHER installation's identity must
// refuse the bind. Taking it would be seizing a second cluster's object.
//
// It also pins the ORDER guarantee: adoption runs lowest address first, so the
// refusal stops the pass and the address BEHIND the foreign one is left alone
// rather than adopted into a binding that will never go live.
func TestFleetBindRefusesAForeignIdentityAndAdoptsNothingAfterIt(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)
	mustCreateVMHoldingIP(t, c, n, "second", adoptNetName, adoptSecondIP)

	// Another installation's object, sitting on the incumbent's address.
	foreign := "lv:ffffffffffffffff:11111111-1111-1111-1111-111111111111:aa:bb:cc:dd:ee:ff"
	nb.SeedIP(adoptFirstIP+"/24", adoptVRF, foreign, time.Now().UTC())

	err := relink(c, n, t)
	if err == nil {
		t.Fatal("a bind must refuse an address held under a foreign identity")
	}
	if !strings.Contains(err.Error(), adoptFirstIP) {
		t.Fatalf("refusal must name the address, got: %v", err)
	}
	if !strings.Contains(err.Error(), foreign) {
		t.Fatalf("refusal must name the foreign identity, got: %v", err)
	}

	// The binding stays SUSPENDED — the durable, observable record that
	// adoption is owed — and serves no claim while it does.
	b := bindingFor(t, n)
	if b == nil {
		t.Fatal("the binding row must survive a failed adoption; it is what records that adoption is owed")
	}
	if !b.Suspended {
		t.Fatal("a bind whose adoption refused must leave the binding SUSPENDED")
	}

	// Nothing was adopted — not the refused address and not the one BEHIND it.
	//
	// Asserted on the OBJECT SET and the leases, not on the POST count: adoption
	// reuses the ordinary explicit-claim path, which POSTs first and lets
	// NetBox's own enforce_unique refuse a duplicate. That attempt creates
	// nothing, so "no POST was issued" would be the wrong property to pin — what
	// matters is that NetBox holds nothing new and litevirt leased nothing.
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("NetBox holds %v, want only the pre-existing foreign object at %s/24",
			got, adoptFirstIP)
	}
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != foreign {
		t.Fatalf("identities in NetBox = %v, want only the foreign one", ids)
	}
	if got := leaseCount(t, n, adoptNetName); got != 0 {
		t.Fatalf("a refused adoption leased %d addresses, want 0 — including the one "+
			"sorted BEHIND the refusal", got)
	}

	// And a resume cannot paper over it: the foreign object still stands.
	if _, rerr := c.SelfClient(n).ResumeBinding(context.Background(),
		&pb.ResumeBindingRequest{Network: adoptNetName}); rerr == nil {
		t.Fatal("resume must refuse while the foreign identity still holds the address")
	}
}

// TestFleetPartialAdoptionStaysSuspendedAndResumeFinishesIt: adoption that got
// partway must leave the binding suspended, and `lv netbox resume` must finish
// exactly the work the failed pass left.
//
// This is the contract that makes a half-adopted bind safe rather than merely
// unlucky: while the binding is suspended no claim is served, so the un-adopted
// remainder cannot collide with anything.
func TestFleetPartialAdoptionStaysSuspendedAndResumeFinishesIt(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)
	mustCreateVMHoldingIP(t, c, n, "second", adoptNetName, adoptSecondIP)

	// NetBox refuses the SECOND address only, without committing it.
	nb.SetOnClaimSpecific(func(address string) error {
		if strings.HasPrefix(address, adoptSecondIP+"/") {
			return errRefusedByNetBox
		}
		return nil
	})

	err := relink(c, n, t)
	if err == nil {
		t.Fatal("a bind whose adoption cannot finish must not report success")
	}
	if !strings.Contains(err.Error(), adoptNetName) {
		t.Fatalf("the failure must name the network so the operator can resume it, got: %v", err)
	}
	if !strings.Contains(err.Error(), "resume") {
		t.Fatalf("the failure must name the recovery path (`lv netbox resume`), got: %v", err)
	}

	b := bindingFor(t, n)
	if b == nil || !b.Suspended {
		t.Fatalf("a partial adoption must leave the binding suspended, got %+v", b)
	}
	// The first address DID adopt — that is what makes this partial rather than
	// a clean refusal, and what a re-run must not redo.
	if lease := leaseFor(t, n, adoptNetName, adoptFirstIP); lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("the first address should have adopted before the failure, got %+v", lease)
	}
	if lease := leaseFor(t, n, adoptNetName, adoptSecondIP); lease != nil {
		t.Fatalf("the refused address must not be leased, got %+v", lease)
	}
	// A suspended binding serves no claim, so nothing can take the remainder.
	if _, cerr := createVMOnNetwork(c, n, "newcomer", adoptNetName); cerr == nil {
		t.Fatal("a create on a half-adopted (suspended) binding must be refused")
	}

	// And the RE-KEY is not a second door around the gate. It resumes too, its
	// drift predicate finds nothing wrong (the fingerprint pin is current), and
	// without the same adoption gate it would put this binding live over the
	// address it has not recorded yet.
	if _, kerr := c.SelfClient(n).RekeyBinding(context.Background(),
		&pb.RekeyBindingRequest{Network: adoptNetName}); kerr == nil {
		t.Fatal("a re-key must not resume a binding whose existing addresses are not all adopted")
	}
	if b := bindingFor(t, n); b == nil || !b.Suspended {
		t.Fatalf("the binding must still be suspended after the refused re-key, got %+v", b)
	}

	// Repair NetBox and re-run. The resume finishes the remainder.
	nb.SetOnClaimSpecific(nil)
	postsBefore := nb.AddressPOSTs()
	if _, rerr := c.SelfClient(n).ResumeBinding(context.Background(),
		&pb.ResumeBindingRequest{Network: adoptNetName}); rerr != nil {
		t.Fatalf("resume must finish a partial adoption: %v", rerr)
	}
	if got := nb.AddressPOSTs() - postsBefore; got != 1 {
		t.Fatalf("the resume POSTed %d addresses, want exactly the 1 that was left", got)
	}
	if b := bindingFor(t, n); b == nil || b.Suspended {
		t.Fatalf("a completed adoption must resume the binding, got %+v", b)
	}
	for _, ip := range []string{adoptFirstIP, adoptSecondIP} {
		if lease := leaseFor(t, n, adoptNetName, ip); lease == nil || lease.NetBoxIPID == 0 {
			t.Fatalf("address %s is still not adopted after the resume: %+v", ip, lease)
		}
	}
	// And the binding now serves claims again, from beyond both adopted addresses.
	mustCreateVMOnNetwork(t, c, n, "newcomer", adoptNetName)
	if got := vmNICIP(t, n, "newcomer"); got != adoptThirdIP {
		t.Fatalf("post-resume claim = %q, want %s", got, adoptThirdIP)
	}
}

// TestFleetBindDoesNotSkipAnAddressOnAStaleTombstonedLease: a TOMBSTONED lease
// still carries the netbox_ip_id of the object it used to name, and that object
// is long gone. Reading a tombstone as "already adopted" would skip the address
// entirely — and skipping is the collision, because the guest that holds it now
// would be invisible to NetBox for good.
//
// The chain is all real RPCs: claim the address through a bound network, delete
// the VM (which tombstones the lease and releases the object), unlink, re-address
// a NEW guest at the same address by hand, and re-link.
func TestFleetBindDoesNotSkipAnAddressOnAStaleTombstonedLease(t *testing.T) {
	nb, c, n := adoptCluster(t)

	// Round one: a real claim, so the lease is written with a real object id.
	mustCreateBoundNetwork(t, c, n, adoptNetName, adoptSubnet, adoptPrefix)
	mustCreateVMOnNetwork(t, c, n, "first-tenant", adoptNetName)
	if got := vmNICIP(t, n, "first-tenant"); got != adoptFirstIP {
		t.Fatalf("precondition: first tenant holds %q, want %s", got, adoptFirstIP)
	}
	staleID := leaseFor(t, n, adoptNetName, adoptFirstIP).NetBoxIPID
	if staleID == 0 {
		t.Fatal("precondition: the claim must have recorded an object id")
	}

	// Delete it: the lease is tombstoned (retaining netbox_ip_id) and the
	// object released.
	mustDeleteVM(t, n, "first-tenant")
	if lease := leaseFor(t, n, adoptNetName, adoptFirstIP); lease != nil {
		t.Fatalf("precondition: the lease must be tombstoned after a delete, got %+v", lease)
	}
	if len(nb.Addresses()) != 0 {
		t.Fatalf("precondition: the object must be released, NetBox still holds %v", nb.Addresses())
	}

	// Unlink, and let a new guest take the same address outside NetBox's view.
	mustDeleteNetwork(t, c, n, adoptNetName)
	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "second-tenant", adoptNetName, adoptFirstIP)

	if err := relink(c, n, t); err != nil {
		t.Fatalf("relink: %v", err)
	}

	// The address must be adopted AFRESH, under the new guest's identity.
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("NetBox holds %v, want [%s/24] — a tombstoned lease must not be "+
			"mistaken for an adopted one", got, adoptFirstIP)
	}
	want := vmNICIdentity(t, n, "second-tenant")
	if ids := nb.Identities(); len(ids) != 1 || ids[0] != want {
		t.Fatalf("adopted identity = %v, want [%s]", ids, want)
	}
	lease := leaseFor(t, n, adoptNetName, adoptFirstIP)
	if lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("no live adopted lease, got %+v", lease)
	}
	// The lease must name the object that EXISTS NOW, not the number the
	// tombstone was carrying. (Compared against the live object rather than
	// against staleID: the fake hands ids out of a free pool, so a re-created
	// object can legitimately land on the released id — real NetBox would not,
	// and an inequality assertion would be testing the fake.)
	if live := nb.IDForAddress(adoptFirstIP+"/24", adoptVRF); lease.NetBoxIPID != live {
		t.Fatalf("lease names object %d but NetBox holds %d at %s",
			lease.NetBoxIPID, live, adoptFirstIP)
	}
	// Two POSTs in total: the original claim, and the adoption. Reading the
	// tombstone as "already adopted" would skip the second and leave this at 1.
	if got := nb.AddressPOSTs(); got != 2 {
		t.Fatalf("%d addresses POSTed in total, want 2 (the original claim, then the "+
			"adoption) — a tombstoned lease must not suppress an adoption", got)
	}
}

// TestFleetBindWithNothingToAdoptTouchesNoAddresses is the negative control the
// common case depends on: a bind of a network with no existing guests must not
// become a slow path. It must reach the ipam ADDRESS surface zero times — reads
// included, because enumerating a whole prefix on every bind would be exactly
// the cost this control forbids — and it must leave the binding live.
func TestFleetBindWithNothingToAdoptTouchesNoAddresses(t *testing.T) {
	nb, c, n := adoptCluster(t)

	mustCreateBoundNetwork(t, c, n, adoptNetName, adoptSubnet, adoptPrefix)

	if got := nb.AddressRequests(); got != 0 {
		t.Fatalf("a bind with nothing to adopt made %d ipam address requests, want 0", got)
	}
	b := bindingFor(t, n)
	if b == nil || b.Suspended {
		t.Fatalf("a bind with nothing to adopt must be live immediately, got %+v", b)
	}
}

// TestFleetBindRefusesADHCPContainerHoldingAnAddress is the container route,
// end to end and entirely through production paths.
//
// A container on a SUBNET-LESS network is DHCP: the create path takes NO lease
// ("blank IP, no lease"), so the bind's lease-based container refusal never
// fires for one. Its live address arrives later, from the IP scanner, into
// `container_interfaces.ip` — a table bind-time adoption did not read. Nothing
// refused, nothing was adopted, the binding went live over an address a
// container was holding, and NetBox offered it to the next VM.
//
// The address is 10.0.5.100 for the reason the whole file turns on: it is the
// FIRST address the fake hands out, so with the refusal removed the very next
// VM created here gets it.
//
// Every step is real — CreateContainer over gRPC, the IP scanner's own pass
// against the container runtime, then the bind — with only the runtime's IP
// report stubbed, which is what CTFake is for.
func TestFleetBindRefusesADHCPContainerHoldingAnAddress(t *testing.T) {
	_, c, n := adoptCluster(t)
	ctx := context.Background()

	// A SUBNET-LESS bridge network, which is what makes this DHCP. Seeded as a
	// row rather than created through CreateNetwork because a bridge network is
	// provisioned for real (`ip link add`) and the harness is unprivileged —
	// the same reason mustCreateBoundNetwork uses sriov. Containers refuse
	// sriov outright, so this scenario needs the bridge family.
	if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{
		Name: adoptNetName, Type: "bridge",
		Config: `{"type":"bridge","interface":"br-adopt"}`,
	}); err != nil {
		t.Fatalf("seed subnet-less network: %v", err)
	}

	if _, err := c.SelfClient(n).CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: n.Name, Name: "dhcp-ct", Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: adoptNetName}},
	}); err != nil {
		t.Fatalf("CreateContainer on a subnet-less network: %v", err)
	}
	// The precondition that makes this the container_interfaces route and not
	// the lease route: a subnet-less network leases NOTHING.
	if got := leaseCount(t, n, adoptNetName); got != 0 {
		t.Fatalf("precondition: a DHCP container must hold no lease, got %d rows — this "+
			"scenario has to reach the refusal through container_interfaces", got)
	}

	// The container comes up on the address, and the IP scanner records it —
	// the production writer, driven by the production pass. Started first,
	// because the scanner maintains RUNNING containers only.
	if _, err := c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{
		HostName: n.Name, Name: "dhcp-ct",
	}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	n.CT.SetIP("dhcp-ct", adoptFirstIP)
	grpcapi.NewIPScanner(n.Server).ScanOnce(ctx)
	ifaces, err := corrosion.GetContainerInterfaces(ctx, n.DB, n.Name, "dhcp-ct")
	if err != nil || len(ifaces) == 0 {
		t.Fatalf("GetContainerInterfaces: %v (%d rows)", err, len(ifaces))
	}
	if ifaces[0].IP != adoptFirstIP {
		t.Fatalf("precondition: the scanner recorded %q, want %s — without it the "+
			"container holds no address anywhere and there is nothing to detect",
			ifaces[0].IP, adoptFirstIP)
	}

	// Now the operator links the subnet.
	err = relink(c, n, t)
	if err == nil {
		t.Fatalf("the bind SUCCEEDED over a container holding %s — NetBox would hand that "+
			"same address to the next VM created on this network", adoptFirstIP)
	}
	if !strings.Contains(err.Error(), "dhcp-ct") {
		t.Fatalf("the refusal must NAME the container so it can be moved, got: %v", err)
	}
	if !strings.Contains(err.Error(), adoptFirstIP) {
		t.Fatalf("the refusal must name the address, got: %v", err)
	}
	if !strings.Contains(err.Error(), "container") {
		t.Fatalf("the refusal must say containers are the reason, got: %v", err)
	}
	// Decided from local rows alone, so it claimed nothing: no binding row at
	// all, which is what lets the operator move the container and retry.
	if b := bindingFor(t, n); b != nil {
		t.Fatalf("a refusal decided from local rows must claim nothing, got %+v", b)
	}
}
