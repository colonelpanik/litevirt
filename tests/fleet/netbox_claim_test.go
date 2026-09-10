// Fleet scenarios for VM address claims against an external IPAM.
//
// The property that matters most here is a NEGATIVE one: a VM on an UNBOUND
// network must get exactly what it gets today, which is nothing. VMs have never
// allocated — network.AllocateIP had no non-test callers before this work — so
// routing unbound VM NICs through an allocator would newly assign addresses to
// every VM on every existing network and push static cloud-init config to guests
// that currently DHCP. That regression is invisible to a single-package test of
// the allocator, because the allocator would be behaving correctly; only the
// create path can show it.
//
// The positive cases lean on NetBoxFake's distinctive band (.100+, never the
// .2/.3 the builtin allocator produces), so an assertion about an address can
// only pass if the NetBox path actually supplied it.

package fleet

import (
	"context"
	"net"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// createVMOnNetwork creates a one-NIC VM pinned to n, returning the RPC error
// unchanged so refusal scenarios can assert on it.
//
// Placement is pinned deliberately: an unpinned create is free to forward to a
// peer, and a scenario that means "this node refuses" must actually run on this
// node.
func createVMOnNetwork(c *Cluster, n *Node, name, netName string) (*pb.VM, error) {
	return c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      name,
			Cpu:       1,
			MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: n.Name},
			Network:   []*pb.NetworkAttachment{{Name: netName}},
		},
	})
}

func mustCreateVMOnNetwork(t *testing.T, c *Cluster, n *Node, name, netName string) *pb.VM {
	t.Helper()
	vm, err := createVMOnNetwork(c, n, name, netName)
	if err != nil {
		t.Fatalf("CreateVM %s on network %q at %s: %v", name, netName, n.Name, err)
	}
	return vm
}

// vmNICIP is the address persisted on a VM's first NIC — the vm_interfaces row
// CreateVM writes from ifaceRecords.
//
// That row is the single source of the guest's addressing: the static
// cloud-init network-config loop reads ifaceRecords[i].IP for any NIC without an
// explicit request, so an empty value here is also what proves no static
// network-config was generated.
func vmNICIP(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	ifaces, err := corrosion.GetVMInterfaces(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("GetVMInterfaces(%s): %v", vmName, err)
	}
	if len(ifaces) == 0 {
		t.Fatalf("VM %s has no interface rows — an address assertion would be vacuous", vmName)
	}
	return ifaces[0].IP
}

// vmNICRowIP is the same address as seen through the v42 vm_nics read model.
// Both rows are written from the same loop and must agree; asserting only one
// would let a claim reach cloud-init while the typed hardware model still said
// the NIC had no address.
func vmNICRowIP(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs(%s): %v", vmName, err)
	}
	if len(nics) == 0 {
		t.Fatalf("VM %s has no vm_nics rows", vmName)
	}
	return nics[0].IP
}

// leaseCount is how many LIVE ip_allocations rows exist for a network.
func leaseCount(t *testing.T, n *Node, network string) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT COUNT(*) FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`, network)
	if err != nil {
		t.Fatalf("count leases on %q: %v", network, err)
	}
	if len(rows) == 0 || len(rows[0].Values) == 0 {
		t.Fatalf("count query returned no rows")
	}
	switch v := rows[0].Values[0].(type) {
	case int64:
		return int(v)
	case float64:
		return int(v)
	case int:
		return v
	default:
		t.Fatalf("unexpected count type %T", v)
		return 0
	}
}

// seedClusterRow gives every node the `cluster` row a real cluster always has.
//
// It is what corrosion.ClusterFingerprint reads, and it matters here for a
// mutation-testing reason: without it, a VM create that wrongly reached ANY
// allocation path would fail on the missing fingerprint rather than on the
// address it produced, and the guard below would go red for the wrong reason.
// (NetBox clusters get this from the harness; a plain one does not.)
func seedClusterRow(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := n.DB.Execute(context.Background(),
			`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
			 VALUES ('default', 'fleet', 'fleet.local', 'fleet-ca-cert', ?, ?)
			 ON CONFLICT(id) DO NOTHING`,
			n.DB.NowWall(), n.DB.NowWall()); err != nil {
			t.Fatalf("seed cluster row on %s: %v", n.Name, err)
		}
	}
}

// TestVMOnUnboundNetworkGetsNoAllocation is the behaviour-preservation guard.
//
// VMs do NOT allocate today, so an unbound network must stay exactly as it was:
// no address on either NIC row, no ip_allocations lease, and therefore no static
// cloud-init network-config (which is derived from the interface row's IP).
//
// The cluster has no NetBox client at all, so both ways of getting this wrong
// are caught: handing VMs the builtin allocator would produce 10.77.0.2, and
// handing them the NetBox allocator would refuse the create outright.
func TestVMOnUnboundNetworkGetsNoAllocation(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	// CreateVM preflights the resolved bridge with `ip link add`, which is EPERM
	// for an unprivileged test process. Stub the seam only — everything the
	// scenario asserts on is above it.
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)

	mustCreateVMOnNetwork(t, c, n, "vm-1", ctNetName)

	if ip := vmNICIP(t, n, "vm-1"); ip != "" {
		t.Fatalf("VM on an unbound network must get no address, got %q", ip)
	}
	if ip := vmNICRowIP(t, n, "vm-1"); ip != "" {
		t.Fatalf("vm_nics row carries %q — the NIC must have no address on an unbound network", ip)
	}
	if got := leaseCount(t, n, ctNetName); got != 0 {
		t.Fatalf("VM on an unbound network must write no ip_allocations row, got %d", got)
	}
}

// TestVMOnBoundNetworkClaimsFromNetBox is the positive case.
//
// 10.0.5.100 is the fake's first address and one the builtin allocator can never
// produce (it starts at .2), so this assertion cannot be satisfied by anything
// but a real claim through NetBox.
func TestVMOnBoundNetworkClaimsFromNetBox(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)

	mustCreateVMOnNetwork(t, c, n, "vm-1", "bound")

	if ip := vmNICIP(t, n, "vm-1"); ip != "10.0.5.100" {
		t.Fatalf("VM IP = %q, want 10.0.5.100 from NetBox", ip)
	}
	if ip := vmNICRowIP(t, n, "vm-1"); ip != "10.0.5.100" {
		t.Fatalf("vm_nics IP = %q, want 10.0.5.100 — both NIC rows must carry the claim", ip)
	}
	if got := leaseCount(t, n, "bound"); got != 1 {
		t.Fatalf("want exactly one ip_allocations lease for the claim, got %d", got)
	}
	if ids := nb.Identities(); len(ids) != 1 {
		t.Fatalf("want exactly one identity recorded in NetBox, got %v", ids)
	}
}

// TestContainerOnBoundNetworkRefused pins that containers are refused on a bound
// network rather than quietly allocating around the external IPAM.
//
// The error TEXT is asserted, not merely its presence. A bound network in this
// harness is type sriov (mustCreateBoundNetwork explains why), and containers
// already refuse sriov for an unrelated reason — so "an error came back" would
// hold with the binding refusal deleted. The message is what distinguishes them.
func TestContainerOnBoundNetworkRefused(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)

	_, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: "ct-1", Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "bound"}},
	})
	if err == nil {
		t.Fatal("a container on a bound network must be refused")
	}
	if !strings.Contains(err.Error(), "bound networks") {
		t.Fatalf("refusal must name the binding as the reason, got: %v", err)
	}
	if got := leaseCount(t, n, "bound"); got != 0 {
		t.Fatalf("a refused container must lease nothing, got %d rows", got)
	}
}

// TestBoundCreateRefusedWhileNetBoxDown pins that there is NO local fallback.
//
// Both nodes must refuse. A node that quietly fell back to the builtin allocator
// while NetBox was unreachable would let two nodes pick the same address out of
// a prefix whose authority cannot see either of them.
func TestBoundCreateRefusedWhileNetBoxDown(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	// SharedCRDT so the binding written on node 0 is visible to node 1 without
	// driving anti-entropy; the scenario is about the claim path, not replication.
	c := New(t, Options{Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true})
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	mustCreateBoundNetwork(t, c, c.Nodes[0], "bound", "10.0.5.0/24", 7)

	nb.SetDown(true)
	if _, err := createVMOnNetwork(c, c.Nodes[0], "vm-a", "bound"); err == nil {
		t.Fatal("node 0 must refuse while NetBox is down")
	}
	if _, err := createVMOnNetwork(c, c.Nodes[1], "vm-b", "bound"); err == nil {
		t.Fatal("node 1 must refuse while NetBox is down")
	}
	for _, n := range c.Nodes {
		if got := leaseCount(t, n, "bound"); got != 0 {
			t.Fatalf("%s: a refused create must write no lease, got %d", n.Name, got)
		}
	}
}

// TestBoundCreateOnTwoNodesGetsDistinctAddresses pins that two daemons claiming
// from ONE prefix never collide — the property a per-node builtin allocator
// cannot provide across an address space NetBox also hands out from.
func TestBoundCreateOnTwoNodesGetsDistinctAddresses(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := New(t, Options{Nodes: 2, NetBoxURL: nb.URL(), SharedCRDT: true})
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	mustCreateBoundNetwork(t, c, c.Nodes[0], "bound", "10.0.5.0/24", 7)

	mustCreateVMOnNetwork(t, c, c.Nodes[0], "vm-a", "bound")
	mustCreateVMOnNetwork(t, c, c.Nodes[1], "vm-b", "bound")

	a := vmNICIP(t, c.Nodes[0], "vm-a")
	b := vmNICIP(t, c.Nodes[1], "vm-b")
	if a == b {
		t.Fatalf("two VMs on one prefix share address %q", a)
	}
	for name, ip := range map[string]string{"vm-a": a, "vm-b": b} {
		// Parse, do not prefix-match: "10.0.5.1" also admits .1 and .10-.19,
		// which the builtin allocator hands out, so the assertion would still
		// pass with NetBox out of the picture entirely.
		v4 := net.ParseIP(ip).To4()
		if v4 == nil || v4[3] < 100 {
			t.Fatalf("%s got %q, which is not from the NetBox band (.100+)", name, ip)
		}
	}
	if got := leaseCount(t, c.Nodes[0], "bound"); got != 2 {
		t.Fatalf("want two leases across the fleet, got %d", got)
	}
	if ids := nb.Identities(); len(ids) != 2 {
		t.Fatalf("want two identities recorded in NetBox, got %v", ids)
	}
}
