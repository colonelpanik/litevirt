// Fleet helpers for the NetBox external-IPAM scenarios, plus the smoke test that
// proves the harness actually reaches NetBox.
//
// The dangerous failure mode here is a scenario that "passes" against a NetBox
// that was never consulted: the builtin allocator answers, the assertion is
// about an address, and nothing distinguishes the two. Two things guard against
// it — NetBoxFake allocates from a band the builtin allocator never produces,
// and TestFleetNetBoxWiring asserts on the BINDING ROW, which only the NetBox
// path can create.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// latchNetBoxIPAM drives the netbox_ipam_v1 cluster latch on every node.
//
// The config kill-switch is already on everywhere — NewClusterWithNetBox sets it
// alongside the client, because the daemon sets both from the same config block
// and a node with one but not the other is a state production cannot produce.
// What is left is the negotiation: every voting-eligible member must advertise
// the token before any node latches it.
//
// Both halves are asserted. Enforced alone is not enough: a bind demands the
// DURABLE form, so a latch held only in memory — one that would not survive a
// restart — must not read as ready here either.
func latchNetBoxIPAM(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.NetBoxIPAMV1) {
			t.Fatalf("%s: netbox_ipam_v1 failed to latch with the config flag on everywhere", n.Name)
		}
		if !gates[n.Name].DurablyLatched(capabilities.NetBoxIPAMV1) {
			t.Fatalf("%s: netbox_ipam_v1 latched only in memory — a bind requires the durable form", n.Name)
		}
	}
}

// latchNetBoxMirror drives the netbox_mirror_v1 cluster latch on every node.
//
// A SECOND latch, not a rename of the one above, because the two contracts are
// independent: netbox_ipam_v1 says every peer carries the v51 tables and parses
// a prefix binding, and netbox_mirror_v1 says every peer has opted into the
// INVENTORY half (`netbox.mirror_inventory`). A pure-IPAM cluster forms the
// first and never the second, and that is the default shape.
//
// wireNetBox has already set the config flag on every node, for the same reason
// it sets netbox.enabled: the daemon sets both from one config block. What is
// left is the negotiation, which only an Enforced call performs.
//
// Both halves are asserted, as above: the mirror gates on the DURABLE form, so a
// latch held only in memory — one that would not survive a restart mid-rolling-
// upgrade — must not read as ready here either.
func latchNetBoxMirror(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.NetBoxMirrorV1) {
			t.Fatalf("%s: netbox_mirror_v1 failed to latch with mirror_inventory on everywhere", n.Name)
		}
		if !gates[n.Name].DurablyLatched(capabilities.NetBoxMirrorV1) {
			t.Fatalf("%s: netbox_mirror_v1 latched only in memory — the mirror requires the durable form", n.Name)
		}
	}
}

// latchNetBoxBoth drives both NetBox latches, which is what a fixture that
// mirrors needs: the mirror requires netbox_ipam_v1 for its tables AND
// netbox_mirror_v1 for the opt-in.
func latchNetBoxBoth(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	latchNetBoxIPAM(t, c, gates)
	latchNetBoxMirror(t, c, gates)
}

// mustCreateBoundNetwork creates a network on n bound to a NetBox prefix,
// through the real CreateNetwork RPC over the harness's mTLS loopback.
//
// Type "sriov" is deliberate: it is the one network type Provision returns from
// without touching the host (no `ip link`, no sysctl, no dnsmasq), so the
// scenario tests the BINDING, not whether the test process can create bridges
// as an unprivileged user.
//
// "bridge" — the type a NetBox-bound production VLAN really is — was tried and
// does not work here, for reasons no seam on Server can reach: CreateNetwork
// provisions for real (networks.go, provisionAndPersistNetwork →
// network.SafeProvision) and a bridge network with a subnet needs root TWICE,
// at `ip link add … type bridge` and at `sysctl -w net.ipv4.ip_forward=1`
// (NATEnabled defaults to TRUE, and CreateNetwork has no way to set it false).
// Both are inside package network, below the grpcapi seam. It also drags the
// host's REAL routing table into the test via the SafeProvision snapshot.
//
// The type does not weaken what this file proves. What matters for a VM on a
// bound network is that CreateVM preflights the resolved device through
// ensureBridge — and it does that for sriov too, with the PF name (vm.go,
// resolveBridge returns def.PF, which is not "direct:"-prefixed). That is the
// seam wireNetBox stubs, and TestFleetVMCreateOnBoundNetworkIsBridgeStubbed
// mutation-fails without it.
func mustCreateBoundNetwork(t *testing.T, c *Cluster, n *Node, name, subnet string, prefixID int) *pb.NetworkInfo {
	t.Helper()
	ni, err := createBoundNetwork(c, n, name, subnet, prefixID)
	if err != nil {
		t.Fatalf("CreateNetwork(%s, prefix %d) on %s: %v", name, prefixID, n.Name, err)
	}
	return ni
}

// createBoundNetwork is mustCreateBoundNetwork without the fatal, for the
// scenarios whose subject IS the refusal.
func createBoundNetwork(c *Cluster, n *Node, name, subnet string, prefixID int) (*pb.NetworkInfo, error) {
	return c.SelfClient(n).CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name:           name,
		Type:           "sriov",
		Pf:             "ens1f0",
		Subnet:         subnet,
		NetboxPrefixId: int32(prefixID),
	})
}

// TestFleetNetBoxWiring is the end-to-end proof that the harness reaches a real
// NetBox client: fleet bootstrap → netbox.Client built from a token file →
// netbox_ipam_v1 advertised and latched cluster-wide → CreateNetwork over gRPC
// → prefix and VRF validated against the fake → a binding row persisted.
//
// Every link is load-bearing. Delete the client wiring and the bind refuses for
// want of a client; delete the kill-switch and the token never latches; delete
// the latch check and the bind refuses as not durably latched. None of that is
// reachable from a single-package test, which has no cluster to negotiate with.
func TestFleetNetBoxWiring(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)

	b, err := corrosion.GetBindingByPrefix(context.Background(), n.DB, 7)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("a bound create must persist a binding row — nothing reached NetBox")
	}
	if b.Network != "bound" {
		t.Fatalf("binding names network %q, want \"bound\"", b.Network)
	}
	// The CIDR is read back FROM the fake, not echoed from the request, so this
	// pins that the prefix lookup actually happened.
	if b.ObservedCIDR != "10.0.5.0/24" {
		t.Fatalf("binding ObservedCIDR = %q, want the CIDR NetBox reported", b.ObservedCIDR)
	}
	if b.VRFID != 3 {
		t.Fatalf("binding VRFID = %d, want 3 from the fake's prefix", b.VRFID)
	}
	if b.ClusterFingerprint == "" {
		t.Fatal("binding must pin a cluster fingerprint")
	}
}

// TestFleetVMCreateOnBoundNetworkIsBridgeStubbed proves the harness can create a
// VM on a NetBox-bound network at all.
//
// It looks trivial and is not. No fleet scenario had ever attached a VM to a
// network, so nothing had exercised CreateVM's bridge preflight: it resolves the
// network to a host device and calls ensureBridge, which runs
// `ip link add … type bridge` when the device is missing. Unprivileged, that is
// EPERM, and every create on a bound network fails FailedPrecondition before it
// reaches any addressing logic — a property of the test process, not of the code
// under test. wireNetBox stubs Server.bridgeEnsure to make the preflight inert.
//
// Deliberately asserts NOTHING about the VM's address. VM-side allocation from a
// bound prefix does not exist yet; today the VM simply gets no address, and an
// assertion here would either be vacuous or would fail for the right reason at
// the wrong time. The single claim is: the bridge path no longer blocks.
func TestFleetVMCreateOnBoundNetworkIsBridgeStubbed(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := NewClusterWithNetBox(t, 1, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)

	n := c.Nodes[0]
	mustCreateBoundNetwork(t, c, n, "bound", "10.0.5.0/24", 7)

	vm, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name: "on-bound", Cpu: 1, MemoryMib: 512,
			Network: []*pb.NetworkAttachment{{Name: "bound"}},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM on a bound network: %v", err)
	}
	if vm.Name != "on-bound" {
		t.Fatalf("created VM is named %q, want \"on-bound\"", vm.Name)
	}
}

// TestFleetNetBoxBindRefusedWithoutTheLatch is the negative control for the
// smoke test above: with the token NOT latched, the same create is refused. It
// is what proves TestFleetNetBoxWiring's latching step is doing something —
// without it, a bind that ignored the latch entirely would pass both.
func TestFleetNetBoxBindRefusedWithoutTheLatch(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	// Two nodes, but only one advertises: the fleet cannot latch.
	c := NewClusterWithNetBox(t, 2, nb)
	c.Nodes[1].Server.SetNetBoxIPAM(false)
	gateAll(t, c)

	_, err := c.SelfClient(c.Nodes[0]).CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: "bound", Type: "sriov", Pf: "ens1f0", NetboxPrefixId: 7,
	})
	if err == nil {
		t.Fatal("a bind must be refused while netbox_ipam_v1 is unlatched")
	}
	b, berr := corrosion.GetBindingByPrefix(context.Background(), c.Nodes[0].DB, 7)
	if berr != nil {
		t.Fatal(berr)
	}
	if b != nil {
		t.Fatalf("a refused bind must claim nothing, got %+v", b)
	}
}

// TestNetBoxFakeRejectsAnUnknownFilter pins the fake's own strictness. A fake
// that ignored an unrecognised query parameter would let a lookup that silently
// loses its scope — the exact bug the scoped identity query exists to prevent —
// pass in the fleet and fail against a real NetBox.
func TestNetBoxFakeRejectsAnUnknownFilter(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	resp, err := http.Get(nb.URL() + "/api/ipam/ip-addresses/?not_a_real_filter=x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown filter status = %d, want 400", resp.StatusCode)
	}
}

// TestNetBoxFakeAllocatesFromTheDistinctiveBand pins the property every
// NetBox-backed assertion in the fleet leans on: the fake never hands out an
// address the builtin allocator would have produced, so an address in the .100s
// can only have come through the NetBox path.
func TestNetBoxFakeAllocatesFromTheDistinctiveBand(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	body := strings.NewReader(`{"custom_fields":{"litevirt_identity":"lv:fp:uuid:aa:bb"}}`)
	resp, err := http.Post(nb.URL()+"/api/ipam/prefixes/7/available-ips/", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var got struct {
		ID      int    `json:"id"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("available-ips must return a single OBJECT, not an array: %v", err)
	}
	if got.Address != "10.0.5.100/24" {
		t.Fatalf("first claim = %q, want 10.0.5.100/24 (the .100+ band the builtin allocator never reaches)", got.Address)
	}
	if want := []string{"lv:fp:uuid:aa:bb"}; !reflect.DeepEqual(nb.Identities(), want) {
		t.Fatalf("Identities() = %v, want %v", nb.Identities(), want)
	}
}

// TestNetBoxFakeDownIsATransportFailure pins that Down models an UNREACHABLE
// server, not one that answered 5xx. The two classify differently in
// netbox.Classify, and only the transport form exercises the "we never learned
// whether it committed" branch.
func TestNetBoxFakeDownIsATransportFailure(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)
	nb.SetDown(true)

	resp, err := http.Get(nb.URL() + "/api/ipam/prefixes/7/")
	if err == nil {
		resp.Body.Close() //nolint:errcheck
		t.Fatalf("a Down fake must fail the CONNECTION, got HTTP %d", resp.StatusCode)
	}
}

// TestNetBoxFakeCommitsThenFailsTheResponse pins the OnClaim contract: the hook
// runs before the commit, and a hook error still leaves the address committed
// while failing the response. That is the only way to reach "NetBox wrote it and
// the caller never learned the address" — the case identity recovery exists for.
func TestNetBoxFakeCommitsThenFailsTheResponse(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)
	nb.SetOnClaim(func(int) error { return errors.New("response lost") })

	body := strings.NewReader(`{"custom_fields":{"litevirt_identity":"lv:fp:uuid:aa:bb"}}`)
	resp, err := http.Post(nb.URL()+"/api/ipam/prefixes/7/available-ips/", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx", resp.StatusCode)
	}
	// The write LANDED despite the failed response — that is the whole point.
	if want := []string{"lv:fp:uuid:aa:bb"}; !reflect.DeepEqual(nb.Identities(), want) {
		t.Fatalf("a failed OnClaim must still commit, Identities() = %v, want %v", nb.Identities(), want)
	}
}
