// Fleet scenarios for NIC HOTPLUG against an external IPAM.
//
// Create and delete claim and release addresses; hotplug is the third door into
// the same address space, and until it goes through the same allocator a NIC
// attached to a bound network gets no address at all while a detached one
// silently strands the one it held. These scenarios pin that the hotplug path
// claims and releases identically to create/delete: same allocator selection,
// same fail-closed refusal when NetBox is unreachable, same per-NIC (never
// per-VM) release, and the same compensation when the live attach fails.
//
// Two structural facts shape every scenario here:
//
//   - Hotplug refuses outright unless operation_protocol_v1 is active, so every
//     test latches it. That refusal is correct behaviour, not a test artifact.
//   - Pre-latch, the legacy vm_interfaces PK is (vm_name, network_name), and
//     attachNICOwner rejects a second NIC on a network the VM already uses. So
//     the multi-NIC scenarios use two bound networks on two prefixes, and their
//     VMs are created NIC-less so every NIC under test comes from a hotplug.

package fleet

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// nicInfo is one NIC as the cluster records it, read back through the
// vm_nics/vm_interfaces overlay rather than from the RPC response — the row is
// what carries the address downstream, so an assertion on it cannot pass
// against a claim that never reached persistence.
type nicInfo struct {
	MAC string
	IP  string
}

// hotplugCluster is boundCluster plus the operation_protocol_v1 latch that every
// NIC attach and detach hard-requires.
//
// The gates are re-wired here because boundCluster does not hand its own back,
// and a fresh health.Checker re-reads the durable activation markers the first
// one wrote — so netbox_ipam_v1 stays latched across the swap.
func hotplugCluster(t *testing.T, nodes int) (*NetBoxFake, *Cluster, map[string]*health.Checker) {
	t.Helper()
	nb, c := boundCluster(t, nodes)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	latchOperationProtocol(t, c, gates)
	return nb, c, gates
}

// mustAddBoundNetwork adds a SECOND NetBox prefix and a litevirt network bound
// to it, for the scenarios that need two independent address spaces.
func mustAddBoundNetwork(t *testing.T, nb *NetBoxFake, c *Cluster, n *Node, name, subnet string, prefixID int) {
	t.Helper()
	nb.AddPrefix(prefixID, subnet, orphanVRF, true)
	mustCreateBoundNetwork(t, c, n, name, subnet, prefixID)
}

// mustCreateNICLessVM creates a running VM with NO interfaces, so every NIC in
// the scenario arrives through hotplug and nothing is pre-claimed.
func mustCreateNICLessVM(t *testing.T, c *Cluster, n *Node, name string) *pb.VM {
	t.Helper()
	vm, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      name,
			Cpu:       1,
			MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: n.Name},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM %s with no NICs on %s: %v", name, n.Name, err)
	}
	return vm
}

// attachNIC hot-attaches one NIC to vmName over the real AttachDevice RPC and
// reports the NIC row it produced, returning the RPC error unchanged so refusal
// scenarios can assert on it.
//
// The new NIC is identified by DIFFING the overlay rather than by trusting a
// MAC the test supplied: the MAC is generated inside the daemon, and it is what
// the NetBox identity is derived from.
func attachNIC(c *Cluster, n *Node, vmName, netName string) (nicInfo, error) {
	ctx := context.Background()
	before, err := corrosion.MergedVMNICs(ctx, n.DB, vmName)
	if err != nil {
		return nicInfo{}, fmt.Errorf("read NICs before attach: %w", err)
	}
	seen := make(map[string]bool, len(before))
	for _, x := range before {
		seen[strings.ToLower(x.MAC)] = true
	}
	if _, err := c.SelfClient(n).AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: vmName,
		Nic:    &pb.NetworkAttachment{Name: netName},
	}); err != nil {
		return nicInfo{}, err
	}
	after, aerr := corrosion.MergedVMNICs(ctx, n.DB, vmName)
	if aerr != nil {
		return nicInfo{}, fmt.Errorf("read NICs after attach: %w", aerr)
	}
	for _, x := range after {
		if !seen[strings.ToLower(x.MAC)] {
			return nicInfo{MAC: x.MAC, IP: x.IP}, nil
		}
	}
	return nicInfo{}, fmt.Errorf("attach of a NIC on %q returned OK but wrote no new NIC row", netName)
}

func mustAttachNIC(t *testing.T, c *Cluster, n *Node, vmName, netName string) nicInfo {
	t.Helper()
	nic, err := attachNIC(c, n, vmName, netName)
	if err != nil {
		t.Fatalf("AttachDevice nic on %q for %s at %s: %v", netName, vmName, n.Name, err)
	}
	return nic
}

// detachNIC hot-detaches the NIC with the given MAC, returning the RPC error
// unchanged.
func detachNIC(c *Cluster, n *Node, vmName, mac string) error {
	_, err := c.SelfClient(n).DetachDevice(context.Background(), &pb.DetachDeviceRequest{
		VmName: vmName, NicMac: mac,
	})
	return err
}

func mustDetachNIC(t *testing.T, c *Cluster, n *Node, vmName, mac string) {
	t.Helper()
	if err := detachNIC(c, n, vmName, mac); err != nil {
		t.Fatalf("DetachDevice nic %s from %s at %s: %v", mac, vmName, n.Name, err)
	}
}

// isNetBoxBand reports whether ip is in NetBoxFake's distinctive .100+ band.
//
// Parsed, never prefix-matched: "10.0.5.1" also admits .1 and .10-.19, which
// the builtin allocator hands out, so a string comparison would still pass with
// NetBox out of the picture entirely.
func isNetBoxBand(ip string) bool {
	v4 := net.ParseIP(ip).To4()
	return v4 != nil && v4[3] >= 100
}

// liveNICs is the VM's LIVE NIC rows as the cluster records them, through the
// same vm_nics/vm_interfaces overlay the daemon reads.
func liveNICs(t *testing.T, n *Node, vmName string) []corrosion.NICRecord {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs(%s): %v", vmName, err)
	}
	return nics
}

// domainHasNIC reports whether the LIVE domain still carries the interface —
// the guest's own view, which is the half a lease assertion cannot see.
func domainHasNIC(t *testing.T, n *Node, vmName, mac string) bool {
	t.Helper()
	xml, err := n.Virt.DumpXML(vmName)
	if err != nil {
		t.Fatalf("DumpXML(%s): %v", vmName, err)
	}
	return strings.Contains(strings.ToLower(xml), strings.ToLower(mac))
}

// orphanChecksQueued drains the node's sync queue and reports which identities
// were named for the orphan sweep.
func orphanChecksQueued(t *testing.T, n *Node) []string {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), n.DB, "orphan", 50)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	var out []string
	for _, it := range items {
		if it.Kind == "orphan" && it.Op == "check" {
			out = append(out, it.Key)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ── attach ──────────────────────────────────────────────────────────────────

// TestHotplugAttachClaimsFromNetBox is the positive case: a NIC hot-attached to
// a bound network gets its address from NetBox, not from nowhere.
//
// The VM is created on the first bound network and the NIC attached on a
// SECOND one, because pre-latch a VM cannot hold two NICs on one network. That
// also makes the identity count load-bearing: one from the create, one from the
// attach.
func TestHotplugAttachClaimsFromNetBox(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustAddBoundNetwork(t, nb, c, n, "bound-b", "10.0.6.0/24", 8)
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)

	nic := mustAttachNIC(t, c, n, "vm-1", "bound-b")

	// .100+ is the fake's distinctive band; the builtin allocator produces .2.
	if !isNetBoxBand(nic.IP) {
		t.Fatalf("hotplugged NIC IP = %q, want an address from NetBox", nic.IP)
	}
	if got := leaseCount(t, n, "bound-b"); got != 1 {
		t.Fatalf("want exactly one lease for the hotplugged NIC, got %d", got)
	}
	if len(nb.Identities()) != 2 {
		t.Fatalf("want two identities after attach, got %v", nb.Identities())
	}
}

// TestHotplugAttachRefusedWhileNetBoxDown pins that hotplug has NO local
// fallback either. A node that quietly used the builtin allocator while NetBox
// was unreachable would hand out an address from a prefix whose authority
// cannot see it.
func TestHotplugAttachRefusedWhileNetBoxDown(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	nb.SetDown(true)
	if _, err := attachNIC(c, n, "vm-1", orphanNetwork); err == nil {
		t.Fatal("attach on a bound network must refuse while NetBox is down")
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("a refused attach must write no lease, got %d", got)
	}
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nics) != 0 {
		t.Fatalf("a refused attach must leave no NIC row, got %+v", nics)
	}
}

// TestHotplugAttachOnUnboundNetworkUnchanged is the behaviour-preservation
// guard, and the counterpart to TestVMOnUnboundNetworkGetsNoAllocation.
//
// VMs have never allocated on an unbound network, so a hotplugged NIC must keep
// getting exactly what it gets today: no address and no lease. The cluster has
// no NetBox client at all, so both ways of getting this wrong are caught —
// routing through the builtin allocator would produce 10.77.0.2, and routing
// through NetBox would refuse the attach outright.
func TestHotplugAttachOnUnboundNetworkUnchanged(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	// CreateVM preflights the resolved bridge with `ip link add`, EPERM for an
	// unprivileged test process. Stub the seam only.
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)

	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", ctNetName)

	if nic.IP != "" {
		t.Fatalf("a NIC hotplugged onto an unbound network must get no address, got %q", nic.IP)
	}
	if got := leaseCount(t, n, ctNetName); got != 0 {
		t.Fatalf("a NIC hotplugged onto an unbound network must write no ip_allocations row, got %d", got)
	}
}

// TestHotplugAttachRollsBackClaimWhenLiveAttachFails covers the window a claim
// opens: the address is taken from NetBox and then the irreversible live attach
// fails. Without compensation that address is held by an object nothing
// references and no NIC row records — invisible locally and, because the
// identity still resolves, not reclaimable by the sweeper either.
func TestHotplugAttachRollsBackClaimWhenLiveAttachFails(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	n.Virt.FailAttachNIC = func(_, _, _, _ string) error {
		return fmt.Errorf("live attach refused by the hypervisor")
	}

	if _, err := attachNIC(c, n, "vm-1", orphanNetwork); err == nil {
		t.Fatal("an attach whose live hotplug fails must not report success")
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("the claimed address must be released, still held: %v", ids)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("the local lease must be tombstoned too, %d still live", got)
	}
}

// TestHotplugAttachWithHardwareV2Latched proves the claim lands on the JOURNALED
// vm_nics path as well, not only on the pre-latch dual-write.
//
// Latched, the legacy (vm_name, network_name) key is out of the way, so this is
// also the one scenario where two NICs on ONE network are representable — and
// each must get its own distinct address.
func TestHotplugAttachWithHardwareV2Latched(t *testing.T) {
	nb, c, gates := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)

	// After the VM exists, so the audit pass adopts it rather than blocking it.
	latchHardwareV2(t, c, gates)

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)

	if !isNetBoxBand(nic.IP) {
		t.Fatalf("hotplugged NIC IP = %q, want an address from NetBox", nic.IP)
	}
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nics) != 2 {
		t.Fatalf("want two vm_nics rows once hardware_v2 is latched, got %+v", nics)
	}
	seen := map[string]bool{}
	for _, x := range nics {
		if !isNetBoxBand(x.IP) {
			t.Fatalf("vm_nics row %s carries %q, which is not a NetBox address", x.MAC, x.IP)
		}
		if seen[x.IP] {
			t.Fatalf("both NICs were given the same address %q", x.IP)
		}
		seen[x.IP] = true
	}
	if got := leaseCount(t, n, orphanNetwork); got != 2 {
		t.Fatalf("want a lease per NIC, got %d", got)
	}
	if ids := nb.Identities(); len(ids) != 2 {
		t.Fatalf("want two identities in NetBox, got %v", ids)
	}
}

// ── detach ──────────────────────────────────────────────────────────────────

// TestHotplugDetachReleasesOnlyThatNIC pins that a detach releases the address
// of the NIC being detached and NOTHING else.
//
// TWO networks, not two NICs on one: pre-latch the legacy vm_interfaces PK is
// (vm_name, network_name), so a VM cannot hold two NICs on a single network at
// all — a same-network pair would be refused before any release logic ran. Two
// bound prefixes give the same shape the property needs (two independently
// leased NICs on one VM) in a state the cluster can actually represent, and a
// release keyed on the VM rather than on the NIC frees the second one too.
func TestHotplugDetachReleasesOnlyThatNIC(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustAddBoundNetwork(t, nb, c, n, "bound-b", "10.0.6.0/24", 8)
	mustCreateNICLessVM(t, c, n, "vm-1")

	first := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)
	second := mustAttachNIC(t, c, n, "vm-1", "bound-b")
	if len(nb.Identities()) != 2 {
		t.Fatalf("want two claims before the detach, got %v — the assertions below would be vacuous", nb.Identities())
	}

	mustDetachNIC(t, c, n, "vm-1", first.MAC)

	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("the detached NIC's lease must be released, %d still live", got)
	}
	if got := leaseCount(t, n, "bound-b"); got != 1 {
		t.Fatalf("detaching one NIC released the other NIC's lease too, %d live on the second network", got)
	}
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want exactly the surviving NIC's identity left in NetBox, got %v", ids)
	}
	if !strings.HasSuffix(ids[0], ":"+second.MAC) {
		t.Fatalf("the WRONG identity survived: %q does not name the still-attached NIC %s", ids[0], second.MAC)
	}
}

// TestHotplugDetachTombstonesLeaseWhenBindingSuspended is the hotplug mirror of
// TestDeleteVMTombstonesLeaseWhenBindingSuspended.
//
// A suspended binding makes allocatorFor fail, and the release cannot go
// through the allocator. Skipping the release would tombstone nothing while the
// NIC goes away, leaving the ip_allocations row LIVE under a NIC that no longer
// exists — which burns the address in both systems at once, because the orphan
// sweep must never touch a live lease.
//
// The detach must still succeed (a suspended binding is not a reason a NIC
// becomes undetachable) while doing both halves it still can: tombstone the
// local lease directly, and hand the now-unreferenced remote object to the
// sweeper.
func TestHotplugDetachTombstonesLeaseWhenBindingSuspended(t *testing.T) {
	ctx := context.Background()
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("want one live lease before the detach, got %d", got)
	}
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want one NetBox identity before the detach, got %v", ids)
	}

	if err := corrosion.SuspendBinding(ctx, n.DB, orphanPrefixID, "test"); err != nil {
		t.Fatalf("SuspendBinding: %v", err)
	}

	if err := detachNIC(c, n, "vm-1", nic.MAC); err != nil {
		t.Fatalf("a suspended binding must not make the NIC undetachable: %v", err)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("the local lease must be tombstoned anyway, %d still live", got)
	}
	// The REMOTE half is deliberately deferred: releasing through a suspended
	// binding is what the suspension exists to prevent.
	if got := nb.Identities(); len(got) != 1 {
		t.Fatalf("the NetBox object must be left for the sweeper, identities = %v", got)
	}

	items, err := corrosion.DrainSyncQueue(ctx, n.DB, "orphan", 10)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	var found bool
	for _, it := range items {
		if it.Kind == "orphan" && it.Op == "check" && it.Key == ids[0] {
			found = true
		}
	}
	if !found {
		t.Fatalf("the deferred NetBox object must be queued as an orphan check for %q, queue = %+v", ids[0], items)
	}
}

// TestHotplugAttachPartialRollbackEnqueuesOrphanCheck covers the OTHER half of
// the compensation trade in failNICAttach.
//
// When the rollback cannot complete, the claimed address is deliberately NOT
// given back: a NIC row that survived the rollback would still name it, and
// freeing an address something still points at is worse than holding one nothing
// does. But that decision on its own ends in a log line — the lease stays live
// and the NetBox object stays held with nothing left to drive either forward,
// and neither is visible to anything that reports stuck leases.
//
// The failure is built out of two seams, because the property needs BOTH halves
// of a partial rollback to be real: the legacy dual-write aborts so the attach
// fails with the live hotplug and the authoritative row already on the ground,
// and the vm_nics tombstone aborts so the undo of that row genuinely cannot
// land. The device rollback still succeeds, which is what makes this partial
// rather than total.
func TestHotplugAttachPartialRollbackEnqueuesOrphanCheck(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	n.FailNICRowWrites(t) // the attach fails AFTER the live hotplug + vm_nics row
	n.FailNICRowDelete(t) // ...and the rollback of that row cannot land

	if _, err := attachNIC(c, n, "vm-1", orphanNetwork); err == nil {
		t.Fatal("an attach whose row write fails must not report success")
	}

	// The claim is RETAINED, in both systems: a live NIC row still names it.
	nics := liveNICs(t, n, "vm-1")
	if len(nics) != 1 {
		t.Fatalf("test setup: the rollback should have been unable to remove the NIC row, got %+v", nics)
	}
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("an incomplete rollback must NOT release the claim, identities = %v", ids)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("an incomplete rollback must leave the local lease live, got %d", got)
	}

	// ...and it is SURFACED rather than left to a log line.
	queued := orphanChecksQueued(t, n)
	if !contains(queued, ids[0]) {
		t.Fatalf("the retained claim %q must be named for the stuck-lease sweep, queue = %v", ids[0], queued)
	}
}

// TestHotplugDetachReleasesAfterLiveDetach pins the detach ORDER, and it is the
// exact mirror of the attach path's rolledBack guard.
//
// Give the address back BEFORE the live unplug and a detach that then fails
// leaves the guest holding an address that litevirt and the external IPAM both
// consider free — the collision every other ordering decision here exists to
// prevent. Unplug first and the same failure can only ever leak, which a retry
// or the sweep clears.
//
// The domain assertion is what makes this non-vacuous: both orderings return an
// error here, and only one of them has already freed an address the guest is
// still using.
func TestHotplugDetachReleasesAfterLiveDetach(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("want one live lease before the detach, got %d", got)
	}

	n.Virt.FailDetachNIC = func(_, _ string) error {
		return fmt.Errorf("live detach refused by the hypervisor")
	}

	if err := detachNIC(c, n, "vm-1", nic.MAC); err == nil {
		t.Fatal("a detach whose live unplug fails must not report success")
	}

	if !domainHasNIC(t, n, "vm-1", nic.MAC) {
		t.Fatal("test setup: the failed unplug must have left the NIC in the live domain")
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the address was freed while the domain still has the NIC: %d leases live", got)
	}
	if ids := nb.Identities(); len(ids) != 1 {
		t.Fatalf("the NetBox object was released while the domain still has the NIC: %v", ids)
	}
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 1 {
		t.Fatalf("a failed detach must leave the NIC row, got %+v", nics)
	}
}

// TestHotplugDetachReleaseFailureKeepsRow is what the ordering above BUYS: the
// leak it prefers has to be recoverable.
//
// The unplug lands and the release then fails on its local half, so litevirt
// still holds the address with the NIC already gone from the guest. The NIC row
// must survive that — it is the only thing that still names the address a retry
// has to release — and the operation must be terminally failed rather than left
// in flight, or the retry would be refused for an operation already in progress.
func TestHotplugDetachReleaseFailureKeepsRow(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)

	dropTombstoneFailure := n.FailLeaseTombstones(t)

	err := detachNIC(c, n, "vm-1", nic.MAC)
	if status.Code(err) != codes.Internal {
		t.Fatalf("a failed release must surface as Internal, got %v", err)
	}
	if domainHasNIC(t, n, "vm-1", nic.MAC) {
		t.Fatal("the live unplug runs first and must have landed")
	}
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 1 {
		t.Fatalf("the NIC row must be RETAINED so a retry can re-run the release, got %+v", nics)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the lease must still be live after a failed release, got %d", got)
	}
	if ids := nb.Identities(); len(ids) != 1 {
		t.Fatalf("the NetBox object must still be held after a failed release, got %v", ids)
	}

	// The retry is the whole point of retaining the row.
	dropTombstoneFailure()
	mustDetachNIC(t, c, n, "vm-1", nic.MAC)

	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("the retry must release the lease, %d still live", got)
	}
	if ids := nb.Identities(); len(ids) != 0 {
		t.Fatalf("the retry must release the NetBox object, still held: %v", ids)
	}
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 0 {
		t.Fatalf("the retry must remove the NIC row, got %+v", nics)
	}
}

// TestHotplugDetachRemoteReleaseFailureRetryRemovesRow is the OTHER release
// failure, and the one where a retry cannot simply do it all again.
//
// The release tombstones the local lease first and only then deletes the remote
// object, so a NetBox that is unreachable at that moment leaves the lease gone
// and the object held. A retry finds no lease at all — there is nothing left to
// prove ownership with, and re-running the remote delete blind would risk freeing
// an address another incarnation now holds. So the retry must not stall on it:
// it hands the object to the orphan sweep, which reclaims only under whole-
// cluster proof, and finishes removing the NIC.
func TestHotplugDetachRemoteReleaseFailureRetryRemovesRow(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want one NetBox identity before the detach, got %v", ids)
	}

	nb.SetDown(true)
	err := detachNIC(c, n, "vm-1", nic.MAC)
	if status.Code(err) != codes.Internal {
		t.Fatalf("a failed remote release must surface as Internal, got %v", err)
	}
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 1 {
		t.Fatalf("the NIC row must be RETAINED while the release is unfinished, got %+v", nics)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("test setup: the local half of the release lands first, so no lease should be live, got %d", got)
	}
	if got := nb.Identities(); len(got) != 1 {
		t.Fatalf("the remote object must still be held after an unreachable NetBox, got %v", got)
	}

	nb.SetDown(false)
	mustDetachNIC(t, c, n, "vm-1", nic.MAC)

	if nics := liveNICs(t, n, "vm-1"); len(nics) != 0 {
		t.Fatalf("the retry must remove the NIC row, got %+v", nics)
	}
	// Deliberately NOT deleted inline: with the lease already gone there is no
	// local proof of ownership left, so the sweep's whole-cluster proof is what
	// reclaims it.
	if got := nb.Identities(); len(got) != 1 {
		t.Fatalf("the retry must leave the remote object to the sweep, got %v", got)
	}
	queued := orphanChecksQueued(t, n)
	if !contains(queued, ids[0]) {
		t.Fatalf("the deferred NetBox object must be queued as an orphan check for %q, queue = %v", ids[0], queued)
	}
}

// ── detach: stopped VM ──────────────────────────────────────────────────────

// stoppedVMWithNIC brings up a VM holding exactly ONE hotplugged NIC on a bound
// network and then stops it — the state the stopped detach path acts on.
//
// hardware_v2 is latched AFTER the VM exists (so the audit pass adopts it rather
// than blocking it) and BEFORE the attach, which is what both makes the stopped
// path reachable at all and keeps the NIC on the journaled vm_nics row alone.
func stoppedVMWithNIC(t *testing.T, c *Cluster, gates map[string]*health.Checker, n *Node, vmName, netName string) nicInfo {
	t.Helper()
	ctx := context.Background()
	mustCreateNICLessVM(t, c, n, vmName)
	latchHardwareV2(t, c, gates)

	nic := mustAttachNIC(t, c, n, vmName, netName)
	if !isNetBoxBand(nic.IP) {
		t.Fatalf("the NIC must hold a NetBox address before the VM is stopped, got %q", nic.IP)
	}
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: vmName, Force: true}); err != nil {
		t.Fatalf("StopVM %s on %s: %v", vmName, n.Name, err)
	}
	vm, err := corrosion.GetVM(ctx, n.DB, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): %+v (err=%v)", vmName, vm, err)
	}
	if vm.State != "stopped" {
		t.Fatalf("test setup: %s must be stopped to reach the stopped detach path, state = %q", vmName, vm.State)
	}
	return nic
}

// TestHotplugStoppedDetachTombstonesRowBeforeRelease pins the stopped path's
// ORDER, and it is the same property TestHotplugDetachReleasesAfterLiveDetach
// pins for a running VM.
//
// A stopped VM has no live device, but it is NOT true that nothing is applied
// until the row goes: for a stopped VM the ROW IS the applied state, because
// reconcileDomainDefinition rebuilds the domain from the NIC rows, so the next
// define/start boots the guest with whatever the row says. Removing it is a
// separate replicated write that can fail on its own. Release first and a
// tombstone that then fails leaves a row naming an address NetBox has already
// handed to someone else — a collision on the next start.
//
// The failing tombstone is what makes this non-vacuous: both orderings return an
// error, and only one of them has already given the address away under a NIC the
// VM still declares.
func TestHotplugStoppedDetachTombstonesRowBeforeRelease(t *testing.T) {
	nb, c, gates := hotplugCluster(t, 1)
	n := c.Nodes[0]
	nic := stoppedVMWithNIC(t, c, gates, n, "vm-1", orphanNetwork)

	n.FailNICRowDelete(t)

	err := detachNIC(c, n, "vm-1", nic.MAC)
	if status.Code(err) != codes.Internal {
		t.Fatalf("a detach whose row tombstone fails must surface as Internal, got %v", err)
	}

	// The row step ran FIRST and failed, so NOTHING was released: the NIC the
	// next start would define still names an address both systems still hold.
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 1 {
		t.Fatalf("test setup: the tombstone should have been unable to remove the NIC row, got %+v", nics)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the address was freed while the NIC row still names it: %d leases live", got)
	}
	if ids := nb.Identities(); len(ids) != 1 {
		t.Fatalf("the NetBox object was released while the NIC row still names it: %v", ids)
	}
}

// TestHotplugStoppedDetachReleaseFailureIsALeak is what that ordering BUYS: the
// failure it prefers is a leak, and a leak has to be reclaimable.
//
// The row is gone and the release then fails, so litevirt still holds the address
// with the VM already unable to boot that NIC. Unlike the running path there is
// no row left for a retry to release from — a retried detach can only answer
// NotFound — so the identity must be named for the orphan sweep, which is the one
// mechanism that can still reclaim a lease and a NetBox object nothing references.
func TestHotplugStoppedDetachReleaseFailureIsALeak(t *testing.T) {
	nb, c, gates := hotplugCluster(t, 1)
	n := c.Nodes[0]
	nic := stoppedVMWithNIC(t, c, gates, n, "vm-1", orphanNetwork)
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want one NetBox identity before the detach, got %v", ids)
	}

	dropTombstoneFailure := n.FailLeaseTombstones(t)

	err := detachNIC(c, n, "vm-1", nic.MAC)
	if status.Code(err) != codes.Internal {
		t.Fatalf("a failed release must surface as Internal, got %v", err)
	}

	// A LEAK, not a collision: the row is gone (so no start can bring the NIC
	// back), and the address stays held in both systems.
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 0 {
		t.Fatalf("the row tombstone runs first and must have landed, got %+v", nics)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the lease must still be live after a failed release, got %d", got)
	}
	if got := nb.Identities(); len(got) != 1 {
		t.Fatalf("the NetBox object must still be held after a failed release, got %v", got)
	}

	// ...and it is RECLAIMABLE: named for the sweep, which is the only thing left
	// that can reclaim it, because a retry of the detach no longer finds the NIC.
	queued := orphanChecksQueued(t, n)
	if !contains(queued, ids[0]) {
		t.Fatalf("the retained address %q must be named for the orphan sweep, queue = %v", ids[0], queued)
	}
	dropTombstoneFailure()
	if err := detachNIC(c, n, "vm-1", nic.MAC); status.Code(err) != codes.NotFound {
		t.Fatalf("with the row already gone a retried detach can only answer NotFound, got %v", err)
	}
}
