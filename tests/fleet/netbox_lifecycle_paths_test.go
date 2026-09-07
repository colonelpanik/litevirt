// Fleet scenarios for the VM lifecycle paths that are NEITHER CreateVM nor
// DeleteVM — the ones P1 originally left out.
//
// The claim/release pair was wired into exactly one create path and one delete
// path. Every other way a VM row comes into existence (clone, live-restore,
// import, a renamed promote) built NIC rows and persisted them without ever
// consulting the allocator, and every other way a VM row is REMOVED (rebuild,
// cutover, the stale-record cleanup) tombstoned the row while leaving the lease
// behind. Neither gap is visible from a single-package test: both need a real
// bound network, a real binding row, and a real NetBox behind them.
//
// Two invariants are being defended, and they pull in opposite directions:
//
//	never let a guest hold an address litevirt did not reserve   (the creates)
//	never free an address something still names                  (the deletes)
//
// So the creates REFUSE, and the deletes RELEASE FIRST — and a release that
// fails is surfaced rather than swallowed, because a lease that outlives its VM
// row is one the sweeper's live-lease veto can never reclaim.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// mustCreateVMWithDiskOnNetwork creates a VM with ONE real root disk and one NIC
// on netName, pinned to n.
//
// The disk is real (a pure-Go qcow2 in the node's own image store, no root
// needed) because the destructive paths under test DELETE disks: a scenario that
// asserts "nothing was destroyed" against a VM that never had a disk would pass
// with the refusal removed.
func mustCreateVMWithDiskOnNetwork(t *testing.T, c *Cluster, n *Node, name, netName string) *pb.VM {
	t.Helper()
	vm, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      name,
			Cpu:       1,
			MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: n.Name},
			Disks:     []*pb.DiskSpec{{Name: "root", Size: "64M"}},
			Network:   []*pb.NetworkAttachment{{Name: netName}},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM %s on network %q at %s: %v", name, netName, n.Name, err)
	}
	return vm
}

// vmSpecUUIDOf reads the incarnation uuid out of a VM's stored spec.
//
// It is the middle component of every NetBox identity, and the ONLY part of the
// identity a rebuild changes — the MAC is carried forward deliberately. So it is
// what distinguishes "the rebuild was refused" from "the rebuild ran and the VM
// that came back is a different incarnation wearing the same name".
func vmSpecUUIDOf(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): vm=%v err=%v", vmName, vm, err)
	}
	var sp struct {
		Uuid string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(vm.Spec), &sp); err != nil {
		t.Fatalf("parse spec of %s: %v", vmName, err)
	}
	if sp.Uuid == "" {
		t.Fatalf("VM %s carries no spec uuid — an identity assertion would be vacuous", vmName)
	}
	return sp.Uuid
}

// nicIdentityOf builds the NetBox identity a VM's first NIC claims under,
// exactly as the daemon builds it: cluster fingerprint + incarnation uuid + MAC.
func nicIdentityOf(t *testing.T, n *Node, vmName string) string {
	t.Helper()
	nics := liveNICs(t, n, vmName)
	if len(nics) == 0 {
		t.Fatalf("VM %s has no NIC rows", vmName)
	}
	return netbox.Identity(clusterFP(t, n), vmSpecUUIDOf(t, n, vmName), nics[0].MAC)
}

// vmDiskPaths is where a VM's disks actually live on this node's filesystem.
func vmDiskPaths(t *testing.T, n *Node, vmName string) []string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("GetVMDisks(%s): %v", vmName, err)
	}
	var out []string
	for _, d := range disks {
		out = append(out, d.Path)
	}
	return out
}

// mustStopVM stops a VM so a clone can read a crash-consistent disk.
func mustStopVM(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	if _, err := c.SelfClient(n).StopVM(context.Background(),
		&pb.StopVMRequest{Name: name, Force: true}); err != nil {
		t.Fatalf("StopVM %s: %v", name, err)
	}
}

// identitySet is the set of identities NetBox currently holds.
func identitySet(nb *NetBoxFake) map[string]bool {
	out := map[string]bool{}
	for _, id := range nb.Identities() {
		out[id] = true
	}
	return out
}

// ── 1. rebuild ──────────────────────────────────────────────────────────────

// TestRebuildRefusedOnBoundNetwork is the CRITICAL one: rebuild used to destroy
// the VM and then refuse to recreate it.
//
// RebuildVM copies the VM's current address out of vm_interfaces into the new
// spec as an EXPLICIT one, deletes the disks, the firmware state and the row,
// and only then calls CreateVM — which mints a FRESH spec uuid. A NetBox claim
// is keyed on (fingerprint, uuid, mac), so the recreate asks for the old address
// under a NEW identity: the specific claim is refused as held by another system,
// and the recovery lookup finds the object under the OLD identity. By then the
// disks are gone. The VM is destroyed and cannot come back.
//
// So the refusal comes first, before anything destructive, and this asserts on
// all four things that had to survive it: the row (with the SAME incarnation
// uuid), the disk file, the lease, and the NetBox object under its ORIGINAL
// identity.
//
// The uuid is what makes it non-vacuous. Delete the refusal and the rebuild runs
// — on today's code it can even succeed, because the release now added before
// the tombstone frees the address first — but the VM that comes back is a
// different incarnation: new uuid, new identity, the original object gone from
// NetBox. Both assertions go red.
func TestRebuildRefusedOnBoundNetwork(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "vm-1", orphanNetwork)

	ip := vmNICIP(t, n, "vm-1")
	if !isNetBoxBand(ip) {
		t.Fatalf("the VM must hold a NetBox address before the rebuild, got %q", ip)
	}
	uuidBefore := vmSpecUUIDOf(t, n, "vm-1")
	identityBefore := nicIdentityOf(t, n, "vm-1")
	disks := vmDiskPaths(t, n, "vm-1")
	if len(disks) == 0 {
		t.Fatal("the VM must have a disk on disk, or the destruction assertion is vacuous")
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("test setup: disk %q is not on disk: %v", p, err)
		}
	}

	_, err := c.SelfClient(n).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "vm-1"})
	if err == nil {
		t.Fatal("rebuilding a VM on a NetBox-bound network must be refused")
	}
	// The NETWORK is named, not merely "an error came back": the operator has to
	// know which attachment blocks the rebuild.
	if !strings.Contains(err.Error(), orphanNetwork) {
		t.Fatalf("the refusal must name the bound network, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("the refusal must name the operation it declined, got: %v", err)
	}

	// 1. the row, and the SAME incarnation.
	if got := vmSpecUUIDOf(t, n, "vm-1"); got != uuidBefore {
		t.Fatalf("the VM was rebuilt: spec uuid %q → %q", uuidBefore, got)
	}
	// 2. the disks.
	for _, p := range disks {
		if _, serr := os.Stat(p); serr != nil {
			t.Fatalf("a refused rebuild destroyed disk %q: %v", p, serr)
		}
	}
	// 3. the lease.
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the VM's lease must survive a refused rebuild, got %d rows", got)
	}
	if got := vmNICIP(t, n, "vm-1"); got != ip {
		t.Fatalf("the NIC's address changed under a refused rebuild: %q → %q", ip, got)
	}
	// 4. the NetBox object, under its ORIGINAL identity.
	if ids := identitySet(nb); !ids[identityBefore] {
		t.Fatalf("the NetBox object must still carry the original identity %q, NetBox holds %v",
			identityBefore, nb.Identities())
	}
}

// TestRebuildStillWorksOnAnUnboundNetwork is the control. Without it the test
// above passes against a rebuild that refuses everything.
func TestRebuildStillWorksOnAnUnboundNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)

	mustCreateVMWithDiskOnNetwork(t, c, n, "vm-1", ctNetName)

	if _, err := c.SelfClient(n).RebuildVM(context.Background(),
		&pb.RebuildVMRequest{Name: "vm-1"}); err != nil {
		t.Fatalf("a rebuild on an UNBOUND network must still work: %v", err)
	}
}

// ── 2. clone ────────────────────────────────────────────────────────────────

// TestCloneRefusedOntoBoundNetwork pins that a clone does not quietly produce a
// VM on a NetBox-bound network with no reservation behind it.
//
// CloneVM rebuilds the source's NIC list with fresh MACs and persists it
// directly — it never consults the allocator — so the clone came up attached to
// an externally managed prefix holding NO address at all: nothing claimed for
// it, nothing leased, and NetBox with no record that the interface exists.
//
// The assertion is on the ROW, not on an address: with the refusal removed the
// clone's NIC simply has no IP, so an address assertion would be satisfied by
// the bug. What must not exist is the VM.
func TestCloneRefusedOntoBoundNetwork(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "src", orphanNetwork)
	mustStopVM(t, c, n, "src") // a clone source must be stopped or a template

	_, err := c.SelfClient(n).CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "clone-1"})
	if err == nil {
		t.Fatal("cloning onto a NetBox-bound network must be refused")
	}
	if !strings.Contains(err.Error(), orphanNetwork) {
		t.Fatalf("the refusal must name the bound network, got: %v", err)
	}
	if !strings.Contains(err.Error(), "clone") {
		t.Fatalf("the refusal must name the operation it declined, got: %v", err)
	}

	if vm, gerr := corrosion.GetVM(ctx, n.DB, "clone-1"); gerr == nil && vm != nil {
		t.Fatalf("a refused clone must leave no VM row, got state %q", vm.State)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("a refused clone must lease nothing extra, got %d rows (want the source's one)", got)
	}
	if got := len(nb.Identities()); got != 1 {
		t.Fatalf("a refused clone must claim nothing in NetBox, got %d identities", got)
	}
}

// TestCloneStillWorksOnAnUnboundNetwork is the control for the refusal above.
func TestCloneStillWorksOnAnUnboundNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "src", ctNetName)
	mustStopVM(t, c, n, "src")

	if _, err := c.SelfClient(n).CloneVM(context.Background(),
		&pb.CloneVMRequest{Source: "src", Target: "clone-1"}); err != nil {
		t.Fatalf("a clone onto an UNBOUND network must still work: %v", err)
	}
}

// ── 3. live restore ─────────────────────────────────────────────────────────

// seedVMBackupOnNetwork writes a one-disk VM backup whose embedded spec attaches
// the VM to netName. The embedded spec is the whole fixture: autoDefineRestoredVM
// rebuilds the NIC rows straight from it, addresses included.
func seedVMBackupOnNetwork(t *testing.T, name, netName string) (repoDir, ts string) {
	t.Helper()
	repoDir = filepath.Join(t.TempDir(), "vmrepo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("init backup repo: %v", err)
	}
	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: netName, Ip: "10.0.5.101"}},
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	ts = "2026-07-01T00:00:00Z"
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(make([]byte, 1<<20)),
		pbsstore.PushOptions{VMName: name, DiskName: "root", Timestamp: ts, VMSpecJSON: string(specJSON)}); err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	return repoDir, ts
}

// TestRestoreRefusedOntoBoundNetwork pins the restore half.
//
// A live restore reconstructs the NIC rows from the BACKED-UP spec, carrying
// that spec's addresses verbatim. On a bound network that boots a guest holding
// an address the external IPAM either still assigns to the original VM — restore
// alongside is the documented workflow — or never issued to this cluster at all.
// The fixture's spec carries 10.0.5.101 for exactly that reason: with the
// refusal removed, the restored VM comes up wearing it with nothing reserved.
func TestRestoreRefusedOntoBoundNetwork(t *testing.T) {
	_, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	repo, ts := seedVMBackupOnNetwork(t, "backed-up", orphanNetwork)

	st, err := c.SelfClient(n).RestoreLive(ctx, &pb.RestoreLiveRequest{
		RepoPath: repo, VmName: "backed-up", DiskName: "root", Timestamp: ts,
		TargetPath: "restored.qcow2", NewName: "restored",
		AutoStart: true, Blockpull: true,
	})
	if err == nil {
		for {
			_, rerr := st.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				err = rerr
				break
			}
		}
	}
	if err == nil {
		t.Fatal("restoring onto a NetBox-bound network must be refused")
	}
	if !strings.Contains(err.Error(), orphanNetwork) {
		t.Fatalf("the refusal must name the bound network, got: %v", err)
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Fatalf("the refusal must name the operation it declined, got: %v", err)
	}
	if vm, gerr := corrosion.GetVM(ctx, n.DB, "restored"); gerr == nil && vm != nil {
		t.Fatalf("a refused restore must leave no VM row, got state %q", vm.State)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("a refused restore must lease nothing, got %d rows", got)
	}
}

// ── 4. the row-deleting paths ───────────────────────────────────────────────

// TestStaleRecordCleanupReleasesLeases pins the delete half.
//
// Three paths tombstone a VM row without going through DeleteVM's release loop:
// the stale-record cleanup, rebuild, and cutover. Each left the ip_allocations
// row behind — and once the VM row is gone the sweeper's live-lease veto (a live
// lease is one a running guest may be using, so the sweep must never reclaim it)
// makes that lease unreclaimable FOREVER, with no metric, no finding and no log
// line. The address is burned in both systems at once.
//
// The stale-record cleanup is the one of the three that drives end-to-end here,
// and it is also the most dangerous: it fires precisely when the domain has
// vanished out-of-band, which is when nobody is watching. Undefining the domain
// behind the daemon's back is exactly that state — a crash mid-teardown, an
// admin `virsh undefine` — and the VM row survives it.
//
// BOTH halves are asserted, because only the pair distinguishes a real release
// from a local tombstone that never reached NetBox: the lease row goes AND the
// external object goes with it.
func TestStaleRecordCleanupReleasesLeases(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "vm-1", orphanNetwork)
	if !isNetBoxBand(vmNICIP(t, n, "vm-1")) {
		t.Fatal("the VM must hold a NetBox address before the delete")
	}
	identity := nicIdentityOf(t, n, "vm-1")
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("test setup: want one lease before the delete, got %d", got)
	}

	// The domain disappears out-of-band, leaving the cluster row behind. This is
	// what routes DeleteVM into the stale-record cleanup rather than its ordinary
	// path — and the ordinary path already released, so without this the scenario
	// would pass against the bug.
	if err := n.Virt.UndefineDomain("vm-1", false); err != nil {
		t.Fatalf("undefine the domain behind the daemon's back: %v", err)
	}
	if n.Virt.DomainExists("vm-1") {
		t.Fatal("test setup: the domain must be gone for the stale-record path to run")
	}

	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-1"}); err != nil {
		t.Fatalf("DeleteVM (stale-record cleanup): %v", err)
	}

	if vm, gerr := corrosion.GetVM(ctx, n.DB, "vm-1"); gerr == nil && vm != nil {
		t.Fatalf("the stale row must be cleaned up, got state %q", vm.State)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("the lease must be released before the row is tombstoned, got %d live leases", got)
	}
	if ids := identitySet(nb); ids[identity] {
		t.Fatalf("the NetBox object must be released too, NetBox still holds %v", nb.Identities())
	}
}

// TestStaleRecordCleanupEnqueuesOrphanCheckWhenReleaseFails is the failure half.
//
// The cleanup MUST complete even when the release fails: it runs because the
// domain no longer exists anywhere, and refusing to remove the ghost row over a
// release failure would leave a row every node keeps scheduling around and
// failing over. What it must not do is fail SILENTLY — with NetBox unreachable
// the local lease is tombstoned and the remote object survives, a leak nothing
// else in the system will ever notice unless the identity is named for the
// orphan sweep.
func TestStaleRecordCleanupEnqueuesOrphanCheckWhenReleaseFails(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "vm-1", orphanNetwork)
	if got := pendingQueueItems(t, n, "orphan"); got != 0 {
		t.Fatalf("test setup: the sync queue must start empty, got %d items", got)
	}
	if err := n.Virt.UndefineDomain("vm-1", false); err != nil {
		t.Fatalf("undefine the domain behind the daemon's back: %v", err)
	}

	// Unreachable NetBox: the local tombstone lands, the remote delete cannot.
	nb.SetDown(true)

	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-1"}); err != nil {
		t.Fatalf("the stale-record cleanup must complete even when the release fails: %v", err)
	}
	if vm, gerr := corrosion.GetVM(ctx, n.DB, "vm-1"); gerr == nil && vm != nil {
		t.Fatalf("the ghost row must still be removed, got state %q", vm.State)
	}
	if got := pendingQueueItems(t, n, "orphan"); got == 0 {
		t.Fatal("a failed release must name the address for the orphan sweep — " +
			"a leaked lease whose only trace is a log line is invisible")
	}
}

// TestCutoverReleasesTheReplacedVMsLease covers the cutover path's half of the
// same rule.
//
// It asserts ONLY the release, and deliberately does not require the cutover to
// return cleanly: with the replaced VM's row present, the rename that follows
// the tombstone collides with the soft-deleted row on the `vms.name` unique
// constraint. That is a PRE-EXISTING cutover defect, unrelated to addressing and
// out of scope here — every existing CutoverVM test drives the case where the
// replaced VM does not exist, which is why it has not been caught. The release
// is ordered BEFORE the tombstone, so it has already run either way, and it is
// what this scenario is about. Should the rename be fixed, the assertions below
// hold unchanged.
func TestCutoverReleasesTheReplacedVMsLease(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)

	oldIP := vmNICIP(t, n, "app")
	oldIdentity := nicIdentityOf(t, n, "app")
	nextIP := vmNICIP(t, n, "app-next")
	if !isNetBoxBand(oldIP) || !isNetBoxBand(nextIP) || oldIP == nextIP {
		t.Fatalf("both VMs must hold DISTINCT NetBox addresses, got %q and %q", oldIP, nextIP)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 2 {
		t.Fatalf("test setup: want two leases before the cutover, got %d", got)
	}

	_, _ = c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})

	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the replaced VM's lease must be released by the cutover, got %d leases (want 1)", got)
	}
	if ids := identitySet(nb); ids[oldIdentity] {
		t.Fatalf("the replaced VM's NetBox object must be released, NetBox still holds %v", nb.Identities())
	}
	if got := len(nb.Identities()); got != 1 {
		t.Fatalf("exactly the surviving VM's address must remain in NetBox, got %v", nb.Identities())
	}
}
