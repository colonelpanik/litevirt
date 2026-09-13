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
	"errors"
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
// The release is ordered BEFORE the tombstone, which is what this scenario is
// about. It used to assert only that, tolerating a failed cutover: with the
// replaced VM's row present, the rename that followed the tombstone collided
// with the soft-deleted row on the `vms.name` unique constraint. That defect is
// fixed — the handover is now a guarded transition — so the cutover is required
// to succeed, and the assertions are unchanged.
func TestCutoverReleasesTheReplacedVMsLease(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)

	oldIP := vmNICIP(t, n, "app")
	oldIdentity := nicIdentityOf(t, n, "app")
	nextIP := vmNICIP(t, n, "app-next")
	if !isNetBoxBand(oldIP) || !isNetBoxBand(nextIP) || oldIP == nextIP {
		t.Fatalf("both VMs must hold DISTINCT NetBox addresses, got %q and %q", oldIP, nextIP)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 2 {
		t.Fatalf("test setup: want two leases before the cutover, got %d", got)
	}

	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}

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

// A cutover that never commits must not have given the replaced VM's address
// away. Releasing before the transition meant a declined delete — or any later
// failure — left a LIVE VM with its address back in the pool, locally and in the
// external IPAM.
func TestCutoverKeepsTheReplacedVMsAddressWhenItDoesNotCommit(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIP := vmNICIP(t, n, "app")
	oldIdentity := nicIdentityOf(t, n, "app")

	// The transition cannot commit: the tombstone is refused.
	if err := n.DB.Execute(ctx, `CREATE TRIGGER block_cutover_delete BEFORE UPDATE OF deleted_at ON vms
 WHEN OLD.name = 'app' AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover reported success despite a refused tombstone")
	}

	// The VM is still live, and still holds its address — here and in NetBox.
	vm, err := corrosion.GetVM(ctx, n.DB, "app")
	if err != nil || vm == nil {
		t.Fatalf("the replaced VM after a failed cutover: %+v err=%v", vm, err)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 2 {
		t.Fatalf("a failed cutover gave an address back: %d leases (want 2)", got)
	}
	if got := vmNICIP(t, n, "app"); got != oldIP {
		t.Fatalf("the live VM's address changed to %q, want %q", got, oldIP)
	}
	if ids := identitySet(nb); !ids[oldIdentity] {
		t.Fatalf("a failed cutover released the live VM's NetBox object: %v", nb.Identities())
	}
}

// A release that fails must leave the operation OWED, not the address stranded
// under a cutover that reported success. The journaled phase is retried.
func TestCutoverRetriesAFailedAddressRelease(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIdentity := nicIdentityOf(t, n, "app")

	// The remote half of the release fails for this attempt.
	nb.SetDown(true)
	_, cutErr := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
	nb.SetDown(false)
	if cutErr == nil {
		t.Fatal("a failed address release must not report a finished cutover")
	}

	owed, err := corrosion.ListVMReplaceCleanups(ctx, n.DB, n.Name)
	if err != nil {
		t.Fatalf("ListVMReplaceCleanups: %v", err)
	}
	if len(owed) != 1 || owed[0].ReleaseDone {
		t.Fatalf("the failed release left nothing owed: %+v", owed)
	}

	// The retry finishes it, and the address goes back.
	if err := n.Server.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the replaced VM's lease was not released by the retry: %d leases (want 1)", got)
	}
	if ids := identitySet(nb); ids[oldIdentity] {
		t.Fatalf("the replaced VM's NetBox object survived the retry: %v", nb.Identities())
	}
	if left, lErr := corrosion.ListVMReplaceCleanups(ctx, n.DB, n.Name); lErr != nil || len(left) != 0 {
		t.Fatalf("the operation is still owed after a successful retry: %+v err=%v", left, lErr)
	}
}

// A retry of an interrupted cutover has to reuse the manifest its predecessor
// journaled. The address capture walks LIVE NIC rows, so once the first attempt
// has tombstoned the original, a freshly built manifest names no addresses at
// all — and rebuilding it was what the retry used to do. The operation is not
// resumable on its own at that point (its transition never committed, so it is
// still `planned`, which authorizes nothing), so the retry is the only thing that
// can finish it.
func TestCutoverRetryReusesTheJournaledManifest(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIdentity := nicIdentityOf(t, n, "app")

	// Interrupted after the original is tombstoned and before the transition.
	n.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "before-commit" {
			return errors.New("injected crash before the transition")
		}
		return nil
	})
	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the cutover")
	}
	n.Server.SetCutoverCrashHook(nil)

	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("a healthy retry of an interrupted cutover must commit: %v", err)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the retry did not release the replaced VM's lease: %d leases (want 1)", got)
	}
	if ids := identitySet(nb); ids[oldIdentity] {
		t.Fatalf("the retry did not release the replaced VM's NetBox object: %v", nb.Identities())
	}
	if left, lErr := corrosion.ListVMReplaceCleanups(ctx, n.DB, n.Name); lErr != nil || len(left) != 0 {
		t.Fatalf("the retry left the operation owed: %+v err=%v", left, lErr)
	}
}

// A release whose halves both landed and whose `released` record did not must
// resume cleanly. The recorded object id is enough to delete a second time and
// get a not-found back forever, which used to leave every later attempt aborting
// before the destruction and runtime handoff.
func TestCutoverResumeTreatsAnAlreadyDeletedAddressAsReleased(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)

	// Only the phase RECORD fails: both halves of the release land first.
	if err := n.DB.Execute(ctx, `CREATE TRIGGER block_released_step BEFORE INSERT ON operation_steps
 WHEN NEW.step_name = 'released' BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover reported success despite a refused phase record")
	}
	if got, ids := leaseCount(t, n, orphanNetwork), nb.Identities(); got != 1 || len(ids) != 1 {
		t.Fatalf("the fixture did not reach the boundary it tests: %d leases, NetBox %v", got, ids)
	}
	if err := n.DB.Execute(ctx, `DROP TRIGGER block_released_step`); err != nil {
		t.Fatal(err)
	}

	if err := n.Server.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("an already-deleted address must not block recovery: %v", err)
	}
	if left, lErr := corrosion.ListVMReplaceCleanups(ctx, n.DB, n.Name); lErr != nil || len(left) != 0 {
		t.Fatalf("recovery did not finish the cutover: %+v err=%v", left, lErr)
	}
}

// The object id a manifest carries is a name, not a claim. An address released
// locally and then adopted by something else keeps the id and moves the identity,
// and a retry that deletes on the id alone takes a live workload's address.
func TestCutoverResumeLeavesAReassignedAddressAlone(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIP := vmNICIP(t, n, "app")
	lease, err := corrosion.GetLeaseByIPForOwner(ctx, n.DB, orphanNetwork, oldIP, "vm", "", "app")
	if err != nil || lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("the replaced VM's lease carries no NetBox object: %+v err=%v", lease, err)
	}

	// The local tombstone lands, the remote delete does not — the state the retry
	// exists for.
	nb.SetDown(true)
	_, cutErr := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
	nb.SetDown(false)
	if cutErr == nil {
		t.Fatal("a failed remote release must not report a finished cutover")
	}

	// NetBox keeps the object while an external owner adopts it.
	nb.Reassign(lease.NetBoxIPID, "someone-else")
	_ = n.Server.ResumeVMReplaceCleanups(ctx)

	if ids := identitySet(nb); !ids["someone-else"] {
		t.Fatalf("the retry deleted a reassigned NetBox object: %v", nb.Identities())
	}
}

// IPAM leases are cluster-global; host-local artifacts are not. Capturing the
// addresses inside the host-local gate meant a cutover run from the replacement's
// host onto an original hosted elsewhere journaled no addresses, and reported
// success while the original's allocation stayed claimed for good.
func TestCutoverReleasesACrossHostOriginalsAddress(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)
	oldHost, nextHost := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}

	mustCreateVMWithDiskOnNetwork(t, c, oldHost, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, nextHost, "app-next", orphanNetwork)
	oldIdentity := nicIdentityOf(t, oldHost, "app")

	// Retire the original's runtime first, so this pins the ADDRESS half of a
	// cross-host cutover rather than its domain teardown.
	if _, err := c.SelfClient(oldHost).StopVM(ctx, &pb.StopVMRequest{Name: "app", Force: true}); err != nil {
		t.Fatal(err)
	}
	if err := oldHost.Virt.UndefineDomainPreservingState("app"); err != nil {
		t.Fatal(err)
	}
	old, err := corrosion.GetVM(ctx, nextHost.DB, "app")
	if err != nil || old == nil || old.HostName != oldHost.Name {
		t.Fatalf("the replaced VM is not hosted where this test needs it: %+v err=%v", old, err)
	}
	if got, ids := leaseCount(t, nextHost, orphanNetwork), nb.Identities(); got != 2 || len(ids) != 2 {
		t.Fatalf("the fixture did not start with both allocations: %d leases, NetBox %v", got, ids)
	}
	latchCutoverCapabilities(t, c)

	if _, err := c.SelfClient(nextHost).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cross-host cutover: %v", err)
	}
	if got := leaseCount(t, nextHost, orphanNetwork); got != 1 {
		t.Fatalf("the cross-host original's lease survived the cutover: %d leases (want 1)", got)
	}
	if ids := identitySet(nb); ids[oldIdentity] {
		t.Fatalf("the cross-host original's NetBox object survived the cutover: %v", nb.Identities())
	}
}

// Name, MAC and key agreeing is not proof that the live lease row is still the
// allocation the manifest captured. The contested name belongs to the
// REPLACEMENT after the transition, and a cutover may reuse the original's MAC —
// so the external object behind the row is what separates the incarnations.
func TestCutoverLeavesAReclaimedLeaseRowAlone(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIP := vmNICIP(t, n, "app")
	oldIdentity := nicIdentityOf(t, n, "app")

	// Interrupted between the committed transition and the release phase.
	n.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "after-commit" {
			return errors.New("injected crash after the transition")
		}
		return nil
	})
	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the cutover")
	}
	n.Server.SetCutoverCrashHook(nil)

	// The row at that key now backs a different allocation.
	if err := n.DB.Execute(ctx,
		`UPDATE ip_allocations SET netbox_ip_id = 12345 WHERE network = ? AND ip = ?`,
		orphanNetwork, oldIP); err != nil {
		t.Fatal(err)
	}
	_ = n.Server.ResumeVMReplaceCleanups(ctx)

	held, err := corrosion.GetLeaseByIPForOwner(ctx, n.DB, orphanNetwork, oldIP, "vm", "", "app")
	if err != nil {
		t.Fatal(err)
	}
	if held == nil {
		t.Fatal("recovery tombstoned a lease row that backs a different allocation now")
	}
	if ids := identitySet(nb); !ids[oldIdentity] {
		t.Fatalf("recovery released an address that backs a different allocation now: %v", nb.Identities())
	}
}

// The identity check has to cover the branch where the lease row SURVIVED too. A
// first attempt whose local tombstone was refused leaves the row live, and the
// retry that finds it there still ends in a remote delete — which a matching name,
// MAC and object id do not authorize once the external object has moved on.
func TestCutoverRetryLeavesAReassignedAddressAloneWhenTheLeaseRowSurvived(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIP := vmNICIP(t, n, "app")
	lease, err := corrosion.GetLeaseByIPForOwner(ctx, n.DB, orphanNetwork, oldIP, "vm", "", "app")
	if err != nil || lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("the replaced VM's lease carries no NetBox object: %+v err=%v", lease, err)
	}

	// The LOCAL half is refused, so the lease row outlives the first attempt.
	drop := n.FailLeaseTombstones(t)
	_, cutErr := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
	drop()
	if cutErr == nil {
		t.Fatal("a refused lease tombstone must not report a finished cutover")
	}
	held, hErr := corrosion.GetLeaseByIPForOwner(ctx, n.DB, orphanNetwork, oldIP, "vm", "", "app")
	if hErr != nil || held == nil {
		t.Fatalf("the fixture did not reach the live-lease-row branch: %+v err=%v", held, hErr)
	}

	// NetBox keeps the object while an external owner adopts it.
	nb.Reassign(lease.NetBoxIPID, "someone-else")
	if rErr := n.Server.ResumeVMReplaceCleanups(ctx); rErr != nil {
		t.Fatalf("resume: %v", rErr)
	}
	if ids := identitySet(nb); !ids["someone-else"] {
		t.Fatalf("the retry deleted a reassigned NetBox object: %v", nb.Identities())
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("the retry did not release the replaced VM's lease row: %d leases (want 1)", got)
	}
}

// Cutover retires the replaced VM's domain only on the node it runs on. With the
// original hosted elsewhere there is nothing to run that with — so the retirement
// becomes a precondition, answered by the host that can see its own libvirt, and a
// cutover that cannot establish it must change nothing at all. Without the gate it
// handed the name and the address over while that guest was still running on both.
func TestCutoverRefusesWhileTheOriginalStillHasADomainOnAnotherHost(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)
	oldHost, nextHost := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}

	mustCreateVMWithDiskOnNetwork(t, c, oldHost, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, nextHost, "app-next", orphanNetwork)
	oldIdentity := nicIdentityOf(t, oldHost, "app")
	if active, aErr := oldHost.Virt.DomainIsActive("app"); aErr != nil || !active {
		t.Fatalf("the original has to be running for this test: active=%v err=%v", active, aErr)
	}
	latchCutoverCapabilities(t, c)

	if _, err := c.SelfClient(nextHost).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover reported success while the original still had a domain on its host")
	}
	if active, aErr := oldHost.Virt.DomainIsActive("app"); aErr != nil || !active {
		t.Fatalf("the refused cutover touched the original's domain: active=%v err=%v", active, aErr)
	}
	if got := leaseCount(t, nextHost, orphanNetwork); got != 2 {
		t.Fatalf("the refused cutover gave an address back: %d leases (want 2)", got)
	}
	if ids := identitySet(nb); !ids[oldIdentity] {
		t.Fatalf("the refused cutover released the original's NetBox object: %v", nb.Identities())
	}
	vm, err := corrosion.GetVM(ctx, nextHost.DB, "app")
	if err != nil || vm == nil || vm.HostName != oldHost.Name {
		t.Fatalf("the refused cutover moved the original's row: %+v err=%v", vm, err)
	}
}

// An owner-scoped read answers a foreign live allocation and a genuinely absent
// one with the same nil, and those authorize opposite actions: absence is what
// licenses finishing a remote delete on its own. A live allocation another
// workload now holds has to veto both halves — the local row is not this
// operation's to retire, and its external object is backing an address still in
// use, whatever identity happens to be on it.
func TestCutoverLeavesAnAddressAnotherWorkloadNowHoldsAlone(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "app", orphanNetwork)
	mustCreateVMWithDiskOnNetwork(t, c, n, "app-next", orphanNetwork)
	latchCutoverCapabilities(t, c)
	oldIP := vmNICIP(t, n, "app")
	oldIdentity := nicIdentityOf(t, n, "app")

	// Interrupted between the committed transition and the release phase.
	n.Server.SetCutoverCrashHook(func(stage string) error {
		if stage == "after-commit" {
			return errors.New("injected crash after the transition")
		}
		return nil
	})
	if _, err := c.SelfClient(n).CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the injected crash did not fail the cutover")
	}
	n.Server.SetCutoverCrashHook(nil)

	// The allocation's OWNER moves while everything else about it — address, MAC,
	// external object, external identity — stays exactly as the manifest captured
	// it. A local owner is not part of a NetBox identity, so the identity check
	// alone cannot see this.
	if err := n.DB.Execute(ctx,
		`UPDATE ip_allocations SET vm_name = ?, updated_at = ? WHERE network = ? AND ip = ?`,
		"retained", n.DB.NowTS(), orphanNetwork, oldIP); err != nil {
		t.Fatal(err)
	}
	// The veto is a REFUSAL, not a failure: an address this operation may not
	// retire is left for the orphan sweep, and the phases after it — the
	// destruction and the runtime handoff — still run. Retrying a release that can
	// never succeed would wedge the cutover with no domain at the name.
	if rErr := n.Server.ResumeVMReplaceCleanups(ctx); rErr != nil {
		t.Fatalf("a foreign allocation must not wedge the cleanup: %v", rErr)
	}
	if left, lErr := corrosion.ListVMReplaceCleanups(ctx, n.DB, n.Name); lErr != nil || len(left) != 0 {
		t.Fatalf("the cutover is still owed after recovery: %+v err=%v", left, lErr)
	}

	held, err := corrosion.GetLeaseByIPForOwner(ctx, n.DB, orphanNetwork, oldIP, "vm", "", "retained")
	if err != nil {
		t.Fatal(err)
	}
	if held == nil {
		t.Fatal("recovery retired a lease row another workload now owns")
	}
	if ids := identitySet(nb); !ids[oldIdentity] {
		t.Fatalf("recovery deleted the NetBox object backing a live foreign allocation: %v", nb.Identities())
	}
}
