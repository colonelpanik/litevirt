// What the orphan sweep does — and does NOT do — after "local tombstone landed,
// NetBox release failed".
//
// A release is two steps in a fixed order: tombstone the local `ip_allocations`
// row, then delete the object in NetBox. The order is deliberate (the reverse
// would free an address litevirt still believes it holds), and it makes the
// middle state un-retryable: ReleaseLease guards on `deleted_at IS NULL`, so a
// retry matches zero rows and refuses, because the row it would prove ownership
// with is already gone.
//
// Every caller therefore hands the identity to the ORPHAN SWEEP, and a P1 item
// was deferred on the claim that the sweep must cover it. It covers HALF of it,
// and the half it does not cover is not covered by anything:
//
//   - the sweep's absence proof is not only about the lease. `Holds()` is
//     `HoldsUUID || HoldsMAC || HoldsAddress`, and the identity carries the
//     OWNING VM's uuid. Where the VM is gone — a delete, a stale-record cleanup —
//     no host claims the uuid and the address is reclaimed. Where the VM SURVIVES
//     — a NIC hot-detach — its uuid is still in `vms.spec` and in the domain XML,
//     so `Holds()` is true and the reclamation is declined on every pass for as
//     long as the VM lives.
//
// Both are pinned below: the first as the coverage that does exist, the second
// as the residual leak, so that neither can change without a test saying so.

package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestOrphanSweepReclaimsAnAddressLeftByAFailedRemoteRelease is the covered
// half, end to end: tombstone lands, NetBox release fails, the identity is
// queued, and a later sweep reclaims it.
//
// The owning VM is GONE here, which is exactly why the proof completes: nothing
// in the cluster claims the uuid, the MAC or the address any more.
func TestOrphanSweepReclaimsAnAddressLeftByAFailedRemoteRelease(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "vm-1", orphanNetwork)
	identity := nicIdentityOf(t, n, "vm-1")

	// The stale-record path: the domain is gone, so the cleanup must finish even
	// though the remote half of the release cannot.
	if err := n.Virt.UndefineDomain("vm-1", false); err != nil {
		t.Fatalf("undefine the domain behind the daemon's back: %v", err)
	}
	nb.SetDown(true)
	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-1"}); err != nil {
		t.Fatalf("the stale-record cleanup must complete even when the release fails: %v", err)
	}
	nb.SetDown(false)

	if vm, gerr := corrosion.GetVM(ctx, n.DB, "vm-1"); gerr == nil && vm != nil {
		t.Fatalf("precondition: the VM row must be gone, got state %q", vm.State)
	}
	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("precondition: the local tombstone must have landed, got %d live leases", got)
	}
	if ids := identitySet(nb); !ids[identity] {
		t.Fatalf("precondition: NetBox must still hold the object, got %v", nb.Identities())
	}
	if !contains(orphanChecksQueued(t, n), identity) {
		t.Fatalf("precondition: the identity must be queued for the sweep, got %v",
			orphanChecksQueued(t, n))
	}

	m := newSweepMetrics()
	n.Server.SetNetBoxMetrics(m)
	mustSweep(t, n)

	if ids := identitySet(nb); ids[identity] {
		t.Fatalf("the orphan sweep must reclaim an address no host claims any more; "+
			"NetBox still holds %v (declined: %v)", nb.Identities(), m.skips())
	}
}

// TestOrphanSweepCannotReclaimADetachedNICWhileItsVMLives is the residual leak,
// and the reason the deferred item's premise does not hold in general.
//
// Same middle state as above — local tombstone landed, remote release failed,
// identity queued — but the VM survives the detach. The identity carries that
// VM's uuid, the proof asks every host whether it still claims the uuid, the MAC
// or the address, and the answer for the uuid is yes. So `Holds()` is true and
// the reclamation is declined, on this pass and on every pass after it.
//
// That is a LEAK, not a collision, so it is the safe side of the branch this
// whole feature leans on — but nothing surfaces it: the refusal raises no health
// condition (the blocked-pass streak only counts unreachable hosts), the queued
// item is acked after one pass, and all that is left is a metric label and a log
// line. An operator has to find the address in NetBox by hand.
//
// Pinned as it BEHAVES, deliberately. Narrowing the proof so a surviving VM's
// uuid no longer vetoes the reclamation of an address it no longer holds is a
// change to the guard that protects a running guest's address, and not one to
// make from inside a test.
func TestOrphanSweepCannotReclaimADetachedNICWhileItsVMLives(t *testing.T) {
	nb, c, _ := hotplugCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()
	mustCreateNICLessVM(t, c, n, "vm-1")

	nic := mustAttachNIC(t, c, n, "vm-1", orphanNetwork)
	ids := nb.Identities()
	if len(ids) != 1 {
		t.Fatalf("want one NetBox identity before the detach, got %v", ids)
	}
	identity := ids[0]

	// The middle state: the local tombstone lands, the remote delete cannot, and
	// the retry removes the NIC row and queues the identity.
	nb.SetDown(true)
	if err := detachNIC(c, n, "vm-1", nic.MAC); err == nil {
		t.Fatal("precondition: a detach against an unreachable NetBox must fail")
	}
	nb.SetDown(false)
	mustDetachNIC(t, c, n, "vm-1", nic.MAC)

	if got := leaseCount(t, n, orphanNetwork); got != 0 {
		t.Fatalf("precondition: the lease must be tombstoned, got %d live", got)
	}
	if nics := liveNICs(t, n, "vm-1"); len(nics) != 0 {
		t.Fatalf("precondition: the NIC row must be gone, got %+v", nics)
	}
	if !contains(orphanChecksQueued(t, n), identity) {
		t.Fatalf("precondition: the identity must be queued, got %v", orphanChecksQueued(t, n))
	}
	// The VM — and therefore the uuid inside the identity — is still here.
	vm, err := corrosion.GetVM(ctx, n.DB, "vm-1")
	if err != nil || vm == nil {
		t.Fatalf("precondition: the VM must survive the detach: %v", err)
	}

	m := newSweepMetrics()
	n.Server.SetNetBoxMetrics(m)
	mustSweep(t, n)

	if ids := identitySet(nb); !ids[identity] {
		t.Fatal("the sweep reclaimed a detached NIC's address while its VM was still alive. " +
			"That is the behaviour this test was written to say did NOT happen — if the " +
			"absence proof was narrowed deliberately, this test records the old answer and " +
			"should be replaced by one asserting the reclamation")
	}
	if !contains(m.skips(), "host_still_claims") {
		t.Fatalf("the sweep must decline because a host still claims the identity's uuid, "+
			"declined for: %v", m.skips())
	}
}
