// Maintenance-loop scenarios.
//
// Tasks 12 and 13 built the orphan sweeper and binding revalidation as one-shot
// entry points; nothing called them. This is the driver that does, and the only
// decision it makes is the ORDER: revalidate first, and sweep only against
// bindings that pass. A sweep is the one operation that deletes state from
// NetBox, so it may never run against a binding litevirt has just stopped
// trusting — or one it could not check at all.

package fleet

import (
	"context"
	"testing"
)

// mustRunMaintenance runs one maintenance pass — revalidation, then the sweep —
// on n.
//
// Neither half errors on a REFUSAL: drift is a suspension and a blocked
// reclamation is a logged skip, so an error here means the pass itself broke.
func mustRunMaintenance(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Server.RunNetBoxMaintenanceOnce(context.Background()); err != nil {
		t.Fatalf("RunNetBoxMaintenanceOnce on %s: %v", n.Name, err)
	}
}

// failBindingWrites makes every write to netbox_bindings on n fail, leaving
// reads working. It models the one shape that separates the two halves of a
// pass: revalidation cannot record what it found, while the sweep's own
// enumeration is untouched and would happily proceed.
func failBindingWrites(t *testing.T, n *Node) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`CREATE TRIGGER netbox_binding_writes_fail_test BEFORE UPDATE ON netbox_bindings
		 BEGIN SELECT RAISE(ABORT, 'binding write refused by the test'); END`); err != nil {
		t.Fatalf("install binding-write trigger on %s: %v", n.Name, err)
	}
}

// TestMaintenanceLoopRevalidatesAndSweeps pins that ONE pass does both halves,
// in the order that matters.
//
// The fixture is the exact one TestSweeperReclaimsATrueOrphan proves is
// reclaimable, plus a re-CIDR under it. So the pass has real work for both
// halves, and sweeping first would genuinely delete the address — under a
// binding whose recorded range NetBox no longer agrees with.
func TestMaintenanceLoopRevalidatesAndSweeps(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	n := c.Nodes[0]

	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24")

	mustRunMaintenance(t, n)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the maintenance pass must revalidate bindings")
	}
	// Revalidation suspended the binding, so the sweep in that same pass must
	// not then reclaim against a binding litevirt no longer trusts.
	if len(nb.Identities()) != 1 {
		t.Fatalf("a binding suspended by this very pass must not have its addresses swept, released %v",
			nb.Released())
	}
}

// TestMaintenanceSkipsSweepWhenRevalidationFails pins the other half of that
// order: a revalidation that could not COMPLETE leaves the sweep unrun.
//
// The distinction matters because a failed revalidation is not "no drift" — it
// is "unknown". Here the prefix HAS been re-CIDRed and the suspension write is
// what fails, so the binding is still recorded as live: nothing but the skip
// stands between a stale binding and a deletion.
func TestMaintenanceSkipsSweepWhenRevalidationFails(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	n := c.Nodes[0]

	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24")
	failBindingWrites(t, n)

	if err := n.Server.RunNetBoxMaintenanceOnce(context.Background()); err == nil {
		t.Fatal("a pass that could not record a suspension must report the failure, not swallow it")
	}

	// The control: the binding is STILL LIVE, so the sweeper's own
	// suspended-binding guard is not what protected the address here.
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the suspension write was supposed to fail; this scenario proves nothing about the sweep otherwise")
	}
	if len(nb.Identities()) != 1 {
		t.Fatalf("bindings that could not be validated must not be swept against, released %v", nb.Released())
	}
}

// TestMaintenanceDoesNotRunWithoutNetBoxConfig pins that an unconfigured node
// starts nothing at all.
//
// Not a micro-optimisation: the sweeper elects a single cluster-wide leader
// through the `netbox` lease, and a node that cannot read NetBox has no
// standing to hold it.
func TestMaintenanceDoesNotRunWithoutNetBoxConfig(t *testing.T) {
	c := New(t, Options{Nodes: 1}) // no netbox config

	if c.Nodes[0].NetBoxMaintenanceRunning() {
		t.Fatal("no netbox config must mean no loop, no goroutine, no lease contention")
	}
}

// TestMaintenanceRunsWhenNetBoxIsConfigured is the control for the test above:
// without it, wiring that started the loop for nobody would pass.
func TestMaintenanceRunsWhenNetBoxIsConfigured(t *testing.T) {
	_, c := boundCluster(t, 1)

	if !c.Nodes[0].NetBoxMaintenanceRunning() {
		t.Fatal("a node configured for NetBox must run the maintenance loop")
	}
}
