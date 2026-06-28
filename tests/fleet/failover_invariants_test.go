package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedHealth writes quorum health rows: each observer reports target with
// `fails` consecutive failures, stamped updated_at (RFC3339 — the coordinator's
// freshness gate compares against an RFC3339 cutoff).
func seedHealth(t *testing.T, n *Node, observers []string, target string, fails int, updatedAt string) {
	t.Helper()
	ctx := context.Background()
	for _, obs := range observers {
		if err := n.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', ?, NULL, ?)`,
			obs, target, fails, updatedAt); err != nil {
			t.Fatalf("seed health %s->%s: %v", obs, target, err)
		}
	}
}

// TestFleet_StaleHealthDoesNotFence proves invariant (d): host_health rows older
// than the 30s freshness window do NOT satisfy quorum, so a coordinator must not
// fence a host whose failure is only attested by stale observers. A fresh re-seed
// (the control) then does fence, isolating freshness as the deciding factor.
func TestFleet_StaleHealthDoesNotFence(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	now := time.Now().UTC()

	// Two observers report victim down, but with a STALE timestamp (> 30s old).
	seedHealth(t, a, []string{a.Name, b.Name}, victim.Name, 5, now.Add(-2*time.Minute).Format(time.RFC3339))
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-stale", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	var fences atomic.Int32
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.Now = func() time.Time { return now }
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences.Add(1)
		return fence.Result{Method: "fleet-test", Success: true}
	})

	coord.RunOnce(ctx)
	if fences.Load() != 0 {
		t.Fatalf("stale health rows must not satisfy quorum, but %d fence(s) fired", fences.Load())
	}
	if vrec, _ := corrosion.GetHost(ctx, a.DB, victim.Name); vrec == nil || vrec.State != "active" {
		t.Fatalf("victim should remain active under stale health, got %+v", vrec)
	}

	// Control: refresh the same rows → now within the freshness window → fence.
	seedHealth(t, a, []string{a.Name, b.Name}, victim.Name, 5, now.Format(time.RFC3339))
	coord.RunOnce(ctx)
	if fences.Load() != 1 {
		t.Fatalf("fresh quorum should fence exactly once, got %d", fences.Load())
	}
}

// TestFleet_OneOwnerAfterHeal proves invariant (e): after the coordinator fences a
// host and reassigns its VM to a survivor, the fenced host's reconciler — once it
// can run again (heal) — self-fences the stale local domain that moved away, so
// exactly one owner remains. This is the integrated quorum→fence→reassign→
// self-fence path, not the lock arbitrating a partition.
func TestFleet_OneOwnerAfterHeal(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	now := time.Now().UTC()

	// VM running on victim, both in cluster state and in victim's local libvirt.
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-own", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	victim.Virt.SetState("vm-own", libvirtfake.StateRunning)

	seedHealth(t, a, []string{a.Name, b.Name}, victim.Name, 5, now.Format(time.RFC3339))

	// Coordinator on node-a fences victim and reassigns vm-own to a survivor.
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.Now = func() time.Time { return now }
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)

	vmAfter, _ := corrosion.GetVM(ctx, a.DB, "vm-own")
	if vmAfter == nil || vmAfter.HostName == victim.Name {
		t.Fatalf("vm-own should have been reassigned off the fenced victim, got %+v", vmAfter)
	}
	survivor := c.Node(vmAfter.HostName)

	// Model the partition+heal split-brain: the survivor's reconciler has already
	// started vm-own (so it runs there), while the victim's stale copy is STILL
	// running locally — two running copies at the instant of heal.
	survivor.Virt.SetState("vm-own", libvirtfake.StateRunning)

	// Heal: the victim's reconciler runs and finds vm-own running locally but owned
	// (in corrosion) by the survivor → it self-fences ONLY its own stale copy.
	rec := health.NewReconciler(victim.Name, t.TempDir(), victim.DB, victim.Virt)
	rec.ReconcileOnce(ctx)

	if victim.Virt.DomainExists("vm-own") {
		t.Fatal("fenced victim must self-fence its stale local domain after the VM was reassigned")
	}

	// Exactly one owner remains, and it's the DB-owner (the survivor) — not zero,
	// not two.
	var owners []string
	for _, n := range c.Nodes {
		if n.Virt.DomainExists("vm-own") {
			owners = append(owners, n.Name)
		}
	}
	if len(owners) != 1 || owners[0] != vmAfter.HostName {
		t.Fatalf("expected exactly one running owner == %s, got %v", vmAfter.HostName, owners)
	}
}
