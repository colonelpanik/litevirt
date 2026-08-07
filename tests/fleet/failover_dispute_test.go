// Fleet scenario: failover must not recover a workload whose ownership is in
// dispute.
//
// A fenced host is only ONE of an ownership condition's holders — the other
// side may still be live on an unfenced host. If the coordinator reschedules
// (or promotes) the disputed workload onto a third host, automated recovery
// manufactures exactly the dual-writer the condition was raised to prevent.
//
// Three nodes, shared CRDT. The victim holds two VMs and one relocatable
// container; one VM and the container carry an active ownership condition.
// After the coordinator fences the victim:
//   - the clean VM is rescheduled to a healthy host
//   - the disputed VM stays on the fenced host, untouched
//   - the disputed container stays on the fenced host, untouched
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

func TestFleet_Failover_RefusesDisputedWorkload(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, observer := range []string{a.Name, b.Name} {
		if err := a.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`,
			observer, victim.Name, nowRFC,
		); err != nil {
			t.Fatalf("insert health %s: %v", observer, err)
		}
	}

	for _, vm := range []string{"vm-clean", "vm-disputed"} {
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
			Name:     vm,
			HostName: victim.Name,
			Spec:     `{"on_host_failure":"restart-any"}`,
			State:    "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm, err)
		}
	}
	if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
		HostName: victim.Name, Name: "ct-disputed", State: "running",
		Image: "alpine:3.21", OnHostFailure: "relocate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	// vm-disputed is dual-running between the victim and node-b; ct-disputed
	// likewise. Note node-b is NOT fenced — recovery would add a third writer.
	for _, cond := range []corrosion.HealthCondition{
		{Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm-disputed",
			Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
			Hosts: []string{victim.Name, b.Name}, FirstSeen: nowRFC, LastSeen: nowRFC},
		{Evaluator: "dual_run", Code: "ct_dual_run", SubjectKind: "container", SubjectID: "ct-disputed",
			Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
			Hosts: []string{victim.Name, b.Name}, FirstSeen: nowRFC, LastSeen: nowRFC},
	} {
		if err := corrosion.UpsertHealthCondition(ctx, a.DB, cond); err != nil {
			t.Fatalf("seed condition %s: %v", cond.SubjectID, err)
		}
	}

	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RunOnce(ctx)

	vrec, _ := corrosion.GetHost(ctx, a.DB, victim.Name)
	if vrec == nil || vrec.State == "active" {
		t.Fatalf("victim should have been fenced: %+v", vrec)
	}

	clean, _ := corrosion.GetVM(ctx, a.DB, "vm-clean")
	if clean == nil || clean.HostName == victim.Name {
		t.Errorf("clean VM must be rescheduled off the fenced host: %+v", clean)
	}
	disputed, _ := corrosion.GetVM(ctx, a.DB, "vm-disputed")
	if disputed == nil {
		t.Fatal("disputed VM disappeared")
	}
	if disputed.HostName != victim.Name {
		t.Errorf("disputed VM was recovered to %q — automated recovery must refuse a "+
			"workload with an active ownership condition", disputed.HostName)
	}
	ct, _ := corrosion.GetContainer(ctx, a.DB, victim.Name, "ct-disputed")
	if ct == nil {
		t.Fatal("disputed container row disappeared from the fenced host")
	}
	if ct.State == "relocating" || ct.StateDetail != "" {
		t.Errorf("disputed container must not be relocated: state=%q detail=%q", ct.State, ct.StateDetail)
	}
}
