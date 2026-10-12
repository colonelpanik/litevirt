// Fleet scenario for colonelpanik/litevirt#157: a new VM is never published
// running at the pre-epoch generation 0.
//
// Every create path inserts its row "creating", assigns the first owner epoch,
// stamps both runtime markers, and only then flips the row to "running". When
// the finish fails, the row stays "creating" with the guest running, and the
// owner's reconciler finishes it. With that ordering there is no newborn window,
// so the dual-run detector has no newborn grace: it pages an epoch-0 runtime on
// its owner at once, and a normal create must give it nothing to page.
package fleet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// ownerEpochOnlyGate is a serverGate with exactly owner_epoch_v1 latched —
// the token that switches the detector's owner-epoch check on — and quorum
// present. Nothing else is enforced, so the create path runs as it does on a
// default cluster.
type ownerEpochOnlyGate struct{}

func (ownerEpochOnlyGate) ExecutionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (ownerEpochOnlyGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (ownerEpochOnlyGate) CapabilityActive(_ context.Context, token string) (bool, string) {
	return token == capabilities.OwnerEpochV1, ""
}
func (ownerEpochOnlyGate) CapabilityActiveForHealth(_ context.Context, token string) (bool, string) {
	return token == capabilities.OwnerEpochV1, ""
}
func (ownerEpochOnlyGate) Enforced(_ context.Context, token string) bool {
	return token == capabilities.OwnerEpochV1
}
func (ownerEpochOnlyGate) Latched(token string) bool { return token == capabilities.OwnerEpochV1 }
func (ownerEpochOnlyGate) DurablyLatched(token string) bool {
	return token == capabilities.OwnerEpochV1
}
func (ownerEpochOnlyGate) PeerSupportsFresh(context.Context, string, string) bool { return true }
func (ownerEpochOnlyGate) HealthyPeers(context.Context) []string                  { return nil }
func (ownerEpochOnlyGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 1, 1
}

// epochCondition reads the detector's owner_epoch_mismatch condition for vm.
func epochCondition(t *testing.T, n *Node, vm string) (corrosion.HealthCondition, bool) {
	t.Helper()
	h, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, "dual_run", "owner_epoch_mismatch", "vm", vm)
	if err != nil {
		t.Fatalf("GetHealthCondition(%s): %v", vm, err)
	}
	return h, ok
}

func TestFleet_Newborn_NeverPublishedRunningAtEpochZero(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a := c.Nodes[0]
	for _, n := range c.Nodes {
		n.Server.SetGate(ownerEpochOnlyGate{})
	}
	roomyHosts(t, c)
	ctx := context.Background()
	create := func(name string) {
		t.Helper()
		if _, err := c.SelfClient(a).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: a.Name},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
	}
	row := func(name string) *corrosion.VMRecord {
		t.Helper()
		vm, err := corrosion.GetVM(ctx, a.DB, name)
		if err != nil || vm == nil {
			t.Fatalf("GetVM %s: %v (row=%v)", name, err, vm)
		}
		return vm
	}

	// (1) A normal create is published running at a positive epoch.
	create("vm-ok")
	if vm := row("vm-ok"); vm.State != "running" || vm.OwnerEpoch < 1 {
		t.Fatalf("vm-ok: state=%q epoch=%d, want running at a positive epoch", vm.State, vm.OwnerEpoch)
	}

	// (2) A create whose graduation fails stays "creating" — not running at 0,
	// not torn down. The trigger fails only the UPDATE that names
	// vm_owner_epoch, so the insert lands and the graduation does not.
	if _, err := a.DB.DB().Exec(`CREATE TRIGGER fleet_fail_graduation
		BEFORE UPDATE OF vm_owner_epoch ON vms
		BEGIN SELECT RAISE(ABORT, 'injected graduation failure'); END`); err != nil {
		t.Fatalf("install graduation trigger: %v", err)
	}
	create("vm-stuck")
	if vm := row("vm-stuck"); vm.State != "creating" || vm.OwnerEpoch != 0 {
		t.Fatalf("vm-stuck: state=%q epoch=%d, want creating at 0 — a failed graduation must not "+
			"publish the VM running at epoch 0", vm.State, vm.OwnerEpoch)
	}
	if !a.Virt.DomainExists("vm-stuck") {
		t.Fatal("vm-stuck's domain was torn down; a failed graduation leaves it for the reconciler")
	}

	// (3) The detector, with no newborn grace, pages the stranded newborn — the
	// positive control that it is running and enforcing — and nothing for the
	// normal create, which it has examined on every one of the same passes.
	dctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); a.Server.RunDualRunDetector(dctx, 20*time.Millisecond) }()
	defer func() { stop(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if h, ok := epochCondition(t, a, "vm-stuck"); ok && h.Lifecycle == corrosion.ConditionConfirmed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the detector never confirmed owner_epoch_mismatch for a running epoch-0 row with " +
				"no marker — without that the check below proves nothing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	conds, err := corrosion.ListHealthConditions(ctx, a.DB, true)
	if err != nil {
		t.Fatalf("ListHealthConditions: %v", err)
	}
	for _, h := range conds {
		if h.SubjectID == "vm-ok" {
			t.Errorf("the detector raised %s (%s) for a normal create — a VM published only after it "+
				"is marked must give it nothing to page", h.Code, h.Lifecycle)
		}
	}

	// (4) The owner's reconciler finishes the stranded newborn once the fault
	// clears: graduated, marked, then published.
	if _, err := a.DB.DB().Exec(`DROP TRIGGER fleet_fail_graduation`); err != nil {
		t.Fatalf("drop graduation trigger: %v", err)
	}
	dataDir := filepath.Join(c.tmpRoot, a.Name, "data")
	health.NewReconciler(a.Name, dataDir, a.DB, a.Virt).ReconcileOnce(ctx)
	vm := row("vm-stuck")
	if vm.State != "running" || vm.OwnerEpoch != 1 {
		t.Fatalf("after the reconciler: state=%q epoch=%d, want running at 1", vm.State, vm.OwnerEpoch)
	}
	if epoch, ok, err := a.Virt.GetDomainOwnerEpoch("vm-stuck"); err != nil || !ok || epoch != 1 {
		t.Errorf("domain marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
	if epoch, ok, err := health.ReadVMOwnerEpochMarker(dataDir, "vm-stuck"); err != nil || !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}

	// (5) And the detector resolves it: the finished VM proves its generation.
	deadline = time.Now().Add(10 * time.Second)
	for {
		if h, ok := epochCondition(t, a, "vm-stuck"); ok && h.Lifecycle == corrosion.ConditionResolved {
			break
		}
		if time.Now().After(deadline) {
			h, _ := epochCondition(t, a, "vm-stuck")
			t.Fatalf("owner_epoch_mismatch for the finished VM never resolved (lifecycle %q)", h.Lifecycle)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
