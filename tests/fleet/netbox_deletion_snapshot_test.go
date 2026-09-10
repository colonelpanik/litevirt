package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// TestIndependentCorroborationMustCoverTheDeletionSnapshot is the regression for
// a proof that certified the wrong state.
//
// The mirror reads its desired state and its removal evidence, diffs them
// against NetBox, and only then finds a removal resting on a mapping row alone —
// the one record that identifies an incarnation without saying whether it
// stopped existing. The corroboration it asked at that point sampled FRESH
// digests, so it answered about the inventory as it stood at the END of the
// pass. The plan came from the inventory as it stood at the start.
//
// The gap is one replicated row wide: the target's `vms` row lands mid-pass,
// every peer agrees about the now-complete inventory, the proof succeeds, and
// the OLD plan executes — deleting a live VM's NetBox object and reporting
// convergence. A separately sampled boolean cannot establish a relationship to a
// plan it never saw.
//
// So the pass samples the inventory BEFORE it reads anything and asks a proof
// BOUND to that sample. Driven through the real client, the real sampler and the
// production peer fan-out, with the write landing in the window the binding
// defends.
func TestIndependentCorroborationMustCoverTheDeletionSnapshot(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)
	n := c.Nodes[0]
	ctx := context.Background()
	mustCreateVM(t, n, "keeper", orphanNetwork)
	mustSyncAllNodes(t, c)
	const lateUUID = "12345678-1234-4234-8234-123456789abc"
	identity := netbox.Identity(clusterFP(t, n), lateUUID, "")
	id := nb.SeedVM("late", nb.ClusterID("fleet"), identity)
	if err := corrosion.PutObjectRef(ctx, n.DB, corrosion.ObjectRef{
		LitevirtKind: "vm", LitevirtKey: identity, NetBoxKind: "virtual_machine", NetBoxID: id,
	}); err != nil {
		t.Fatal(err)
	}
	always := func(context.Context) bool { return true }
	// The PRODUCTION sampler, taken when a pass takes it, wrapped so the
	// replicated row lands between the sample and the question — which is where
	// it landed in production, and the whole of what the binding is about.
	latecomer := &writeBeforeAsking{
		write: func() {
			// This production row write represents replication completing after
			// desired state and removal evidence were read, but before the proof
			// is asked. The shared DB makes both real peers agree about it.
			if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
				Name: "late", HostName: c.Nodes[1].Name, State: "running",
				Spec: `{"uuid":"` + lateUUID + `","cpu":1,"memory_mib":512}`,
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
		},
	}
	r := netboxsync.New(netboxsync.Options{
		NetBox: netboxClientFor(t, nb), DB: n.DB, ClusterName: "fleet",
		AcquireLease: always, HoldsLease: always, Latched: always,
		InventorySnapshot: func(ctx context.Context) netboxsync.InventoryProof {
			latecomer.bound = n.Server.NetBoxInventorySnapshotOnce(ctx)
			return latecomer
		},
	})
	err := r.SyncOnce(ctx)

	if !latecomer.asked {
		t.Fatalf("the pass never reached the corroboration, so this scenario proves nothing "+
			"about it: err=%v", err)
	}
	vm, readErr := corrosion.GetVM(ctx, n.DB, "late")
	if readErr != nil || vm == nil || vm.State != "running" {
		t.Fatalf("the live row must now exist: vm=%+v err=%v", vm, readErr)
	}
	if nb.VMIdentity(id) != identity {
		t.Fatalf("corroboration of the NEW complete inventory authorized deleting a live VM "+
			"from the OLD incomplete plan: netbox ID=%d identity=%q err=%v",
			id, nb.VMIdentity(id), err)
	}
	// …and it was withheld by THE BINDING, not by some bystander gate: the
	// production proof has to say the inventory moved out from under the read
	// this pass was computed from. Every peer in this fixture shares one
	// database, so peer AGREEMENT is never what withholds here — without the
	// binding they agree perfectly about the row that just landed.
	if latecomer.ok || !strings.Contains(latecomer.why, "rows changed while the proof was being taken") {
		t.Fatalf("the corroboration answered ok=%v why=%q; the pass must be withheld because "+
			"the inventory the plan was read from is no longer this node's own read",
			latecomer.ok, latecomer.why)
	}
}

// writeBeforeAsking is the production inventory proof with a replicated write
// landing immediately before the question is put to it.
//
// It models the one ordering the binding exists for and nothing else: the sample
// is the production sampler's, the answer is the production corroboration's, and
// what this contributes is the moment the row arrives.
type writeBeforeAsking struct {
	bound netboxsync.InventoryProof
	write func()
	asked bool
	ok    bool
	why   string
}

func (w *writeBeforeAsking) Corroborated(ctx context.Context) (bool, string) {
	w.asked = true
	w.write()
	w.ok, w.why = w.bound.Corroborated(ctx)
	return w.ok, w.why
}
