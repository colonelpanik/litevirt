package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A VM whose cutover handoff is still owed looks exactly like one that stopped
// out of band: the row says running, and no domain answers to the name because
// the replacement's domain has not been installed under it yet.
//
// Syncing that to "stopped" erases the running intent the journaled retry needs,
// and the retry then finishes the operation with the VM down. So the reconciler
// leaves it alone until the handoff is finished — the ordinary out-of-band stop,
// with no owed handoff, must still be synced.
func TestReconciler_LeavesAVMWithAnOwedCutoverHandoffAlone(t *testing.T) {
	ctx := context.Background()

	seed := func(t *testing.T, owed bool) *corrosion.Client {
		t.Helper()
		db := testReconcilerDB(t)
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "app", HostName: "host-a", Spec: `{}`, State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if !owed {
			return db
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "app-next", HostName: "host-a", Spec: `{}`, State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM replacement: %v", err)
		}
		next, err := corrosion.GetVM(ctx, db, "app-next")
		if err != nil || next == nil {
			t.Fatalf("read the replacement: %+v err=%v", next, err)
		}
		prepared, _, err := corrosion.PrepareVMReplace(ctx, db, corrosion.VMReplaceManifest{
			ReplacedVM: "app", Replacement: "app-next", HostName: "host-a",
			ReplacementIncarnation: next.CreatedAt, ReplacementUUID: "next-uuid",
			ReplacementSpec: next.Spec, ReplacementState: "running",
		}, next.OwnerEpoch)
		if err != nil {
			t.Fatalf("PrepareVMReplace: %v", err)
		}
		// The transition committed; the handoff has not run.
		// The step the transition writes in its own batch; recorded directly here
		// because the batch is not what this test drives.
		if err := corrosion.AppendOperationStep(ctx, db, corrosion.OperationStepRecord{
			OperationID: prepared.OperationID, OwnerEpoch: prepared.OwnerEpoch,
			StepName: corrosion.OpStepDesiredPersisted,
		}); err != nil {
			t.Fatalf("record the committed transition: %v", err)
		}
		return db
	}

	for _, tc := range []struct {
		name string
		owed bool
		want string
	}{
		{"handoff owed — left alone", true, "running"},
		{"no handoff owed — synced", false, "stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := seed(t, tc.owed)
			// The domain is DEFINED but shut off — what both an unfinished handoff
			// and an ordinary out-of-band stop look like from here.
			fake := libvirtfake.New()
			if err := fake.DefineDomain(`<domain><name>app</name></domain>`); err != nil {
				t.Fatal(err)
			}
			r := NewReconciler("host-a", t.TempDir(), db, fake)
			r.reconcile(ctx)

			vm, err := corrosion.GetVM(ctx, db, "app")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %+v err=%v", vm, err)
			}
			if vm.State != tc.want {
				t.Fatalf("state = %q, want %q", vm.State, tc.want)
			}
		})
	}
}
