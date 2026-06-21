package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestReconcile_BackingUpPreservedWhileBackupActive: the reconciler must NOT
// clear a "backing-up" state row when a backup is genuinely in flight on this
// host (the injected predicate returns true). Guards against clobbering a live
// backup's deletion-protection flag.
func TestReconcile_BackingUpPreservedWhileBackupActive(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "bk-vm", HostName: "host-a", Spec: "{}", State: "backing-up",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", t.TempDir(), db, nil)
	r.SetBackupInProgress(func(string) bool { return true }) // backup live here

	r.reconcile(ctx)

	vm, err := corrosion.GetVM(ctx, db, "bk-vm")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "backing-up" {
		t.Fatalf("live backup: state should stay backing-up, got %q", vm.State)
	}
}
