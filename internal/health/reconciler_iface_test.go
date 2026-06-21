package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestStartPendingVM_InterfaceQueryError is the A5 regression: when the
// VM-interfaces query fails, the reconciler must fail the VM into "error"
// rather than starting it headless (with zero NICs).
//
// We force the query to fail by dropping vm_interfaces after inserting a
// disk-less pending VM, so reconcile reaches the interface lookup cleanly.
func TestStartPendingVM_InterfaceQueryError(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-net",
		HostName: "host-a",
		Spec:     `{"cpu":1,"memory":512}`,
		State:    "pending",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Make GetVMInterfaces fail. Everything reconcile touches before the
	// interface lookup (vms, vm_locks, vm_disks) is left intact.
	if err := db.Execute(ctx, `DROP TABLE vm_interfaces`); err != nil {
		t.Fatalf("drop vm_interfaces: %v", err)
	}

	// nil virt: with the fix we return before any libvirt use; without the fix
	// the swallowed error would let execution fall through toward domain setup.
	r := NewReconciler("host-a", t.TempDir(), db, nil)
	r.reconcile(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm-net")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Fatalf("expected VM state 'error' on interface-query failure, got %q (detail=%q)", vm.State, vm.StateDetail)
	}
	if !strings.Contains(strings.ToLower(vm.StateDetail), "interface") {
		t.Errorf("expected an interfaces-related error detail, got %q", vm.StateDetail)
	}
}
