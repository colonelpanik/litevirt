package grpcapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestMigrateVM_LibvirtFailureRestoresTheRowAfterTheClientGoesAway: libvirt
// fails the migration — the guest is still on the source — and the client goes
// away at that very moment. The row must still come back out of `migrating`:
// nothing else heals that state (the reconciler and owner-assert skip it, and a
// retry is refused because the VM is not running).
//
// The failure branch used to restore the row on the request context, so a
// cancellation landing between libvirt's error and the state write dropped the
// write and stranded the VM `migrating` while it ran on, untouched, here.
//
// Deterministic: the request is cancelled from inside the restore's own
// domain-state probe — after libvirt's error has been taken off `done`, and
// before the row is written. Cancelling earlier would race the select against
// migrateCtx.Done() and could take the (already detached) adopter path instead.
//
// Mutation: pass the request ctx back to restoreSourceStateAfterFailedMigration
// in MigrateVM's `case migrateErr := <-done` branch — red.
func TestMigrateVM_LibvirtFailureRestoresTheRowAfterTheClientGoesAway(t *testing.T) {
	const name = "fail-cancel-vm"
	s, _, fake := abortTestServer(t, name)
	reqCtx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	var migrateFailed, cancelledInRestore atomic.Bool
	fake.FailMigrateToTarget = func(string, string) error {
		migrateFailed.Store(true)
		return errors.New("injected libvirt migrate failure")
	}
	fake.FailDomainState = func(n string) error {
		// The first state probe after libvirt failed is the restore's.
		if n == name && migrateFailed.Load() && cancelledInRestore.CompareAndSwap(false, true) {
			cancel()
		}
		return nil
	}

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName: name, TargetHost: "target-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, &mockMigrateStream{ctx: reqCtx})
	if err == nil {
		t.Fatal("the migration succeeded; the scenario needs libvirt to fail it")
	}
	if !migrateFailed.Load() {
		t.Fatalf("libvirt was never asked to migrate (err %v) — this scenario proves nothing", err)
	}
	if !cancelledInRestore.Load() {
		t.Fatal("the request was never cancelled during the restore — this scenario proves nothing")
	}

	ctx := adminCtx()
	vm, gerr := corrosion.GetVM(ctx, s.db, name)
	if gerr != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, gerr)
	}
	if vm.State != "running" || vm.HostName != "test-host" {
		t.Fatalf("after libvirt failed and the client went away the VM is %q on %q, want running on "+
			"test-host — the restore ran on the cancelled request context", vm.State, vm.HostName)
	}
}
