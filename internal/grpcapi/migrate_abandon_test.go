package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func seedMigratingVM(t *testing.T, s *Server, name string) *corrosion.VMRecord {
	t.Helper()
	ctx := adminCtx()
	// Seeded in `migrating`, which is where the real RPC leaves it before
	// MigrateToTarget blocks — and the state the reconciler explicitly skips.
	// Seeding "running" would make every "must not still be migrating"
	// assertion below pass without the code doing anything.
	insertTestVM(t, ctx, s.db, name, "test-host", "migrating")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	return vm
}

// TestAdoptAbandonedMigration_CommitsOwnershipWhenLibvirtFinishes is the #194
// regression.
//
// MigrateToTarget takes no context and blocks in libvirt regardless, so on
// Ctrl-C or a migrate timeout the handler returned bare: no state update, no
// artifact cleanup, no ownership finalize, and the per-VM lock dropped
// mid-flight. libvirt then completed with
// MigratePersistDest|MigrateUndefineSource, so the guest ran on the TARGET
// while corrosion still said host_name=source, state=migrating. Nothing healed
// it — the reconciler explicitly continues on `migrating`.
//
// Abandoning the wait is fine; abandoning the OUTCOME is not. The migration is
// adopted onto a detached context that finishes the commit when libvirt does.
func TestAdoptAbandonedMigration_CommitsOwnershipWhenLibvirtFinishes(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	vm := seedMigratingVM(t, s, "mig1")

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) })

	done <- nil // libvirt cut over successfully

	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted migration never released the per-VM lock")
	}

	got, err := corrosion.GetVM(adminCtx(), s.db, "mig1")
	if err != nil || got == nil {
		t.Fatalf("GetVM: %+v %v", got, err)
	}
	if got.HostName != "h2" {
		t.Errorf("host_name = %q, want h2 — libvirt cut the guest over to the "+
			"target and the record still points at the source; the guest runs on "+
			"h2 while the cluster believes it is on test-host", got.HostName)
	}
	if got.State == "migrating" {
		t.Errorf("state is still %q; the reconciler skips `migrating`, so nothing "+
			"will ever heal this", got.State)
	}
}

// When libvirt reports a FAILURE, the VM stays on the source — and must not be
// left in `migrating`, which is the state nothing heals.
func TestAdoptAbandonedMigration_LeavesTheVMOnTheSourceWhenLibvirtFails(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	vm := seedMigratingVM(t, s, "mig2")

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) })

	done <- errors.New("injected libvirt migration failure")

	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted migration never released the per-VM lock")
	}

	got, err := corrosion.GetVM(adminCtx(), s.db, "mig2")
	if err != nil || got == nil {
		t.Fatalf("GetVM: %+v %v", got, err)
	}
	if got.HostName != "test-host" {
		t.Errorf("host_name = %q, want test-host — the migration failed", got.HostName)
	}
	if got.State == "migrating" {
		t.Errorf("state is still %q after a failed adopted migration; nothing "+
			"heals `migrating`", got.State)
	}
}

// The lock must be released even if the outcome handling itself errors, or one
// abandoned migration wedges every later operation on that VM.
func TestAdoptAbandonedMigration_AlwaysReleasesTheLock(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	// A VM record that vanished mid-migration: the commit cannot succeed.
	vm := &corrosion.VMRecord{Name: "ghost", HostName: "test-host", State: "migrating"}

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) })
	done <- nil

	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not released when the adopted migration could not finalize")
	}
}
