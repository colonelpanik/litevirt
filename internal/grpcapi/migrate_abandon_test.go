package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
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
		func() { close(unlocked) }, migrationFinish{})

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
		func() { close(unlocked) }, migrationFinish{})

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
		func() { close(unlocked) }, migrationFinish{})
	done <- nil

	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not released when the adopted migration could not finalize")
	}
}

type cleanupRecordingPeer struct {
	pb.LiteVirtClient
	calls chan *pb.CleanupMigrationArtifactsRequest
}

func (p cleanupRecordingPeer) CleanupMigrationArtifacts(_ context.Context, r *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.calls <- r
	return &emptypb.Empty{}, nil
}

func finishFor(s *Server, vm *corrosion.VMRecord) migrationFinish {
	return migrationFinish{
		target: &corrosion.HostRecord{Name: "h2", Address: "10.0.0.2", GRPCPort: 7443},
		pbVM:   &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_RUNNING},
		hspec:  vmHooks(vm),
	}
}

// An adopted migration that cuts over finishes like any other: the source's
// leftovers are cleaned up, VFs re-attached, DNS, FDB and LB brought over, the
// target told. It used to commit ownership and stop — the guest lost its SR-IOV
// NICs, VXLAN traffic went to the old host's VTEP, and source files leaked.
func TestAdoptAbandonedMigration_ACutOverRunsTheWholeFinish(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	vm := seedMigratingVM(t, s, "mig4")
	iso := filepath.Join(s.dataDir, "cloudinit", "mig4.iso")
	if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) }, finishFor(s, vm))
	done <- nil
	<-unlocked

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(iso); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the source's cloud-init ISO is still there: the adopted cut-over skipped the post-migration finish")
}

// A failed adopted migration removes the stubs it pre-created on the target, as
// the watched failure does. Left behind, they leak space and shadow a retry.
func TestAdoptAbandonedMigration_AFailureCleansTheTarget(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	vm := seedMigratingVM(t, s, "mig5")
	peer := cleanupRecordingPeer{calls: make(chan *pb.CleanupMigrationArtifactsRequest, 1)}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return peer, func() {}, nil
	}

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) }, finishFor(s, vm))
	done <- errors.New("injected libvirt migration failure")
	<-unlocked

	select {
	case r := <-peer.calls:
		if r.GetVmName() != "mig5" {
			t.Errorf("cleaned up %q on the target, want mig5", r.GetVmName())
		}
	default:
		t.Fatal("a failed adopted migration left its pre-created artifacts on the target")
	}
}

// An adopted migration that never ends is aborted, so the per-VM lock is not
// held forever. MigrateToTarget takes no context; a live migration whose dirty
// rate beats the bandwidth never converges, and every later stop, delete,
// snapshot or migrate on that VM blocked behind it.
func TestAdoptAbandonedMigration_OneThatNeverEndsIsAborted(t *testing.T) {
	prev := adoptedMigrationCeiling
	adoptedMigrationCeiling = 100 * time.Millisecond
	t.Cleanup(func() { adoptedMigrationCeiling = prev })
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	vm := seedMigratingVM(t, s, "mig6")

	done := make(chan error, 1)
	fake.OnAbortMigration = func(string) { done <- errors.New("migration aborted") }
	unlocked := make(chan struct{})
	s.adoptAbandonedMigration(context.Background(), vm, "h2", false, nil, done,
		func() { close(unlocked) }, finishFor(s, vm))

	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("an adopted migration that never ended was never aborted; the per-VM lock is held forever")
	}
	if n := fake.AbortedMigrations("mig6"); n != 1 {
		t.Errorf("aborted %d time(s), want 1", n)
	}
}

// The migrate timeout aborts the job; a client that merely stopped listening
// does not. timeout_sec is a policy on the operation — "give up after N" — and
// ignoring it left a non-converging migration running with the lock held. A
// disconnect is not a policy; the migration is adopted and allowed to finish.
func TestAbortOnMigrateTimeout(t *testing.T) {
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake

	parent := context.Background()
	timed, cancel := context.WithTimeout(parent, time.Nanosecond)
	defer cancel()
	<-timed.Done()
	s.abortOnMigrateTimeout(parent, timed, "vm-timeout")
	if fake.AbortedMigrations("vm-timeout") != 1 {
		t.Error("the migrate timeout fired but the libvirt job was not aborted")
	}

	gone, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	s.abortOnMigrateTimeout(gone, gone, "vm-disconnect")
	if fake.AbortedMigrations("vm-disconnect") != 0 {
		t.Error("a client disconnect aborted the migration; it should be adopted and finish")
	}
}
