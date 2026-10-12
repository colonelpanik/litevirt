package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// quorumLossGate is an enforced split-brain gate whose execution gate holds
// until lost is set — the source losing quorum partway through a migration.
type quorumLossGate struct {
	fakeServerGate
	lost *atomic.Bool
}

func (g quorumLossGate) ExecutionGate(context.Context) health.GateResult {
	if g.lost.Load() {
		return health.GateResult{OK: false, Reason: health.ReasonNoQuorum}
	}
	return health.GateResult{OK: true}
}

// admissionHookDest is the always-admitting destination with a hook that runs
// when the source asks it for capacity — after the early gate, before any VF
// is touched.
type admissionHookDest struct {
	*cleanupCountingDest
	onReserve func()
}

func (d *admissionHookDest) ReserveHostCapacity(ctx context.Context, req *pb.ReserveHostCapacityRequest, opts ...grpc.CallOption) (*pb.ReserveHostCapacityResponse, error) {
	if d.onReserve != nil {
		d.onReserve()
	}
	return d.cleanupCountingDest.ReserveHostCapacity(ctx, req, opts...)
}

type vfRig struct {
	s    *Server
	fake *libvirtfake.Fake
	fs   *pciUnbindRecordingFS
	dest *admissionHookDest
	vfs  []string
}

// vfMigrationRig is a running VM on test-host holding the given SR-IOV VFs:
// owned by it in host inventory, bound to vfio-pci, and in its live domain.
func vfMigrationRig(t *testing.T, vfs ...string) *vfRig {
	t.Helper()
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	dest := &admissionHookDest{cleanupCountingDest: &cleanupCountingDest{fakeDestPeer: &fakeDestPeer{leaseID: "dest-lease-1"}}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return dest, func() {}, nil
	}
	fs := newPCIUnbindRecordingFS()
	t.Cleanup(vfio.SetFS(fs))

	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "vf-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "target-host", "active")
	fake.SetState("vf-vm", "running")
	for _, a := range vfs {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: a, Type: "net", VendorID: "8086", VMName: "vf-vm",
		}); err != nil {
			t.Fatalf("seed VF %s: %v", a, err)
		}
		fs.setVF(a)
		fs.setBound(a)
		if err := fake.AttachHostdev("vf-vm", a); err != nil {
			t.Fatalf("seed VF %s in the guest: %v", a, err)
		}
	}
	return &vfRig{s: s, fake: fake, fs: fs, dest: dest, vfs: vfs}
}

func (r *vfRig) migrate(t *testing.T) error {
	t.Helper()
	return r.s.MigrateVM(&pb.MigrateVMRequest{
		VmName: "vf-vm", TargetHost: "target-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, &mockMigrateStream{ctx: adminCtx()})
}

// assertVFsHome fails unless every VF is back where it started: owned by the
// VM, bound to vfio-pci, and in its live domain.
func (r *vfRig) assertVFsHome(t *testing.T, why string) {
	t.Helper()
	for _, a := range r.vfs {
		if o := pciOwnerOf(t, adminCtx(), r.s, a); o != "vf-vm" {
			t.Errorf("%s: VF %s is owned by %q, want vf-vm — released, any VM can claim it", why, a, o)
		}
		if !r.fs.isBound(a) {
			t.Errorf("%s: VF %s is not bound to vfio-pci", why, a)
		}
		if !guestHasHostdev(t, r.s, "vf-vm", a) {
			t.Errorf("%s: VF %s is not in the guest — it is running on the source without its NIC", why, a)
		}
	}
	vm, err := corrosion.GetVM(adminCtx(), r.s.db, "vf-vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	if vm.State != "running" || vm.HostName != "test-host" {
		t.Errorf("%s: VM is %q on %q, want running on test-host", why, vm.State, vm.HostName)
	}
}

// TestMigrateVM_ALateGateRefusalKeepsTheVFs: the source loses quorum while the
// migration is being set up. The late split-brain gate refuses the move — and
// the guest, which is staying, must still have its SR-IOV VFs.
//
// The VFs used to be hot-detached and released before that gate. A refusal
// returned with the guest running on the source without its passthrough NIC,
// and with the VF's ownership released, so another VM could claim it.
func TestMigrateVM_ALateGateRefusalKeepsTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	var lost atomic.Bool
	r.s.SetGate(quorumLossGate{
		fakeServerGate: fakeServerGate{enforcedTok: map[string]bool{capabilities.SplitBrainGateV1: true}},
		lost:           &lost,
	})
	r.dest.onReserve = func() { lost.Store(true) } // quorum goes during setup

	err := r.migrate(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "migration refused") {
		t.Fatalf("got %v, want the late gate's FailedPrecondition \"migration refused\"", err)
	}
	r.assertVFsHome(t, "after a late gate refusal")
}

// TestMigrateVM_ALibvirtFailureReattachesTheVFs: libvirt fails the migration
// after the VFs were detached for it. The guest stays on the source, so its
// VFs go back into it, owned by it again.
//
// reattachVFsOnTarget runs only after a cutover; a failed copy used to leave
// the guest without its NIC and the VFs free for any VM to claim.
func TestMigrateVM_ALibvirtFailureReattachesTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0", "0000:41:10.1")
	r.fake.FailMigrateToTarget = func(string, string) error {
		// The detach really happened: libvirt is asked to move a guest that no
		// longer holds the VFs, and they are free.
		for _, a := range r.vfs {
			if guestHasHostdev(t, r.s, "vf-vm", a) {
				t.Errorf("VF %s still in the guest when libvirt was asked to migrate it", a)
			}
			if o := pciOwnerOf(t, adminCtx(), r.s, a); o != "" {
				t.Errorf("VF %s still owned by %q when libvirt was asked to migrate", a, o)
			}
		}
		return errors.New("injected libvirt migration failure")
	}

	if err := r.migrate(t); err == nil {
		t.Fatal("the migration succeeded; the scenario needs libvirt to fail it")
	}
	r.assertVFsHome(t, "after libvirt failed the migration")
}

// TestMigrateVM_AFailedDetachReattachesTheVFsAlreadyDetached: the second VF
// cannot be detached, so the migration stops. The first was already detached
// and released, and goes back.
func TestMigrateVM_AFailedDetachReattachesTheVFsAlreadyDetached(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0", "0000:41:10.1")
	r.fake.FailDetachHostdev = func(_, addr string) error {
		if addr == "0000:41:10.1" {
			return fmt.Errorf("injected detach failure for %s", addr)
		}
		return nil
	}

	err := r.migrate(t)
	if err == nil || !strings.Contains(err.Error(), "detach VF 0000:41:10.1") {
		t.Fatalf("got %v, want the second VF's detach failure", err)
	}
	r.assertVFsHome(t, "after the second VF failed to detach")
}

// TestAdoptAbandonedMigration_AFailureReattachesTheVFs: the client stopped
// watching and the adopted migration then failed. The guest is still on the
// source, so it gets its VFs back, as a watched failure does.
func TestAdoptAbandonedMigration_AFailureReattachesTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	ctx := adminCtx()
	// Where MigrateVM leaves things when libvirt takes over: VFs detached and
	// released, the row `migrating`.
	for _, a := range r.vfs {
		if err := r.s.detachHostdevIfPresent("vf-vm", a); err != nil {
			t.Fatal(err)
		}
		if err := r.s.unbindAndReleaseOwnership(ctx, "vf-vm", []string{a}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpdateVMState(ctx, r.s.db, "vf-vm", "migrating", "→ target-host"); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, r.s.db, "vf-vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	var detached []corrosion.PCIDeviceRecord
	for _, a := range r.vfs {
		detached = append(detached, corrosion.PCIDeviceRecord{HostName: "test-host", Address: a, Type: "net", VendorID: "8086"})
	}

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	r.s.adoptAbandonedMigration(context.Background(), vm, "target-host", false, nil, done,
		func() { close(unlocked) }, migrationFinish{
			target:      &corrosion.HostRecord{Name: "target-host", Address: "10.0.0.1", GRPCPort: 7443},
			detachedVFs: detached,
		})
	done <- errors.New("injected libvirt migration failure")
	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted migration never finished")
	}
	r.assertVFsHome(t, "after the adopted migration failed")
}
