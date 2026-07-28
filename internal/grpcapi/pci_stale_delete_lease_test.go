package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-22 Fix A: the DeleteVM "stale record" cleanup branch (local domain absent AND no peer
// has it) must RELEASE this host's PCI ownership BEFORE it tombstones the vms row. The domain
// can be gone out-of-band (crash mid-teardown, admin `virsh undefine`) while host_pci_devices
// ownership persists; tombstoning the row first would leave a stale owner of a now-deleted VM,
// blocking every future ClaimPCIDevice CAS on that BDF forever — the exact class the main
// delete path's FIX-21 gate fixed. releaseDevices is strict all-or-nothing and safe here (the
// domain is gone → no live guest): fail BEFORE the tombstone on its error (retryable).
func TestDeleteVM_StaleRecordWithOwnedPCI_ReleasesBeforeTombstone(t *testing.T) {
	const addr = "0000:41:00.0"

	// (a) Releasable device: the stale-record cleanup releases ownership, unbinds, and
	// tombstones the row.
	t.Run("releasable_releases_then_tombstones", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		s.images = image.NewStore(s.dataDir)
		s.images.Init()
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()

		// VM row on this host, but NO libvirt domain (never SetState) → DomainExists is false,
		// and no other active hosts are seeded → the peer probe finds none → stale-record branch.
		seedNICVM(t, s, "vm1", "stopped")
		seedPCIGPU(t, s, addr, -1)
		if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
			t.Fatalf("seed ownership: %v", err)
		}
		fs.setBound(addr)

		if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
			t.Fatalf("stale-record delete with a releasable device must complete: %v", err)
		}
		if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm != nil {
			t.Fatal("stale-record cleanup must tombstone the VM row")
		}
		// The whole point of Fix A: no stale owner of a deleted VM is left behind.
		if o := pciOwnerOf(t, ctx, s, addr); o != "" {
			t.Fatalf("stale-record cleanup must release device ownership before tombstoning, got owner %q", o)
		}
		if fs.isBound(addr) {
			t.Fatal("stale-record cleanup must vfio-unbind the released device")
		}
	})

	// (b) Unbind stuck: the release fails, so the cleanup must FAIL before tombstoning — the
	// row stays, the device stays owned + bound (no stale owner, no unowned+bound orphan), and
	// the delete is retryable.
	t.Run("unbind_fails_no_tombstone_no_stale_owner", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		s.images = image.NewStore(s.dataDir)
		s.images.Init()
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()

		seedNICVM(t, s, "vm1", "stopped")
		seedPCIGPU(t, s, addr, -1)
		if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
			t.Fatalf("seed ownership: %v", err)
		}
		fs.setBound(addr)
		fs.setFailUnbind(addr)

		if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err == nil {
			t.Fatal("stale-record cleanup must FAIL when a PCI device cannot be released (never tombstone over it)")
		}
		if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil {
			t.Fatal("a failed PCI release must NOT tombstone the VM row (cleanup must be retryable)")
		}
		if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
			t.Fatalf("device must stay OWNED by vm1 (no stale owner, no unowned+bound), got owner %q", o)
		}
		if !fs.isBound(addr) {
			t.Fatal("a failed unbind must leave the device still bound (owned + bound, recoverable)")
		}
	})
}

// FIX-25 Fix C (adapts FIX-22 Fix B): RecoverDeviceLeases' orphaned-lease (vm==nil) branch now
// delegates to the durable-lease-authorized reclaimLeasedDevices primitive. It must (a) RECLAIM
// an unowned+bound leaked BDF — after FIX-25 the normal unbindAndReleaseOwnership SKIPS an
// unowned addr, so the orphan reclaim of a genuinely leaked unowned device MUST go through the
// lease-authorized primitive or the leak would never be cleaned up — and (b) NOT unbind a BDF
// since legitimately reclaimed + bound by a DIFFERENT live VM (the DoesNotUnbindOtherVM property,
// preserved via the new primitive). In both cases the orphan lease entry is cleared.
func TestRecoverDeviceLeases_OrphanUnownedLeaked_Reclaims(t *testing.T) {
	// (a) The orphaned lease's BDF is UNOWNED + bound (a genuine leak by the dead VM). Recovery
	// must reclaim it: unbind the device and clear the lease. RED before FIX-25 (the branch
	// routed the unowned addr through unbindAndReleaseOwnership, which now skips it → leaked).
	t.Run("unowned_leaked_reclaimed", func(t *testing.T) {
		const addr = "0000:00:00.0"
		ctx := context.Background()
		s := testServer(t)
		j, _ := opjournal.Open(t.TempDir())
		s.SetOpJournal(j)

		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()

		// Inventory row present but UNOWNED, and the device is still bound to vfio-pci — the
		// leak a dead allocation left behind.
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: s.hostName, Address: addr, Type: "gpu", VMName: "",
		}); err != nil {
			t.Fatalf("seed unowned device: %v", err)
		}
		fs.setBound(addr)

		if err := j.Write(opjournal.Entry{OperationID: deviceLeaseOpID("orphan-vm"), ResourceID: "orphan-vm",
			Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": addr}}); err != nil {
			t.Fatalf("write orphan lease: %v", err)
		}

		s.RecoverDeviceLeases(ctx)

		if fs.unbindCount(addr) != 1 {
			t.Fatalf("orphan recovery must reclaim (unbind) the unowned leaked BDF once, got %d unbind(s)", fs.unbindCount(addr))
		}
		if fs.isBound(addr) {
			t.Fatal("orphan recovery must leave the reclaimed BDF unbound (no unowned+bound orphan)")
		}
		if _, found, _ := j.Read(deviceLeaseOpID("orphan-vm")); found {
			t.Fatal("orphan lease entry must be cleared after a successful reclaim")
		}
	})

	// (b) The orphaned lease's BDF was since legitimately reclaimed + bound by a DIFFERENT live
	// VM. Recovery must NOT unbind it (the reclaiming VM's passthrough survives) and still clear
	// the stale lease. Confirms the DoesNotUnbindOtherVM property holds via reclaimLeasedDevices.
	t.Run("reclaimed_by_other_vm_not_unbound", func(t *testing.T) {
		const addr = "0000:00:00.0"
		ctx := context.Background()
		s := testServer(t)
		j, _ := opjournal.Open(t.TempDir())
		s.SetOpJournal(j)

		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()

		// The BDF was leased by orphan-vm (deleted without clearing its lease), then legitimately
		// reclaimed + bound by live-vm. host_pci_devices records live-vm as owner.
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: s.hostName, Address: addr, Type: "gpu", VMName: "live-vm",
		}); err != nil {
			t.Fatalf("seed reclaimed device: %v", err)
		}
		fs.setBound(addr)

		if err := j.Write(opjournal.Entry{OperationID: deviceLeaseOpID("orphan-vm"), ResourceID: "orphan-vm",
			Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": addr}}); err != nil {
			t.Fatalf("write orphan lease: %v", err)
		}

		s.RecoverDeviceLeases(ctx)

		// The BDF must be untouched — it belongs to live-vm now, whose passthrough must survive.
		if !fs.isBound(addr) {
			t.Fatal("recovery must NOT unbind a BDF the orphan lease no longer owns (breaks the reclaiming VM's live device)")
		}
		if fs.unbindCount(addr) != 0 {
			t.Fatalf("recovery must not invoke Unbind on the reclaimed BDF, got %d unbind(s)", fs.unbindCount(addr))
		}
		if o := pciOwnerOf(t, ctx, s, addr); o != "live-vm" {
			t.Fatalf("the reclaiming VM must retain ownership, got %q", o)
		}
		// The stale orphan lease is still cleared (nothing of ours left to reclaim → handled).
		if _, found, _ := j.Read(deviceLeaseOpID("orphan-vm")); found {
			t.Fatal("orphan lease entry should be cleared after recovery (its owned subset was empty)")
		}
	})
}

// FIX-22 Fix C: a successful DeleteVM must clear any lingering durable device lease for the VM,
// so a deleted VM's devlease:<vm> entry cannot linger and later drive RecoverDeviceLeases to
// unbind a BDF the deleted VM's address has since been reclaimed for (Fix B's hazard source).
func TestDeleteVM_ClearsDeviceLease(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	fs.setBound(addr)

	// A durable device lease lingers for vm1 (e.g. an attach/start finish() that never ran).
	if err := s.opJournal.Write(opjournal.Entry{OperationID: deviceLeaseOpID("vm1"), ResourceID: "vm1",
		Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": addr}}); err != nil {
		t.Fatalf("write lease: %v", err)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("delete must complete: %v", err)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm1")); found {
		t.Fatal("a successful delete must clear the VM's device lease (so it can't linger to drive a cross-VM unbind on recovery)")
	}
}
