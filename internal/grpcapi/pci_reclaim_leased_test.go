package grpcapi

import (
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

var errDumpXMLBoom = errors.New("dumpxml boom")

// FIX-25 Fix B: reclaimLeasedDevices is the durable-lease-authorized recovery primitive —
// the ONLY primitive allowed to reclaim an UNOWNED device, authorized SOLELY because its
// addrs come from a durable device-lease entry (proof the leaked device was this VM's). The
// normal primitive (unbindAndReleaseOwnership) must never touch an unowned device; this one
// must. These tests pin: an unowned leak IS reclaimed, a since-reclaimed foreign device is
// left alone, and a live guest is membership-detached BEFORE the unbind (fail-closed on a
// DumpXML error so a device still in a live guest is never unbound).

// TestReclaimLeasedDevices_UnownedLeaked_Reclaims: an UNOWNED, vfio-bound leaked device with
// vmExists=false (the VM is gone) IS reclaimed — the device is unbound and the call returns
// nil. There is no ownership row to release (the addr is unowned), so unbinding it is the
// whole reclaim.
func TestReclaimLeasedDevices_UnownedLeaked_Reclaims(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	// Inventory row present but UNOWNED, and the device is bound to vfio-pci (the leak).
	seedPCIGPU(t, s, addr, -1)
	fs.setBound(addr)

	if err := s.reclaimLeasedDevices(ctx, "vm-a", []string{addr}, reclaimNoDomain); err != nil {
		t.Fatalf("reclaim of an unowned leaked device must succeed, got %v", err)
	}
	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("reclaim must unbind the leaked device exactly once, got %d unbinds", n)
	}
	if fs.isBound(addr) {
		t.Fatal("reclaim must leave the leaked device UNbound (no unowned+bound orphan)")
	}
}

// TestReclaimLeasedDevices_ForeignOwned_Skips: an addr owned + bound by a DIFFERENT live VM
// (it was legitimately reclaimed after the lease was written) must be SKIPPED — never
// unbound — and the call returns nil (a clean no-op: nothing of the lease VM's left). The
// reclaiming VM's ownership stays intact.
func TestReclaimLeasedDevices_ForeignOwned_Skips(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-b"); err != nil {
		t.Fatalf("assign addr to vm-b: %v", err)
	}
	fs.setBound(addr)

	if err := s.reclaimLeasedDevices(ctx, "vm-a", []string{addr}, reclaimNoDomain); err != nil {
		t.Fatalf("reclaim skipping a foreign-owned addr must be a clean no-op, got %v", err)
	}
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("reclaim must NOT unbind a device reclaimed by another VM, got %d unbinds", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("the reclaiming VM's device must stay bound to vfio-pci")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm-b" {
		t.Fatalf("the reclaiming VM must retain ownership, got %q", o)
	}
}

// TestReclaimLeasedDevices_VMExists_DetachesFromGuestFirst: when vmExists=true and the leased
// device is a member of the VM's live guest, reclaim must FIRST membership-detach it from the
// guest, THEN unbind + owner-release. A DumpXML error variant must fail closed — return an
// error and NOT unbind (the lease is retained for retry) so a device still in a live guest is
// never unbound.
func TestReclaimLeasedDevices_VMExists_DetachesFromGuestFirst(t *testing.T) {
	const addr = "0000:00:00.0"

	t.Run("detaches_from_guest_before_unbind", func(t *testing.T) {
		s := hotplugDiskServer(t)
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)

		// The device is owned + bound by vm-a AND present in vm-a's live guest as a PCI
		// hostdev (its source address matches addr, so detachHostdevIfPresent finds it).
		seedPCIGPU(t, s, addr, -1)
		if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
			t.Fatalf("assign addr to vm-a: %v", err)
		}
		fs.setBound(addr)
		fake.SetActiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
			"<hostdev mode='subsystem' type='pci'><source>"+
			"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
			"</devices></domain>")

		// Record the guest-detach count observed AT the moment of unbind, to prove the
		// detach ran BEFORE the unbind.
		var detachAtUnbind int
		fs.onUnbind = func(string) { detachAtUnbind = fake.DetachHostdevCount() }

		if err := s.reclaimLeasedDevices(ctx, "vm-a", []string{addr}, reclaimLive); err != nil {
			t.Fatalf("reclaim with a live guest member must succeed, got %v", err)
		}
		if fake.DetachHostdevCount() != 1 {
			t.Fatalf("reclaim must membership-detach the device from the live guest, got %d detaches", fake.DetachHostdevCount())
		}
		if detachAtUnbind != 1 {
			t.Fatal("the guest detach must run BEFORE the vfio unbind (never unbind a device still in a live guest)")
		}
		if n := fs.unbindCount(addr); n != 1 {
			t.Fatalf("reclaim must unbind the device once, got %d unbinds", n)
		}
		if fs.isBound(addr) {
			t.Fatal("reclaim must leave the device unbound")
		}
		if o := pciOwnerOf(t, ctx, s, addr); o != "" {
			t.Fatalf("reclaim must owner-release a device owned by the lease VM, got %q", o)
		}
	})

	t.Run("dumpxml_error_fails_closed_no_unbind", func(t *testing.T) {
		s := hotplugDiskServer(t)
		fs := newPCIUnbindRecordingFS()
		restore := vfio.SetFS(fs)
		defer restore()
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)

		seedPCIGPU(t, s, addr, -1)
		if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
			t.Fatalf("assign addr to vm-a: %v", err)
		}
		fs.setBound(addr)
		// Membership can't be confirmed — DumpXML errors.
		fake.FailDumpXML = func(string) error { return errDumpXMLBoom }

		if err := s.reclaimLeasedDevices(ctx, "vm-a", []string{addr}, reclaimLive); err == nil {
			t.Fatal("a DumpXML error during the guest detach must fail closed (return an error), got nil")
		}
		if n := fs.unbindCount(addr); n != 0 {
			t.Fatalf("a device whose guest membership can't be confirmed must NOT be unbound, got %d unbinds", n)
		}
		if !fs.isBound(addr) {
			t.Fatal("fail-closed reclaim must leave the device still bound (lease retained for retry)")
		}
		if o := pciOwnerOf(t, ctx, s, addr); o != "vm-a" {
			t.Fatalf("fail-closed reclaim must retain ownership, got %q", o)
		}
	})
}
