package grpcapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// guestHasHostdev reports whether vmName's LIVE domain still carries a PCI hostdev
// whose source BDF matches addr — the by-source-address membership the legacy detach
// path keys off (legacy hostdevs carry no alias).
func guestHasHostdev(t *testing.T, s *Server, vmName, addr string) bool {
	t.Helper()
	live, err := s.virt.DumpXML(vmName)
	if err != nil {
		t.Fatalf("DumpXML(%s): %v", vmName, err)
	}
	want, _ := pci.CanonicalBDF(addr)
	for _, raw := range libvirt.HostdevSourcePCIAddresses(live) {
		if got, ok := pci.CanonicalBDF(raw); ok && got == want {
			return true
		}
	}
	return false
}

// notFoundOnAbsentDetach builds a FailDetachHostdev hook that models real libvirt:
// DomainDetachDeviceFlags errors ("device not found") when the hostdev is NOT present
// in the live domain. This is the exact non-convergence cause the membership-aware
// helper removes — a bare retry-detach of an already-gone device errors and returns
// before the release can be re-attempted.
func notFoundOnAbsentDetach(fake *libvirtfake.Fake) func(string, string) error {
	return func(dom, addr string) error {
		live, err := fake.DumpXML(dom)
		if err != nil {
			return nil // cannot read → let the normal path proceed
		}
		want, _ := pci.CanonicalBDF(addr)
		for _, raw := range libvirt.HostdevSourcePCIAddresses(live) {
			if got, ok := pci.CanonicalBDF(raw); ok && got == want {
				return nil // present → the detach is allowed
			}
		}
		return fmt.Errorf("device %s not found in domain %s", addr, dom)
	}
}

// TestAttachPCI_LegacyPartialAttachFails_InverseDetachesThenReleases is FIX-20 Fix A:
// the legacy running-attach path (attachPCIDevice) claims+binds every member, then
// live-attaches each. If a LATER member's AttachHostdev fails while an EARLIER member is
// already in the guest, the rollback must FIRST inverse-detach the attached member from
// the guest (so no released device is left attached to the live domain) and only THEN
// release ownership. And when that release cannot complete, the durable device lease
// must be RETAINED (not cleared) so RecoverDeviceLeases back-stops the left-owned+bound
// device.
//
// RED before the fix: the old rollback released the earlier member while it was STILL
// attached to the guest (no inverse-detach), and `defer finish()` cleared the lease
// regardless of whether the rollback completed.
func TestAttachPCI_LegacyPartialAttachFails_InverseDetachesThenReleases(t *testing.T) {
	const primary = "0000:41:00.0"
	const sibling = "0000:41:00.1"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // operation_protocol latched → the durable device lease IS written
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "running")
	fake.SetState("vm1", libvirtfake.StateRunning)
	// Two GPUs in one IOMMU group → a 2-member device resolved from a TYPE selector (the
	// legacy running-only path; an address selector would route to the journaled path).
	seedPCIGPU(t, s, primary, 20)
	seedPCIGPU(t, s, sibling, 20)

	// The FIRST member's live attach succeeds; the SECOND fails — so exactly one member is
	// in the guest when the rollback runs. Capture which member landed first.
	var firstAttached string
	attachN := 0
	fake.FailAttachHostdev = func(_, addr, _ string) error {
		attachN++
		if attachN == 1 {
			firstAttached = addr
			return nil
		}
		return errors.New("injected second-member attach failure")
	}
	// Force the strict release to fail (neither bound member can be confirmed unbound), so
	// the rollback is INCOMPLETE and the lease-retention branch is exercised.
	fs.setFailUnbind(primary)
	fs.setFailUnbind(sibling)

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	})
	if err == nil {
		t.Fatal("a later-member attach failure must fail the attach")
	}
	if firstAttached == "" {
		t.Fatal("precondition: the first member's live attach should have succeeded")
	}

	// THE FIX (ordering): the already-attached member was inverse-detached from the guest
	// BEFORE the release — no released device is left attached to the live domain.
	if guestHasHostdev(t, s, "vm1", firstAttached) {
		t.Fatalf("the attached member %s must be inverse-detached from the guest during rollback", firstAttached)
	}
	if n := fake.DetachHostdevCount(); n != 1 {
		t.Fatalf("exactly the one attached member must be inverse-detached, got %d detaches", n)
	}
	// THE FIX (lease retention): the release could not complete → the durable device lease
	// is RETAINED for RecoverDeviceLeases, never cleared by a finish() on an incomplete rollback.
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm1")); !found {
		t.Fatal("an incomplete rollback (release failed) must RETAIN the device lease for recovery")
	}
}

// TestDetachPCI_LegacyReleaseFailThenRetry_Converges is FIX-20 Fix B (legacy detach):
// on the legacy running-detach path (detachPCIDevice), if the first attempt's release
// fails AFTER the live detach succeeded, a RETRY must converge — the guest device is
// already gone, so the retry must SKIP the (now-erroring) live detach and re-attempt the
// idempotent release to completion.
//
// RED before the fix: the retry called DetachHostdev unconditionally on the already-gone
// device → libvirt errors "device not found" → the RPC returns before reaching the
// release → the release never converges.
func TestDetachPCI_LegacyReleaseFailThenRetry_Converges(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1) // single-member device

	// A TYPE selector routes through the legacy attach path (no address intent), binding +
	// owner-claiming the device and landing its hostdev in the guest.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("legacy type attach: %v", err)
	}
	if !guestHasHostdev(t, s, "vm1", addr) {
		t.Fatal("precondition: the legacy attach must place the hostdev in the guest")
	}
	// Model real libvirt: a detach of an absent device errors "not found".
	fake.FailDetachHostdev = notFoundOnAbsentDetach(fake)

	// First attempt: the live detach succeeds but the release cannot confirm the unbind → the
	// RPC fails (recoverable). The guest hostdev is now gone; the device is still owned + bound.
	fs.setFailUnbind(addr)
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err == nil {
		t.Fatal("a failed release after a successful live detach must fail the RPC (recoverable)")
	}
	if guestHasHostdev(t, s, "vm1", addr) {
		t.Fatal("precondition: the first attempt should have live-detached the device from the guest")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("precondition: the device must remain owned (release failed), got %q", o)
	}

	// Clear the fault and RETRY: the guest device is already gone, so the retry must skip the
	// (now not-found-erroring) live detach and re-attempt the release, which now converges.
	fs.clearFailUnbind(addr)
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err != nil {
		t.Fatalf("the retry must converge, not error on the already-detached device: %v", err)
	}

	// Converged: ownership released and the device unbound.
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("the retry must release ownership, got owner %q", o)
	}
	if fs.isBound(addr) {
		t.Fatal("the retry must unbind the device from vfio-pci")
	}
}

// TestMigrateVM_VFReleaseFailThenRetry_Converges is FIX-20 Fix B (migrate VF loop):
// the SR-IOV VF pre-migration detach mirrors the legacy detach — if the first migration
// attempt's VF release fails after the VF's live detach succeeded, a RETRY must converge
// (skip the already-gone detach, re-attempt the idempotent release) rather than aborting
// on a "device not found" detach error.
//
// RED before the fix: the retry called DetachHostdev on the already-detached VF → libvirt
// errors "not found" → the migration aborts before the release → never converges.
func TestMigrateVM_VFReleaseFailThenRetry_Converges(t *testing.T) {
	const vfAddr = "0000:41:10.0"
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	// After the VF loop converges the migration proceeds; make the libvirt migration itself
	// fail so the retry terminates deterministically at a NON-VF step.
	fake.FailMigrateToTarget = func(_, _ string) error { return errors.New("injected migrate failure") }
	fake.FailDetachHostdev = notFoundOnAbsentDetach(fake)
	s.virt = fake

	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	insertTestVMWithSpec(t, ctx, s.db, "pci-vm", "test-host", "running", "")
	insertTestHost(t, ctx, s.db, "target-host", "active")

	// Seed the VF in host inventory owned by the VM, mark it a VF + vfio-bound, and place its
	// hostdev in the guest so the first detach actually removes it.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: vfAddr, Type: "net", VendorID: "8086", VMName: "pci-vm",
	}); err != nil {
		t.Fatalf("seed VF: %v", err)
	}
	fs.setVF(vfAddr)
	fs.setBound(vfAddr)
	if err := fake.AttachHostdev("pci-vm", vfAddr); err != nil {
		t.Fatalf("seed VF hostdev in guest: %v", err)
	}

	migrate := func() error {
		return s.MigrateVM(&pb.MigrateVMRequest{
			VmName:     "pci-vm",
			TargetHost: "target-host",
			Strategy:   pb.MigrateStrategy_MIGRATE_COLD,
		}, &mockMigrateStream{ctx: ctx})
	}

	// First attempt: the VF live-detaches but its release cannot confirm the unbind → the
	// migration aborts at the VF release site. The guest VF is now gone; still owned + bound.
	fs.setFailUnbind(vfAddr)
	err := migrate()
	if err == nil || !strings.Contains(err.Error(), "release VF") {
		t.Fatalf("first attempt must abort at the VF release site, got %v", err)
	}
	if guestHasHostdev(t, s, "pci-vm", vfAddr) {
		t.Fatal("precondition: the first attempt should have live-detached the VF from the guest")
	}

	// Clear the fault and RETRY: the VF is already gone from the guest, so the retry must skip
	// the (now not-found-erroring) detach and re-attempt the release, which converges.
	fs.clearFailUnbind(vfAddr)
	err = migrate()
	if err != nil && (strings.Contains(err.Error(), "detach VF") || strings.Contains(err.Error(), "release VF")) {
		t.Fatalf("the retry must converge past the VF loop, not fail on the already-detached VF: %v", err)
	}
	// Converged: the VF was released and unbound before the migration proceeded.
	if o := pciOwnerOf(t, ctx, s, vfAddr); o != "" {
		t.Fatalf("the retry must release the VF, got owner %q", o)
	}
	if fs.isBound(vfAddr) {
		t.Fatal("the retry must unbind the VF from vfio-pci")
	}
}
