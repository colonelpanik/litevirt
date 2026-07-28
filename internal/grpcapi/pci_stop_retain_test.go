package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-9b: a stopped VM RETAINS its PCI reservation (reserve-while-off) under the
// active hardware_v2 regime, so "assigned while off, realized while running" holds.
// FIX-9a made host_pci_devices ownership the shared reservation every producer
// contends on; releasing it on stop let another VM grab hardware the stopped VM
// still declares (its vm_pci_intent persists). The change is latch-gated: pre-latch
// stop behaves exactly as before (unbind + release), so the current fleet is
// unchanged and a mixed-version rollout degrades gracefully.

// TestStopVM_Latched_RetainsPCIOwnership: with hardware_v2 latched, stopping a VM
// that owns a PCI device must LEAVE the host_pci_devices ownership in place — the
// device stays reserved for the VM while it is off. RED before the fix (the
// unconditional releaseDevices cleared it).
func TestStopVM_Latched_RetainsPCIOwnership(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "running")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateRunning)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}

	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// The reservation is RETAINED: the device is still owned by the stopped VM.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("latched stop must retain the PCI reservation, got owner %q, want vm1", o)
	}
}

// TestStopVM_NotLatched_ReleasesPCIOwnership: dormancy / no-regression — with
// hardware_v2 NOT latched, stop behaves exactly as today (releaseDevices: unbind +
// clear ownership), so the current fleet is byte-for-behavior unchanged.
func TestStopVM_NotLatched_ReleasesPCIOwnership(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // operation_protocol active, hardware_v2 NOT latched
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "running")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateRunning)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}

	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// Pre-latch: the reservation is released, exactly as before FIX-9b.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("pre-latch stop must release ownership (unchanged legacy behavior), got owner %q", o)
	}
}

// TestStartVM_SelfOwnedReservation_Binds is the load-bearing proof for the chosen
// vfio mechanism (a): a latched stop leaves the reserved device bound + owned, so a
// subsequent start finds it already owned by the VM (self-owned) AND already bound.
// The start path must tolerate that — claimDeviceOwnership's self-owned skip keeps
// ownership (no double-claim AlreadyExists), and vfio.Bind is idempotent (an
// already-vfio-pci device returns success without re-binding) — so the VM starts and
// the device ends up bound.
func TestStartVM_SelfOwnedReservation_Binds(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	// The retained reservation left by a latched stop: the device is OWNED by the VM
	// (the shared reservation), an intent declares it, and it is still BOUND to vfio.
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	seedAddressIntent(t, s, "vm1", "dev-self", "0000:41:00.0")
	fs.bound["0000:41:00.0"] = true // stop retained the vfio bind (mechanism (a))

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start of a self-owned reservation must succeed, got %v", err)
	}

	// The device ends up bound and the VM is running.
	if !fs.bound["0000:41:00.0"] {
		t.Fatal("device must be bound to vfio-pci after start")
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st != "running" {
		t.Fatalf("VM not running after start, state=%s", st)
	}
	// vfio.Bind was idempotent: the already-bound device needed NO re-bind.
	if fs.binds != 0 {
		t.Fatalf("an already-bound self-owned device must not be re-bound, got %d binds", fs.binds)
	}
	// Ownership retained throughout (the self-owned skip, no re-claim, no clear).
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("self-owned reservation must remain owned by vm1, got %q", o)
	}
	// The realization was persisted at start (assigned-while-off → realized-while-running).
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("want 1 realization after start, got %d", len(rs))
	}
}

// TestStartVM_FailedBind_RetainsOwnership: a self-owned reservation whose start-time
// vfio bind FAILS must RETAIN the reservation (ownership) — a failed start cannot
// silently drop a reserve-while-off device, or another VM could grab it. The
// acquire-path rollback releases ONLY the devices THIS start newly claimed, so a
// pre-owned (self-owned) reservation survives the bind failure. RED before the fix
// (the bind-failure rollback released every address, clearing the reservation).
func TestStartVM_FailedBind_RetainsOwnership(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := &failBindFS{pciBindFakeFS: newPCIBindFakeFS(), failAddr: "0000:41:00.0"}
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	// Reserved-while-off: the VM owns the device (the reservation) and declares it via
	// an intent, but it is NOT yet bound — so the start actually attempts a vfio bind,
	// which we force to fail.
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	seedAddressIntent(t, s, "vm1", "dev-self", "0000:41:00.0")

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("a failing start-time bind must fail the start")
	}
	// The reservation SURVIVES the failed start.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("failed start must retain the reservation, got owner %q, want vm1", o)
	}
	// The VM did not start.
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st == "running" {
		t.Fatalf("VM must not be running after a failed start, state=%s", st)
	}
}
