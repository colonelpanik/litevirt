package grpcapi

import (
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-30: lease reclaim must key its guest-detach on the LIVE-domain DISPOSITION, not
// just "the vm row exists". After a HOST REBOOT the vm row still says the VM exists while
// its libvirt domain is SHUT OFF; a LIVE|CONFIG detach against a shut-off domain is
// rejected by libvirt, so the old vmExists=true → LIVE-detach reclaim errored and RETAINED
// the lease forever (stuck). A shut-off domain must be CONFIG-detached (persistent
// definition only); an indeterminate / paused / pm-suspended domain must DEFER (retain the
// lease, reclaim nothing) so a still-active guest never has a device torn out from under it.

var errLiveDetachOnShutoff = errors.New("device modify live on a shut-off domain is rejected")

// TestRecoverDeviceLeases_RollbackIncompleteShutoff_Reclaims: a VM whose row exists but
// whose libvirt domain is SHUT OFF, carrying a rollback_incomplete lease over an owned +
// bound member persisted in its (inactive) definition, must be reclaimed at startup
// recovery — the member is unbound and owner-released and the lease entry removed (not
// stuck). The scenario pins libvirt's real behavior by failing any LIVE detach on the
// shut-off domain: a reclaim that still routed through the LIVE path would error and leave
// the device leaked with the lease retained forever.
func TestRecoverDeviceLeases_RollbackIncompleteShutoff_Reclaims(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// The VM row exists, but its libvirt domain is POSITIVELY shut off after a host reboot.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-a", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("vm-a", libvirtfake.StateShutdown)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)
	// The leased member is present in the PERSISTENT (inactive) definition — what DumpXML
	// returns for a shut-off domain (no live instance). A member persisted-but-not-live is
	// exactly what the CONFIG detach must remove.
	fake.SetInactiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")
	// libvirt rejects a LIVE-flagged device modify on a shut-off domain. If reclaim routes
	// through the LIVE detach it errors here and the device is never reclaimed.
	fake.FailDetachHostdev = func(string, string) error { return errLiveDetachOnShutoff }

	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageRollbackIncomplete, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write rollback_incomplete lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	if fake.DetachHostdevConfigCount() != 1 {
		t.Fatalf("recovery must CONFIG-detach the member from the shut-off domain's persistent definition once, got %d", fake.DetachHostdevConfigCount())
	}
	if fake.DetachHostdevCount() != 0 {
		t.Fatalf("recovery must NOT LIVE-detach a shut-off domain, got %d live detaches", fake.DetachHostdevCount())
	}
	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("recovery must unbind the leaked device once, got %d", n)
	}
	if fs.isBound(addr) {
		t.Fatal("recovery must leave the reclaimed device unbound (no owned+bound leak)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("recovery must owner-release the reclaimed device, got %q", o)
	}
	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); found {
		t.Fatal("recovery must remove the reclaimed rollback_incomplete lease entry (not stuck)")
	}
}

// TestReclaimLeasedDevices_ShutoffDomain_UsesConfigDetachNotLive (Fix A–C): the reclaim
// primitive, given reclaimConfig for a shut-off domain, must membership-detach the leased
// member from the PERSISTENT definition via the CONFIG-only path (never the live path,
// which libvirt rejects on a shut-off domain), then unbind + owner-release. The scenario
// fails any LIVE detach to prove the config path is taken: had reclaim routed through the
// live detach it would have errored and reclaimed nothing.
func TestReclaimLeasedDevices_ShutoffDomain_UsesConfigDetachNotLive(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	// The device is owned + bound by vm-a and persisted in vm-a's (inactive) definition —
	// which DumpXML returns for a shut-off domain.
	fake.SetState("vm-a", libvirtfake.StateShutdown)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)
	fake.SetInactiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")
	// A LIVE detach on a shut-off domain is rejected by libvirt — fail it so any use of the
	// live path surfaces as a reclaim error instead of a silent pass.
	fake.FailDetachHostdev = func(string, string) error { return errLiveDetachOnShutoff }

	// Record the config-detach count observed AT the unbind, to prove the config detach ran
	// BEFORE the unbind (never unbind a device still persisted in the definition).
	var configDetachAtUnbind int
	fs.onUnbind = func(string) { configDetachAtUnbind = fake.DetachHostdevConfigCount() }

	if err := s.reclaimLeasedDevices(ctx, "vm-a", []string{addr}, reclaimConfig); err != nil {
		t.Fatalf("config-mode reclaim of a shut-off domain must succeed, got %v", err)
	}
	if fake.DetachHostdevConfigCount() != 1 {
		t.Fatalf("reclaim must CONFIG-detach the member once, got %d", fake.DetachHostdevConfigCount())
	}
	if fake.DetachHostdevCount() != 0 {
		t.Fatalf("reclaim must NOT use the LIVE detach on a shut-off domain, got %d", fake.DetachHostdevCount())
	}
	if configDetachAtUnbind != 1 {
		t.Fatal("the config detach must run BEFORE the vfio unbind")
	}
	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("reclaim must unbind the device once, got %d", n)
	}
	if fs.isBound(addr) {
		t.Fatal("reclaim must leave the device unbound")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("reclaim must owner-release the device owned by the lease VM, got %q", o)
	}
}

// TestRecoverDeviceLeases_IndeterminateDomain_DefersRetains (Fix D): a VM row exists but
// its live domain is NOT definitively running or shut off (here: paused — coarse-stopped
// with reason "paused", a still-active guest whose devices are attached). A reclaim-stage
// lease over it must DEFER: the entry is RETAINED (not removed) and the device is NOT
// reclaimed (no guest detach, no unbind, no release). Reclaiming an active/unknown-state
// guest could tear a device out from under it — the recovery waits for a definite state.
func TestRecoverDeviceLeases_IndeterminateDomain_DefersRetains(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-a", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A paused domain: coarse "stopped" but reason "paused" → dispDefer (still-active guest).
	fake.SetState("vm-a", libvirtfake.StateShutdown)
	fake.SetStateReason("vm-a", "paused")
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)
	fake.SetInactiveXML("vm-a", "<domain><name>vm-a</name><devices>"+
		"<hostdev mode='subsystem' type='pci'><source>"+
		"<address domain='0x0000' bus='0x00' slot='0x00' function='0x0'/></source></hostdev>"+
		"</devices></domain>")

	if err := s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID("vm-a"), ResourceID: "vm-a", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageRollbackIncomplete, Artifacts: map[string]string{"addresses": addr},
	}); err != nil {
		t.Fatalf("write rollback_incomplete lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	if _, found, _ := s.opJournal.Read(deviceLeaseOpID("vm-a")); !found {
		t.Fatal("an indeterminate/paused domain must RETAIN the lease entry (deferred, not cleared)")
	}
	if fake.DetachHostdevCount() != 0 || fake.DetachHostdevConfigCount() != 0 {
		t.Fatalf("deferred recovery must NOT detach the device (live=%d config=%d)", fake.DetachHostdevCount(), fake.DetachHostdevConfigCount())
	}
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("deferred recovery must NOT unbind the device, got %d unbinds", n)
	}
	if !fs.isBound(addr) {
		t.Fatal("deferred recovery must leave the device bound (nothing reclaimed)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm-a" {
		t.Fatalf("deferred recovery must retain ownership, got %q", o)
	}
}
