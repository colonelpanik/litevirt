package grpcapi

import (
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-9c: a post-acquire start failure must release ONLY the devices freshly claimed
// DURING THIS START, never a pre-existing self-owned reserve-while-off reservation
// (FIX-9b). pciStartPreflight's rollback ran on a realization-write / reconcile /
// StartDomain failure and released the WHOLE member set (allAddrs) via the owner-scoped
// releaseDeviceLeases — which DID clear a self-owned reservation, so a transient
// post-bind failure lost the VM's reserved device to a concurrent claimant. The fix
// scopes the rollback to claimedSriov ∪ the set acquireDeviceLeases newly claimed.

// TestStartVM_ReconcileFailsAfterBind_RetainsReservation: a latched VM holds a device
// reserved-while-off (self-owned in host_pci_devices, declared by an intent). Start
// binds it (self-owned → the CAS claim is skipped), then the post-acquire reconcile
// (define) FAILS → pciStartPreflight's rollback runs. The reservation MUST survive:
// the rollback releases only the freshly-claimed set (empty here), never the self-owned
// device. RED before the fix (rollback released allAddrs → owner cleared).
func TestStartVM_ReconcileFailsAfterBind_RetainsReservation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	// Reserve-while-off (FIX-9b): the VM already OWNS the device (the shared reservation)
	// and declares it via an intent. Not pre-bound, so start-preflight's acquire binds it
	// once — but the self-owned CAS claim is skipped, so it is NOT freshly claimed.
	const deviceID = "dev-self"
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}
	seedAddressIntent(t, s, "vm1", deviceID, "0000:41:00.0")

	// Force the post-acquire reconcile define to FAIL — after the vfio bind and the
	// realization write — so the rollback runs. Fail only the define that carries the
	// device's hostdev alias, so the prior-definition restore define still succeeds.
	alias := pciMemberAlias(deviceID, "m0")
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(xml string) error {
		if hostdevAliasInXML(xml, alias) {
			return fmt.Errorf("injected reconcile define failure")
		}
		return nil
	}

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("a post-acquire reconcile failure must fail the start")
	}
	// The reserve-while-off reservation SURVIVES the failed start: a concurrent claimant
	// cannot grab the VM's reserved device on a transient post-bind failure.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("failed start must retain the self-owned reservation, got owner %q, want vm1", o)
	}
	// The VM did not start.
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st == "running" {
		t.Fatalf("VM must not be running after a failed start, state=%s", st)
	}
}

// TestStartVM_FailsButFreshlyClaimedReleased: the counterweight — a device NOT
// pre-owned is CAS-claimed fresh THIS start, so a post-acquire failure must still
// release it (no leak of a genuinely-new claim). Guards that scoping the rollback to
// the freshly-claimed set does not over-retain.
func TestStartVM_FailsButFreshlyClaimedReleased(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	// NOT pre-owned: unclaimed inventory, so start-preflight's acquire CAS-claims it fresh
	// this start (it IS in the freshly-claimed set).
	const deviceID = "dev-fresh"
	seedAddressIntent(t, s, "vm1", deviceID, "0000:41:00.0")

	alias := pciMemberAlias(deviceID, "m0")
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(xml string) error {
		if hostdevAliasInXML(xml, alias) {
			return fmt.Errorf("injected reconcile define failure")
		}
		return nil
	}

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("a post-acquire reconcile failure must fail the start")
	}
	// A genuinely-new claim taken THIS start must NOT leak on a failed start.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("a freshly-claimed device must be released on a failed start, got owner %q", o)
	}
}
