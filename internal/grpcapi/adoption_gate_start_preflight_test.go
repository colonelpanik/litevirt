package grpcapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// seedAddressIntent inserts a reserved concrete-address vm_pci_intent row (the state
// a stopped-VM PCI attach leaves) so a start-preflight has an intent to realize.
func seedAddressIntent(t *testing.T, s *Server, vmName, deviceID, addr string) {
	t.Helper()
	payload, err := protojson.Marshal(&pb.DeviceSpec{Address: addr})
	if err != nil {
		t.Fatalf("marshal selector payload: %v", err)
	}
	ek := addr
	if err := corrosion.UpsertPCIIntent(adminCtx(), s.db, corrosion.PCIIntentRecord{
		VMName: vmName, DeviceID: deviceID, HostName: "test-host",
		SelectorKind: "address", SelectorPayload: string(payload), ExclusiveKey: &ek,
	}); err != nil {
		t.Fatalf("seed address intent: %v", err)
	}
}

// failBindFS wraps pciBindFakeFS and makes the vfio-pci bind (and the drivers_probe
// fallback) FAIL for one address, simulating a device that has vanished from the host
// so acquireDeviceLeases fails and the start must fail closed.
type failBindFS struct {
	*pciBindFakeFS
	failAddr string
}

func (f *failBindFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if strings.TrimSpace(string(data)) == f.failAddr &&
		(strings.Contains(path, "vfio-pci/bind") || strings.HasSuffix(path, "drivers_probe")) {
		return fmt.Errorf("bind %s: no such device", f.failAddr)
	}
	return f.pciBindFakeFS.WriteFile(path, data, perm)
}

// ── Part 1: adoption gate (fail-closed on blocked ONLY when hardware_v2 latched) ──

func TestAttachDevice_BlockedAdoption_Latched_FailsClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	const reason = "hardware audit: passthrough device incompatible on this host"
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "vm1", "blocked", reason); err != nil {
		t.Fatalf("set adoption state: %v", err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "10G", Bus: "virtio"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("blocked+latched attach: want FailedPrecondition, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("error must carry the stored adoption reason %q, got %v", reason, err)
	}
}

func TestStartVM_BlockedAdoption_Latched_FailsClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	const reason = "hardware audit: passthrough device incompatible on this host"
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "vm1", "blocked", reason); err != nil {
		t.Fatalf("set adoption state: %v", err)
	}

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("blocked+latched start: want FailedPrecondition, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("error must carry the stored adoption reason %q, got %v", reason, err)
	}
	// The blocked VM must NOT have been started.
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st == "running" {
		t.Fatalf("blocked VM was started despite the gate (state=%s)", st)
	}
}

func TestStartVM_BlockedAdoption_NotLatched_StartsAndMutates(t *testing.T) {
	s := hotplugDiskServer(t)
	// NOT latched: adoption state is informational only — start + mutate must behave
	// exactly as today.
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	const reason = "hardware audit: passthrough device incompatible on this host"
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "vm1", "blocked", reason); err != nil {
		t.Fatalf("set adoption state: %v", err)
	}

	// Start is NOT gated when hardware_v2 is inactive.
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("blocked but pre-latch: start must succeed, got %v", err)
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st != "running" {
		t.Fatalf("pre-latch blocked VM should be running, got %s", st)
	}

	// A mutation is NOT gated either: the disk attach reaches its normal path (which
	// here rejects on the operation_protocol precondition), NOT the adoption reason.
	_, aerr := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "10G", Bus: "virtio"},
	})
	if aerr != nil && strings.Contains(aerr.Error(), reason) {
		t.Fatalf("pre-latch mutation was gated by adoption state: %v", aerr)
	}
}

// ── Part 2: PCI start-preflight (acquire + realize + reconcile before StartDomain) ──

func TestStartVM_PCIPreflight_ConcreteAddress_AcquiresRealizesReconciles(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	const deviceID = "dev-concrete-1"
	seedAddressIntent(t, s, "vm1", deviceID, "0000:41:00.0")

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("preflight start: %v", err)
	}

	// The lease was acquired (vfio bind happened for the single member).
	if fs.binds != 1 {
		t.Fatalf("want exactly 1 vfio bind at start, got %d", fs.binds)
	}
	// The realization was persisted (CONTRACT g: member + alias + resolved address).
	rs := liveRealizations(t, ctx, s, "vm1")
	if len(rs) != 1 {
		t.Fatalf("want 1 realization, got %d: %+v", len(rs), rs)
	}
	r := rs[0]
	if r.DeviceID != deviceID || r.MemberID != "m0" || r.ResolvedAddress != "0000:41:00.0" {
		t.Fatalf("realization mismatch: %+v", r)
	}
	if r.XMLAlias != pciMemberAlias(deviceID, "m0") {
		t.Fatalf("realization alias = %q, want %q", r.XMLAlias, pciMemberAlias(deviceID, "m0"))
	}
	// The hostdev was reconciled into the domain definition, and the domain started.
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	if !hostdevAliasInXML(xml, pciMemberAlias(deviceID, "m0")) {
		t.Fatalf("reconciled hostdev alias absent from defined XML:\n%s", xml)
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st != "running" {
		t.Fatalf("VM not running after preflight start, state=%s", st)
	}
}

func TestStartVM_NoIntents_NoPreflight_Unchanged(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // latched, but the VM has NO intents → no preflight
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("no-intent start: %v", err)
	}
	// No preflight ran: no bind attempt, no realization written.
	if fs.binds != 0 {
		t.Fatalf("no-intent start must NOT bind vfio, got %d binds", fs.binds)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("no-intent start must NOT write realizations, got %d", len(rs))
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st != "running" {
		t.Fatalf("no-intent VM not running, state=%s", st)
	}
}

func TestStartVM_PCIPreflight_VanishedDevice_FailClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := &failBindFS{pciBindFakeFS: newPCIBindFakeFS(), failAddr: "0000:41:00.0"}
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	// Domain was previously reconciled (defined) at attach time, so absent the
	// preflight it WOULD start — the ONLY reason it must not is the fail-closed bind.
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	seedAddressIntent(t, s, "vm1", "dev-vanished", "0000:41:00.0")

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("vanished device: start must fail closed")
	}
	// Domain must not be running.
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st == "running" {
		t.Fatalf("start should not have run the domain, state=%s", st)
	}
	// No realizations left, and the device ownership was released (partially-acquired
	// lease rolled back).
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("failed preflight must leave no realizations, got %d", len(rs))
	}
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName == "vm1" {
			t.Fatalf("device %s still owned by vm1 after failed preflight", d.Address)
		}
	}
}

func TestStartVM_PCIPreflight_SRIOV_RoutesThroughAllocator(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.SetSRIOVPolicy(false, 8, nil) // reuse path works unmanaged
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()

	pf := "0000:41:00.0"
	vfs := fakeSysfsPF(t, pf, 8, 2) // 2 existing free VFs
	seedPCIDevice(t, ctx, s, pf, true)
	for _, vf := range vfs {
		seedPCIDevice(t, ctx, s, vf, false)
	}
	seedNICVM(t, s, "vm1", "stopped")

	// Reserve an SR-IOV intent (the selector the resolver would send to the
	// Unimplemented resolver — the preflight must route it to allocateSRIOVVFs).
	payload, err := protojson.Marshal(&pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf})
	if err != nil {
		t.Fatalf("marshal sriov payload: %v", err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, s.db, corrosion.PCIIntentRecord{
		VMName: "vm1", DeviceID: "dev-sriov", HostName: "test-host",
		SelectorKind: "sriov", SelectorPayload: string(payload),
	}); err != nil {
		t.Fatalf("seed sriov intent: %v", err)
	}

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		if status.Code(err) == codes.Unimplemented {
			t.Fatalf("SR-IOV intent hit the Unimplemented resolver — routing not wired: %v", err)
		}
		t.Fatalf("sriov preflight start: %v", err)
	}
	// A VF was claimed + realized for the VM.
	rs := liveRealizations(t, ctx, s, "vm1")
	if len(rs) != 1 {
		t.Fatalf("want 1 sriov realization, got %d: %+v", len(rs), rs)
	}
	owned := 0
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName == "vm1" {
			owned++
		}
	}
	if owned != 1 {
		t.Fatalf("want exactly 1 VF owned by vm1 after sriov preflight, got %d", owned)
	}
	if st, _ := s.virt.(*libvirtfake.Fake).DomainState("vm1"); st != "running" {
		t.Fatalf("sriov VM not running after preflight, state=%s", st)
	}
}
