package grpcapi

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// pciOwnerOf returns the vm_name that currently owns addr in host_pci_devices on
// test-host ("" if the row is unowned or absent) — the shared CAS reservation a
// PCI producer takes.
func pciOwnerOf(t *testing.T, ctx context.Context, s *Server, addr string) string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	return ""
}

// Concrete-address PCI hotplug tests reuse the disk suite's server/gate helpers
// (hotplugDiskServer, setDeviceGate, enableHardwareV2, mustGetVM) and the NIC
// suite's seedNICVM, plus the PCI-inventory + vfio fakes from pci_test.go
// (newPCIBindFakeFS). Every test installs the vfio fake so a bind never touches
// host sysfs.

// seedPCIDevice inserts a host_pci_devices inventory row so the resolver can
// resolve a concrete BDF (and its IOMMU-group siblings) for a VM's passthrough.
func seedPCIGPU(t *testing.T, s *Server, addr string, iommuGroup int) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(adminCtx(), s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: iommuGroup,
	}); err != nil {
		t.Fatalf("seed PCI device %s: %v", addr, err)
	}
}

func liveIntents(t *testing.T, ctx context.Context, s *Server, vm string) []corrosion.PCIIntentRecord {
	t.Helper()
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vm)
	if err != nil {
		t.Fatalf("ListVMPCIIntents(%s): %v", vm, err)
	}
	return intents
}

func liveRealizations(t *testing.T, ctx context.Context, s *Server, vm string) []corrosion.PCIRealizationRecord {
	t.Helper()
	rs, err := corrosion.ListVMPCIRealizations(ctx, s.db, vm)
	if err != nil {
		t.Fatalf("ListVMPCIRealizations(%s): %v", vm, err)
	}
	return rs
}

// ── attach: stopped RESERVES the intent (no bind, no realization) ─────────────

func TestAttachDevice_StoppedPCIReserveIntent(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	out, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if out == nil {
		t.Fatal("nil VM returned")
	}

	// Intent RESERVED: address kind, normalized exclusive_key, this host.
	intents := liveIntents(t, ctx, s, "vm1")
	if len(intents) != 1 {
		t.Fatalf("want exactly 1 live intent, got %d: %+v", len(intents), intents)
	}
	in := intents[0]
	if in.SelectorKind != "address" {
		t.Fatalf("selector_kind = %q, want address", in.SelectorKind)
	}
	if in.ExclusiveKey == nil || *in.ExclusiveKey != "0000:41:00.0" {
		t.Fatalf("exclusive_key = %v, want 0000:41:00.0", in.ExclusiveKey)
	}
	if in.HostName != "test-host" {
		t.Fatalf("host_name = %q, want test-host", in.HostName)
	}
	// selector_payload is protojson (contract (b)).
	if !strings.Contains(in.SelectorPayload, "0000:41:00.0") {
		t.Fatalf("selector_payload not protojson with the address: %q", in.SelectorPayload)
	}

	// NO realization on a stopped reserve (bind/realization happen at VM start).
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("stopped reserve must NOT write realizations, got %d: %+v", len(rs), rs)
	}
	// NO vfio bind on a stopped reserve.
	if fs.binds != 0 {
		t.Fatalf("stopped reserve must NOT bind vfio, got %d binds", fs.binds)
	}

	// reconcile emits the hostdev (aliased ua-<device>-m0) in the inactive definition.
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	alias := pciMemberAlias(in.DeviceID, "m0")
	if !hostdevAliasInXML(xml, alias) {
		t.Fatalf("reserved hostdev alias %s absent from reconciled XML:\n%s", alias, xml)
	}
}

// ── attach: stopped exclusivity — a 2nd VM claiming the same BDF is rejected ──

func TestAttachDevice_PCIExclusivityRejected(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedNICVM(t, s, "vm2", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("first VM reserve: %v", err)
	}
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm2", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("2nd VM claiming the same BDF: code = %v, want AlreadyExists", status.Code(err))
	}
	if rs := liveIntents(t, ctx, s, "vm2"); len(rs) != 0 {
		t.Fatalf("no intent should exist for the rejected VM: %+v", rs)
	}
}

// ── attach: running acquires + binds + realizes (both-state verified) ─────────

func TestAttachDevice_RunningPCIAcquiresAndRealizes(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	// Two devices in one IOMMU group → two realized members (primary + sibling).
	seedPCIGPU(t, s, "0000:41:00.0", 20)
	seedPCIGPU(t, s, "0000:41:00.1", 20)
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Bound to vfio (acquire ran) and live-attached once per member.
	if fs.binds != 2 {
		t.Fatalf("want 2 vfio binds (BDF + IOMMU sibling), got %d", fs.binds)
	}
	if n := fake.AttachHostdevCount(); n != 2 {
		t.Fatalf("live AttachHostdev called %d times, want 2 (one per member)", n)
	}

	// Ownership recorded on both members.
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName != "vm1" {
			t.Fatalf("device %s owner = %q, want vm1", d.Address, d.VMName)
		}
	}

	// Intent written.
	intents := liveIntents(t, ctx, s, "vm1")
	if len(intents) != 1 {
		t.Fatalf("want 1 intent, got %d", len(intents))
	}
	deviceID := intents[0].DeviceID

	// Realizations: one row per member, carrying member_id + ua-alias + resolved addr.
	rs := liveRealizations(t, ctx, s, "vm1")
	if len(rs) != 2 {
		t.Fatalf("want 2 realizations, got %d: %+v", len(rs), rs)
	}
	byMember := map[string]corrosion.PCIRealizationRecord{}
	for _, r := range rs {
		byMember[r.MemberID] = r
	}
	m0, ok := byMember["m0"]
	if !ok {
		t.Fatalf("no m0 realization: %+v", rs)
	}
	if m0.ResolvedAddress != "0000:41:00.0" {
		t.Fatalf("m0 resolved_address = %q, want 0000:41:00.0", m0.ResolvedAddress)
	}
	if m0.XMLAlias != pciMemberAlias(deviceID, "m0") {
		t.Fatalf("m0 xml_alias = %q, want %q", m0.XMLAlias, pciMemberAlias(deviceID, "m0"))
	}
	if _, ok := byMember["m1"]; !ok {
		t.Fatalf("no m1 (IOMMU sibling) realization: %+v", rs)
	}

	// Both-state: each member's alias present in the live AND persistent definitions.
	live, _ := fake.DumpXML("vm1")
	inactive, _ := fake.DumpXMLInactive("vm1")
	for _, mid := range []string{"m0", "m1"} {
		alias := pciMemberAlias(deviceID, mid)
		if !hostdevAliasInXML(live, alias) {
			t.Fatalf("alias %s absent from the live domain:\n%s", alias, live)
		}
		if !hostdevAliasInXML(inactive, alias) {
			t.Fatalf("alias %s absent from the persistent definition:\n%s", alias, inactive)
		}
	}

	// Barrier cleared (op completed).
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after completed attach: %q", vm.ActiveOperationID)
	}
}

// ── detach: running live-detaches + releases + tombstones (rolls forward) ─────

func TestDetachDevice_RunningPCITombstonesAndReleases(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	deviceID := liveIntents(t, ctx, s, "vm1")[0].DeviceID
	alias := pciMemberAlias(deviceID, "m0")

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: "0000:41:00.0",
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}

	// Live-detached once.
	if n := fake.DetachHostdevCount(); n != 1 {
		t.Fatalf("live DetachHostdev called %d times, want 1", n)
	}
	// Intent + realizations tombstoned.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("realizations not tombstoned: %+v", rs)
	}
	// Ownership released.
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName == "vm1" {
			t.Fatalf("device %s still owned by vm1 after detach", d.Address)
		}
	}
	// Alias gone from both defs.
	live, _ := fake.DumpXML("vm1")
	inactive, _ := fake.DumpXMLInactive("vm1")
	if hostdevAliasInXML(live, alias) || hostdevAliasInXML(inactive, alias) {
		t.Fatalf("alias %s still present after detach", alias)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after detach: %q", vm.ActiveOperationID)
	}
}

// ── detach: stopped tombstones intent + reconciles it out ─────────────────────

func TestDetachDevice_StoppedPCIReconcilesOut(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	deviceID := liveIntents(t, ctx, s, "vm1")[0].DeviceID
	alias := pciMemberAlias(deviceID, "m0")

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: "0000:41:00.0",
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	if hostdevAliasInXML(xml, alias) {
		t.Fatalf("hostdev %s should be reconciled out of the stopped def:\n%s", alias, xml)
	}
}

// ── pre-latch dual-write: !latched writes intent + VMSpec.Devices ─────────────

func TestAttachDevice_PCIPreLatchDualWrite(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // protocol active, hardware_v2 NOT latched
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	// Intent written.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("want 1 intent, got %d", len(in))
	}
	// AND the concrete DeviceSpec folded into VMSpec.Devices (pre-latch compatibility).
	spec := loadStoredSpec(t, s, "vm1")
	found := false
	for _, d := range spec.Devices {
		if d.Address == "0000:41:00.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pre-latch dual-write must add the DeviceSpec to VMSpec.Devices, got %+v", spec.Devices)
	}
}

// ── latched: intent only, NO VMSpec.Devices write ────────────────────────────

func TestAttachDevice_PCILatchedIntentOnly(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // latched
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("want 1 intent, got %d", len(in))
	}
	spec := loadStoredSpec(t, s, "vm1")
	if len(spec.Devices) != 0 {
		t.Fatalf("latched attach must NOT write VMSpec.Devices, got %+v", spec.Devices)
	}
}

// ── SR-IOV/type selector stays on the LEGACY running-only path (no intent) ────

func TestAttachDevice_PCITypeSpecUsesLegacyPath(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:50:00.0", -1)

	// A type selector (not "address") must route to the legacy path.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("legacy type attach: %v", err)
	}
	// NO vm_pci_intent row — the legacy path is not journaled/intent-based.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("a type selector must NOT create a vm_pci_intent row, got %+v", in)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("a type selector must NOT create vm_pci_realizations, got %+v", rs)
	}
	// The device WAS attached via the legacy path (ownership assigned).
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	owned := false
	for _, d := range devs {
		if d.VMName == "vm1" {
			owned = true
		}
	}
	if !owned {
		t.Fatal("legacy type attach should have assigned the device to vm1")
	}
}

// ── protocol prerequisite / hardware_v2 gate ──────────────────────────────────

func TestAttachDevice_PCIProtocolInactiveRejected(t *testing.T) {
	s := hotplugDiskServer(t) // no gate → operation_protocol_v1 inactive
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestAttachDevice_PCIStoppedRejectedWithoutHardwareV2(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // protocol active, hardware_v2 NOT latched
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	seedNICVM(t, s, "stopped-vm", "stopped")
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "stopped-vm", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped attach without hardware_v2: code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "hardware_v2") {
		t.Fatalf("expected a hardware_v2 message, got: %v", err)
	}

	// Running still works (protocol active is enough for live hotplug).
	seedNICVM(t, s, "running-vm", "running")
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "running-vm", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("running attach with protocol active should succeed: %v", err)
	}
}

// ── owner-side at-most-once ───────────────────────────────────────────────────

func TestAttachPCIOwner_AtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)

	req := &pb.AttachDeviceRequest{VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"}}
	opID := corrosion.DeterministicOperationID("AttachDevice", "admin@local", "_default", "vm1", "owner-key")
	reqHash := attachPCIRequestHash("vm1", "0000:41:00.0")

	if _, err := s.attachPCIOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("first owner attach: %v", err)
	}
	if _, err := s.attachPCIOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("second owner attach (should replay completed): %v", err)
	}
	if n := fake.AttachHostdevCount(); n != 1 {
		t.Fatalf("owner at-most-once violated: AttachHostdev called %d times, want 1", n)
	}
	// A DIFFERENT request hash on the SAME key is a conflict → InvalidArgument.
	_, err := s.attachPCIOwner(ctx, req, "vm1", opID, "different-hash", "owner-key")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("same op id + different hash: code = %v, want InvalidArgument", status.Code(err))
	}
}

// ── concurrency: same idempotency key → at-most-once ──────────────────────────

func TestAttachDevice_PCISameKeyConcurrentAtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)

	const key = "pci-fixed-key"
	var wg sync.WaitGroup
	var okCount int32
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: "vm1", IdempotencyKey: key,
				PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
			})
			if err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()

	if n := fake.AttachHostdevCount(); n != 1 {
		t.Fatalf("at-most-once violated: AttachHostdev called %d times, want 1", n)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("duplicate/absent realization: %d rows, want 1", len(rs))
	}
	if okCount < 1 {
		t.Fatal("at least one concurrent attach must succeed")
	}
}

// ── mutation error → operation failure + rollback (roll BACK) ─────────────────

func TestAttachDevice_PCIMutationErrorRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailAttachHostdev = func(_, _, _ string) error { return status.Error(codes.Internal, "boom") }

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if err == nil {
		t.Fatal("expected the live-attach failure to surface as an RPC error")
	}
	// No intent / realization rows survive the rolled-back attach.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent must not survive a failed attach: %+v", in)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("realizations must not survive a failed attach: %+v", rs)
	}
	// Device ownership released by rollback (releaseDeviceLeases).
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName == "vm1" {
			t.Fatalf("device %s still owned by vm1 after rollback", d.Address)
		}
	}
	// Barrier released (op reached a terminal failure via compensation).
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after clean rollback: %q", vm.ActiveOperationID)
	}
}

// ── DB error is surfaced, not silently logged ─────────────────────────────────

// TestAttachDevice_PCIRealizationWriteErrorRollsBack: the realization write fails
// AFTER the live attach + intent write have landed — a BEFORE INSERT trigger on
// vm_pci_realizations isolates this to the realization write. The rollback must
// inverse-detach the live hostdev, release the lease, and tombstone the intent.
func TestAttachDevice_PCIRealizationWriteErrorRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER pci_real_fail BEFORE INSERT ON vm_pci_realizations BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	fake := s.virt.(*libvirtfake.Fake)

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a vm_pci_realizations INSERT error must surface as Internal, got: %v", err)
	}
	if n := fake.DetachHostdevCount(); n != 1 {
		t.Fatalf("rollback must inverse-detach the live hostdev once, got %d", n)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent must be tombstoned on rollback: %+v", in)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after rollback: %q", vm.ActiveOperationID)
	}
}

// ── running attach both-state divergence rolls back ───────────────────────────

// TestAttachDevice_PCIRunningConfigDivergenceRollsBack models a live-succeeded-but-
// config-not-applied divergence: the hostdev lands live but never reaches the
// persistent config. The both-state verify must catch it and roll back.
func TestAttachDevice_PCIRunningConfigDivergenceRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices></devices></domain>")
	fake.SkipConfigOnHostdevMutation = true // live lands, persistent config does NOT

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if err == nil {
		t.Fatal("a config-vs-live divergence on a running attach must fail verification, not complete")
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent must not survive a rolled-back attach: %+v", in)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after rollback: %q", vm.ActiveOperationID)
	}
}

// ── acquireDeviceLeases: physical claim is atomic + fail-closed ───────────────

// TestAcquireDeviceLeases_ConflictFailsClosed proves the physical device claim is
// exclusive: a member already owned by a DIFFERENT VM must FAIL the acquire (no
// reassignment, no vfio bind), while a member already owned by the SAME VM is an
// idempotent self-claim that succeeds. Before the CAS fix the blind AssignPCIDevice
// silently reassigned the device to the second VM (fail-open) — the double-bind.
func TestAcquireDeviceLeases_ConflictFailsClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	// Device is already owned by the incumbent VM.
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("seed ownership: %v", err)
	}

	ownerOf := func(addr string) string {
		devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
		for _, d := range devs {
			if d.Address == addr {
				return d.VMName
			}
		}
		return ""
	}

	// A different VM claiming the same BDF must FAIL, and must NOT reassign or bind.
	if _, err := s.acquireDeviceLeases(ctx, "vm2", []ResolvedMember{{Address: "0000:41:00.0"}}); err == nil {
		t.Fatal("acquiring a device owned by another VM must fail, got nil error")
	}
	if o := ownerOf("0000:41:00.0"); o != "vm1" {
		t.Fatalf("device must stay owned by the incumbent, got owner %q", o)
	}
	if fs.binds != 0 {
		t.Fatalf("a conflicting claim must NOT vfio-bind, got %d binds", fs.binds)
	}

	// The incumbent re-acquiring its own device is an idempotent self-claim → OK.
	finish, err := s.acquireDeviceLeases(ctx, "vm1", []ResolvedMember{{Address: "0000:41:00.0"}})
	if err != nil {
		t.Fatalf("idempotent self-claim must succeed, got %v", err)
	}
	finish()
	if o := ownerOf("0000:41:00.0"); o != "vm1" {
		t.Fatalf("self-claim must keep ownership, got owner %q", o)
	}
	if fs.binds != 1 {
		t.Fatalf("self-claim must bind exactly once, got %d binds", fs.binds)
	}
}

// ── concurrency: two VMs attach the same BDF, exactly one wins ────────────────

// TestAttachPCI_ConcurrentSameBDF_OneWins is the #6 proof: two concurrent
// concrete-address attaches of the same host BDF to DIFFERENT VMs (so different
// per-VM locks, which do NOT serialize them) must resolve to EXACTLY ONE winner
// and EXACTLY ONE live intent. The shared host_pci_devices CAS (claimDeviceOwnership)
// is the exclusivity boundary: exactly one attach wins the claim, and the loser fails
// before writing its intent (the intent write is gated by a successful claim). Run
// with -race. The deterministic backstop is the sequential test below.
func TestAttachPCI_ConcurrentSameBDF_OneWins(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedNICVM(t, s, "vm2", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	var wg sync.WaitGroup
	var okCount int32
	for _, vm := range []string{"vm1", "vm2"} {
		vm := vm
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: vm, PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
			}); err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("exactly one concurrent attach of the same BDF must succeed, got %d", okCount)
	}
	total := len(liveIntents(t, ctx, s, "vm1")) + len(liveIntents(t, ctx, s, "vm2"))
	if total != 1 {
		t.Fatalf("exactly one live vm_pci_intent must exist for the BDF across both VMs, got %d", total)
	}
}

// TestAttachPCI_SequentialSameBDF_SecondRejected is the deterministic backstop for
// the concurrency proof: once one VM holds a live intent for a BDF, a second VM's
// attach of the same BDF is rejected with AlreadyExists (the exclusivity read +
// host-scoped reserve rejects the second claimant).
func TestAttachPCI_SequentialSameBDF_SecondRejected(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedNICVM(t, s, "vm2", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm2", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second VM claiming the same BDF: code = %v, want AlreadyExists", status.Code(err))
	}
	total := len(liveIntents(t, ctx, s, "vm1")) + len(liveIntents(t, ctx, s, "vm2"))
	if total != 1 {
		t.Fatalf("exactly one live intent must exist across both VMs, got %d", total)
	}
}

// ── detach: address with no live intent uses the legacy path (NotFound here) ──

func TestDetachDevice_PCINoIntentFallsToLegacy(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	// No vm_pci_intent for this address → legacy detachPCIDevice path. The libvirtfake
	// DetachHostdev succeeds, so this proves the routing reached the legacy path
	// (which does not consult vm_pci_intent) rather than the journaled NotFound.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: "0000:99:00.0",
	}); err != nil {
		t.Fatalf("legacy detach of a non-intent address should succeed via the old path: %v", err)
	}
}

// ── FIX-9a: the DB CAS on host_pci_devices is the ONE shared reservation ──────

// pciProducerServer builds a server that can BOTH journal-attach a PCI device to a
// stopped VM AND run CreateVM (so a cross-producer conflict is exercisable): the
// hotplug-disk server plus an image store and an active host row for placement.
func pciProducerServer(t *testing.T) *Server {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return s
}

// createVMWithBDF is CreateVM for a diskless VM whose only device is the concrete
// BDF — the CreateVM producer in the cross-producer exclusivity tests.
func createVMWithBDF(ctx context.Context, s *Server, name, addr string) error {
	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: "test-host"},
		Network:   []*pb.NetworkAttachment{{Name: "lo", Model: "virtio"}},
		Devices:   []*pb.DeviceSpec{{Address: addr}},
	}})
	return err
}

// TestAttachPCI_StoppedReservesInventory proves a STOPPED concrete-address attach
// now takes the shared inventory reservation (claims host_pci_devices ownership) at
// declare time — WITHOUT any vfio bind or realization (those stay at VM start). RED
// before FIX-9a: the stopped reserve wrote only the intent, leaving the device
// unowned, so a concurrent CreateVM of the same BDF could also claim it.
func TestAttachPCI_StoppedReservesInventory(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// The shared CAS reservation: the stopped attach CLAIMS host_pci_devices ownership.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("stopped attach must claim inventory ownership, got owner %q, want vm1", o)
	}
	// The intent is still reserved.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("want 1 live intent, got %d", len(in))
	}
	// But NO vfio bind and NO realization on a stopped reserve.
	if fs.binds != 0 {
		t.Fatalf("stopped reserve must NOT bind vfio, got %d binds", fs.binds)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("stopped reserve must NOT write realizations, got %d: %+v", len(rs), rs)
	}
}

// TestAttachPCI_vs_CreateVM_SameBDF_OneWins proves the CAS reservation is shared
// ACROSS producers: a stopped attach and a CreateVM racing for the same BDF resolve
// to exactly one winner and exactly one owner. RED before FIX-9a in the
// attach_then_create direction: the stopped attach did not claim inventory, so the
// create's CAS still succeeded (both declared the device).
func TestAttachPCI_vs_CreateVM_SameBDF_OneWins(t *testing.T) {
	const bdf = "0000:41:00.0"

	// Deterministic backstop A: a reserved BDF blocks a later CreateVM of it.
	t.Run("attach_then_create", func(t *testing.T) {
		s := pciProducerServer(t)
		restore := vfio.SetFS(newPCIBindFakeFS())
		defer restore()
		ctx := adminCtx()
		seedPCIGPU(t, s, bdf, -1)
		seedNICVM(t, s, "vm-a", "stopped")

		if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: "vm-a", PciDevice: &pb.DeviceSpec{Address: bdf},
		}); err != nil {
			t.Fatalf("attach: %v", err)
		}
		if err := createVMWithBDF(ctx, s, "vm-b", bdf); err == nil {
			t.Fatal("CreateVM claiming a BDF a stopped attach already reserved must fail")
		}
		if o := pciOwnerOf(t, ctx, s, bdf); o != "vm-a" {
			t.Fatalf("BDF owner = %q, want vm-a (create must not steal a reserved device)", o)
		}
	})

	// Deterministic backstop B: a CreateVM-claimed BDF blocks a later attach of it.
	t.Run("create_then_attach", func(t *testing.T) {
		s := pciProducerServer(t)
		restore := vfio.SetFS(newPCIBindFakeFS())
		defer restore()
		ctx := adminCtx()
		seedPCIGPU(t, s, bdf, -1)

		if err := createVMWithBDF(ctx, s, "vm-b", bdf); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		seedNICVM(t, s, "vm-a", "stopped")
		if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: "vm-a", PciDevice: &pb.DeviceSpec{Address: bdf},
		}); err == nil {
			t.Fatal("attaching a BDF a CreateVM already claimed must fail")
		}
		if o := pciOwnerOf(t, ctx, s, bdf); o != "vm-b" {
			t.Fatalf("BDF owner = %q, want vm-b", o)
		}
	})

	// The concurrency proof (run with -race): exactly one producer wins.
	t.Run("concurrent", func(t *testing.T) {
		s := pciProducerServer(t)
		restore := vfio.SetFS(newPCIBindFakeFS())
		defer restore()
		ctx := adminCtx()
		seedPCIGPU(t, s, bdf, -1)
		seedNICVM(t, s, "vm-a", "stopped")

		var wg sync.WaitGroup
		var okCount int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: "vm-a", PciDevice: &pb.DeviceSpec{Address: bdf},
			}); err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
		go func() {
			defer wg.Done()
			if err := createVMWithBDF(ctx, s, "vm-b", bdf); err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
		wg.Wait()

		if okCount != 1 {
			t.Fatalf("exactly one of {stopped attach, CreateVM} of the same BDF must win, got %d", okCount)
		}
		if o := pciOwnerOf(t, ctx, s, bdf); o != "vm-a" && o != "vm-b" {
			t.Fatalf("the BDF must be owned by exactly one winner, got owner %q", o)
		}
	})
}

// TestDetachPCI_ReleasesStoppedReservation proves a concrete-address detach of a
// STOPPED-reserved device releases the shared inventory reservation the stopped
// attach took. RED before FIX-9a: the stopped attach never claimed, so the
// pre-detach ownership assertion could not hold; the stopped detach path also never
// released ownership.
func TestDetachPCI_ReleasesStoppedReservation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("stopped attach must claim ownership before detach, got owner %q", o)
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: "0000:41:00.0",
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("detach must release the stopped reservation, got owner %q", o)
	}
}

// TestDeletePCI_ReleasesStoppedReservation proves deleting a VM that holds a
// stopped PCI reservation clears its host_pci_devices ownership (releaseDevices →
// ReleasePCIDevicesByVM covers claimed-but-unbound devices).
func TestDeletePCI_ReleasesStoppedReservation(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"},
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "vm1" {
		t.Fatalf("stopped attach must claim ownership, got owner %q", o)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("delete must release the stopped reservation, got owner %q", o)
	}
}

// TestClaimDeviceOwnership_MissingInventory_FailsClosed proves the shared claim
// fails CLOSED for a BDF absent from host_pci_devices: FailedPrecondition, claiming
// nothing. RED before FIX-9a removed the "!present" bind-without-claim branch (which
// treated an un-inventoried BDF as a silent no-op, letting concurrent producers
// bypass the CAS during an inventory gap).
func TestClaimDeviceOwnership_MissingInventory_FailsClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()

	// The BDF is NOT in host_pci_devices.
	release, err := s.claimDeviceOwnership(ctx, "vm1", []ResolvedMember{{Address: "0000:41:00.0"}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing-inventory claim: code = %v, want FailedPrecondition", status.Code(err))
	}
	// Claimed nothing — no ownership row conjured.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("a failed-closed claim must own nothing, got owner %q", o)
	}
	// The returned release is a safe no-op.
	if release != nil {
		release()
	}
}

// TestClaimDeviceOwnership_IOMMUGroup_PartialClaimRollback proves that when a
// multi-member claim fails partway (a later member is owned by another VM), ONLY the
// members THIS call newly claimed are rolled back — the primary is released and the
// other VM's device is untouched. Exercised at the claim primitive directly (the
// public attach path rejects a same-group other-VM sibling earlier via
// checkIOMMUConflict), so the members are constructed by hand.
func TestClaimDeviceOwnership_IOMMUGroup_PartialClaimRollback(t *testing.T) {
	s := hotplugDiskServer(t)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedPCIGPU(t, s, "0000:41:00.0", 20) // primary — inventoried, unowned
	seedPCIGPU(t, s, "0000:41:00.1", 20) // sibling — inventoried
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:41:00.1", "other-vm"); err != nil {
		t.Fatalf("seed sibling ownership: %v", err)
	}

	_, err := s.claimDeviceOwnership(ctx, "vm1", []ResolvedMember{
		{Address: "0000:41:00.0"}, {Address: "0000:41:00.1"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("claim with an other-VM member: code = %v, want AlreadyExists", status.Code(err))
	}
	// The primary claim that momentarily succeeded is rolled back...
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("primary must be released on partial-claim rollback, got owner %q", o)
	}
	// ...and the other VM's device is left untouched.
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.1"); o != "other-vm" {
		t.Fatalf("another VM's device must be untouched, got owner %q", o)
	}
}
