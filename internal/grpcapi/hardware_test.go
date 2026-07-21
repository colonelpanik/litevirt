package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestListVMHardware_OwnershipFallback is the dormancy-fallback case:
// vm_pci_intent is empty fleet-wide (pre-backfill) for a VM that DOES
// have a real PCI device attached via the live ownership table
// (host_pci_devices.vm_name, the same source UpdateVM/reconcile already use).
// ListVMHardware must still surface that device instead of silently showing
// zero PCI hardware for an existing passthrough VM.
func TestListVMHardware_OwnershipFallback(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hw-vm", HostName: "test-host", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "hw-vm", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"},
	}, []corrosion.DiskRecord{
		{VMName: "hw-vm", DiskName: "root", HostName: "test-host", Path: "/vms/hw-vm/root.qcow2",
			SizeBytes: 20 << 30, StorageType: "local", TargetDev: "vda", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:01:00.0", Type: "gpu",
	}); err != nil {
		t.Fatalf("ObservePCIDevice: %v", err)
	}
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", "0000:01:00.0", "hw-vm"); err != nil {
		t.Fatalf("AssignPCIDevice: %v", err)
	}
	// Deliberately no vm_pci_intent rows — exercises the ownership fallback.

	resp, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "hw-vm"})
	if err != nil {
		t.Fatalf("ListVMHardware: %v", err)
	}
	if len(resp.Devices) != 3 {
		t.Fatalf("got %d devices, want 3 (disk+nic+pci): %+v", len(resp.Devices), resp.Devices)
	}

	var disk *pb.HardwareDisk
	var nic *pb.HardwareNIC
	var pci *pb.HardwarePCI
	for _, d := range resp.Devices {
		switch dv := d.Device.(type) {
		case *pb.HardwareDevice_Disk:
			disk = dv.Disk
		case *pb.HardwareDevice_Nic:
			nic = dv.Nic
		case *pb.HardwareDevice_Pci:
			pci = dv.Pci
		default:
			t.Fatalf("unexpected device type %T", dv)
		}
	}

	if disk == nil {
		t.Fatal("no disk device in response")
	}
	if disk.Target != "vda" || disk.Bus != "virtio" {
		t.Errorf("disk target/bus = %q/%q, want vda/virtio", disk.Target, disk.Bus)
	}
	if disk.DeviceId != "root" {
		t.Errorf("disk device_id = %q, want root", disk.DeviceId)
	}

	if nic == nil {
		t.Fatal("no nic device in response")
	}
	if nic.Mac != "52:54:00:aa:bb:cc" {
		t.Errorf("nic mac = %q, want 52:54:00:aa:bb:cc", nic.Mac)
	}
	if nic.Network != "lan" {
		t.Errorf("nic network = %q, want lan", nic.Network)
	}

	if pci == nil {
		t.Fatal("no pci device in response")
	}
	if pci.SelectorKind != "address" {
		t.Errorf("pci selector_kind = %q, want address", pci.SelectorKind)
	}
	if pci.Desired == nil || pci.Desired.Address != "0000:01:00.0" {
		t.Errorf("pci desired = %+v, want address 0000:01:00.0", pci.Desired)
	}
	if len(pci.Members) != 1 || pci.Members[0].ResolvedAddress != "0000:01:00.0" {
		t.Errorf("pci members = %+v, want one member with resolved_address 0000:01:00.0", pci.Members)
	}
}

// TestListVMHardware_FromIntents is the positive counterpart: once
// vm_pci_intent rows exist for a VM (the Phase-6 device-request cutover),
// PCI hardware must build from intents+realizations rather than the
// ownership fallback.
func TestListVMHardware_FromIntents(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hw-vm2", HostName: "test-host", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de", Count: 1})
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, s.db, corrosion.PCIIntentRecord{
		VMName: "hw-vm2", DeviceID: "dev0", HostName: "test-host",
		SelectorKind: "type", SelectorPayload: string(payload),
	}); err != nil {
		t.Fatalf("UpsertPCIIntent: %v", err)
	}
	if err := corrosion.UpsertPCIRealization(ctx, s.db, corrosion.PCIRealizationRecord{
		VMName: "hw-vm2", DeviceID: "dev0", MemberID: "m0", HostName: "test-host",
		ResolvedAddress: "0000:02:00.0", XMLAlias: "hostdev0",
	}); err != nil {
		t.Fatalf("UpsertPCIRealization: %v", err)
	}

	resp, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "hw-vm2"})
	if err != nil {
		t.Fatalf("ListVMHardware: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("got %d devices, want 1 (pci only, from intents): %+v", len(resp.Devices), resp.Devices)
	}
	pci := resp.Devices[0].GetPci()
	if pci == nil {
		t.Fatalf("device is not PCI: %+v", resp.Devices[0])
	}
	if pci.DeviceId != "dev0" {
		t.Errorf("pci device_id = %q, want dev0", pci.DeviceId)
	}
	if pci.SelectorKind != "type" {
		t.Errorf("selector_kind = %q, want type", pci.SelectorKind)
	}
	if pci.Desired == nil || pci.Desired.Type != "gpu" || pci.Desired.Vendor != "10de" {
		t.Errorf("desired = %+v, want gpu/10de", pci.Desired)
	}
	if len(pci.Members) != 1 || pci.Members[0].ResolvedAddress != "0000:02:00.0" || pci.Members[0].XmlAlias != "hostdev0" {
		t.Errorf("members = %+v, want one member 0000:02:00.0/hostdev0", pci.Members)
	}
}

// TestListVMHardware_AdoptionState verifies the read-model side:
// ListVMHardware must surface a VM's hardware-adoption state and
// blocked-reason so the UI's Hardware tab can render a gating banner,
// without requiring the caller to separately query
// GetHardwareAdoptionState.
func TestListVMHardware_AdoptionState(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hw-vm3", HostName: "test-host", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "hw-vm3", "blocked", "ambiguous PCI grouping"); err != nil {
		t.Fatalf("SetHardwareAdoptionState: %v", err)
	}

	resp, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "hw-vm3"})
	if err != nil {
		t.Fatalf("ListVMHardware: %v", err)
	}
	if resp.HardwareAdoptionState != "blocked" {
		t.Errorf("HardwareAdoptionState = %q, want blocked", resp.HardwareAdoptionState)
	}
	if resp.HardwareAdoptionError != "ambiguous PCI grouping" {
		t.Errorf("HardwareAdoptionError = %q, want %q", resp.HardwareAdoptionError, "ambiguous PCI grouping")
	}
}

func TestListVMHardware_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound (err=%v)", status.Code(err), err)
	}
}

func TestListVMHardware_InsufficientRole(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	_, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "hw-vm"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

// TestListVMHardware_ForwardToPeer asserts the owner-forward path is taken
// for a VM owned by a different host, mirroring TestGetVMLogs_ForwardToPeer:
// the peer host isn't registered/reachable in the test cluster state, so the
// forward attempt itself surfaces as Unavailable.
func TestListVMHardware_ForwardToPeer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "remote-hw-vm", HostName: "other-host", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	_, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: "remote-hw-vm"})
	if err == nil {
		t.Fatal("expected error (peer not reachable)")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
}
