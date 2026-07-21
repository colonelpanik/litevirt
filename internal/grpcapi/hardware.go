package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListVMHardware assembles the typed hardware read model (disks, NICs, PCI
// passthrough devices) for a single VM, shared by the UI and CLI. It mirrors
// InspectVM's shape: RBAC precheck, resolve the VM, forward to its owning
// host if this isn't it, else assemble locally.
func (s *Server) ListVMHardware(ctx context.Context, req *pb.ListVMHardwareRequest) (*pb.ListVMHardwareResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}

	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.ListVMHardware(ctx, req)
	}

	return s.assembleVMHardware(ctx, vm)
}

// assembleVMHardware builds the disk, NIC, and PCI HardwareDevices for vm.
// Only called once the VM is confirmed local (vm.HostName == s.hostName) —
// the PCI ownership fallback below is only meaningful against this host's
// own host_pci_devices rows.
func (s *Server) assembleVMHardware(ctx context.Context, vm *corrosion.VMRecord) (*pb.ListVMHardwareResponse, error) {
	resp := &pb.ListVMHardwareResponse{}

	// Adoption state is UX/read-model only here — best-effort. A lookup error
	// degrades to empty fields (no banner) rather than failing the whole read;
	// the backend's AttachDevice/DetachDevice independently enforce the gate
	// regardless of what this read model reports.
	if state, errReason, err := corrosion.GetHardwareAdoptionState(ctx, s.db, vm.Name); err == nil {
		resp.HardwareAdoptionState = state
		resp.HardwareAdoptionError = errReason
	}

	// Disks. Bus is resolved with the same precedence InspectVM's Spec.Disks
	// projection uses (see resolveDiskBus in vm.go): vm_disks.Bus if set,
	// else the stored spec blob's bus for this disk name, else the
	// target-dev heuristic — never empty.
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	specDiskBuses := diskBusesFromSpec(vm.Spec)
	for _, disk := range disks {
		if disk.DeviceKind != "disk" {
			continue // e.g. cdrom — out of scope for the disk device shape
		}
		resp.Devices = append(resp.Devices, &pb.HardwareDevice{
			Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{
				DeviceId:        disk.DiskName,
				Target:          disk.TargetDev,
				Bus:             resolveDiskBus(disk.Bus, specDiskBuses[disk.DiskName], disk.TargetDev),
				ControllerModel: disk.ControllerModel,
				SizeBytes:       disk.SizeBytes,
				StorageType:     disk.StorageType,
				StorageVolume:   disk.StorageVolume,
				DeleteWithVm:    disk.DeleteWithVM,
				State:           "attached",
			}},
		})
	}

	// NICs — MergedVMNICs overlays the v42 vm_nics table over the legacy
	// vm_interfaces table (see its doc comment); this is the same source
	// InspectVM's Spec.Network projection reads.
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list nics: %v", err)
	}
	sort.Slice(nics, func(i, j int) bool { return nics[i].Ordinal < nics[j].Ordinal })
	for _, nic := range nics {
		resp.Devices = append(resp.Devices, &pb.HardwareDevice{
			Device: &pb.HardwareDevice_Nic{Nic: &pb.HardwareNIC{
				Mac:            nic.MAC,
				Network:        nic.NetworkName,
				Model:          nic.Model,
				Ordinal:        int32(nic.Ordinal),
				SecurityGroups: nic.SecurityGroups,
				State:          "attached",
			}},
		})
	}

	pciDevices, err := s.assembleVMHardwarePCI(ctx, vm)
	if err != nil {
		return nil, err
	}
	resp.Devices = append(resp.Devices, pciDevices...)

	return resp, nil
}

// diskBusesFromSpec parses a VM's stored spec blob (JSON-encoded pb.VMSpec)
// into a disk name -> bus map, for disks that declare a bus in the blob. This
// is the same fallback data InspectVM's Spec.Disks projection builds (see
// specDiskBuses in vmToProto). Returns nil — not an error — on an empty or
// unparseable blob; callers then just skip that fallback tier.
func diskBusesFromSpec(specJSON string) map[string]string {
	if specJSON == "" {
		return nil
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return nil
	}
	m := make(map[string]string, len(spec.Disks))
	for _, ds := range spec.Disks {
		if ds.Bus != "" {
			m[ds.Name] = ds.Bus
		}
	}
	return m
}

// assembleVMHardwarePCI builds the PCI HardwareDevices for vm.
//
// vm_pci_intent/vm_pci_realizations are the Phase-6 authoritative source, but
// are EMPTY fleet-wide until Task 6.3's backfill runs. Building PCI hardware
// ONLY from intents would make ListVMHardware (and any CLI/UI built on it)
// silently show zero PCI devices for every existing passthrough VM today —
// an inaccurate read model, not merely an incomplete one. So: when intents
// exist for this VM, they are authoritative and used exclusively. Otherwise,
// fall back to the live PCI OWNERSHIP source (host_pci_devices.vm_name, the
// same source UpdateVM/reconcile's hostdev rebuild already trusts) so the
// read model reflects what's actually attached. The ownership fallback is
// only meaningful on the host that owns those device rows — callers must
// only reach this once vm.HostName == s.hostName (see ListVMHardware's
// owner-forward), but it degrades to an empty (not erroring) PCI list if
// that invariant is ever violated, rather than misreporting another host's
// devices as this VM's.
func (s *Server) assembleVMHardwarePCI(ctx context.Context, vm *corrosion.VMRecord) ([]*pb.HardwareDevice, error) {
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list PCI intents: %v", err)
	}
	if len(intents) > 0 {
		return s.assembleVMHardwarePCIFromIntents(ctx, vm.Name, intents)
	}

	if vm.HostName != s.hostName {
		return nil, nil
	}
	live, _, err := corrosion.VMDeviceOwnership(ctx, s.db, s.hostName, vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list PCI ownership: %v", err)
	}
	devices := make([]*pb.HardwareDevice, 0, len(live))
	for _, addr := range live {
		devices = append(devices, &pb.HardwareDevice{
			Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId:     addr,
				SelectorKind: "address",
				Desired:      &pb.DeviceSpec{Address: addr},
				Members: []*pb.HardwarePCIMember{
					{ResolvedAddress: addr},
				},
				State: "attached",
			}},
		})
	}
	return devices, nil
}

// assembleVMHardwarePCIFromIntents builds one HardwarePCI per intent row,
// decoding its selector_payload into Desired (protojson, matching
// resolveDeviceIntents'/InspectVM's decode contract for this column — NOT
// encoding/json) and attaching its realized members, if any.
func (s *Server) assembleVMHardwarePCIFromIntents(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord) ([]*pb.HardwareDevice, error) {
	realizations, err := corrosion.ListVMPCIRealizations(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list PCI realizations: %v", err)
	}
	membersByDevice := make(map[string][]*pb.HardwarePCIMember, len(intents))
	for _, r := range realizations {
		membersByDevice[r.DeviceID] = append(membersByDevice[r.DeviceID], &pb.HardwarePCIMember{
			MemberId:        r.MemberID,
			ResolvedAddress: r.ResolvedAddress,
			XmlAlias:        r.XMLAlias,
			Ordinal:         int32(r.Ordinal),
		})
	}
	for _, members := range membersByDevice {
		sort.Slice(members, func(i, j int) bool { return members[i].Ordinal < members[j].Ordinal })
	}

	devices := make([]*pb.HardwareDevice, 0, len(intents))
	for _, intent := range intents {
		var desired *pb.DeviceSpec
		if intent.SelectorPayload != "" {
			desired = &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(intent.SelectorPayload), desired); err != nil {
				slog.Warn("failed to decode PCI intent selector payload", "vm", vmName, "device_id", intent.DeviceID, "error", err)
				desired = nil
			}
		}
		devices = append(devices, &pb.HardwareDevice{
			Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId:     intent.DeviceID,
				SelectorKind: intent.SelectorKind,
				Desired:      desired,
				Members:      membersByDevice[intent.DeviceID],
				State:        "attached",
			}},
		})
	}
	return devices, nil
}
