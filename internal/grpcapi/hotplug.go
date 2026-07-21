package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// AttachDevice hot-attaches a disk, NIC, or PCI device to a running VM.
func (s *Server) AttachDevice(ctx context.Context, req *pb.AttachDeviceRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}

	vmRec, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vmRec == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vmRec), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI attach are journaled, stopped-capable, and
	// at-most-once (Tasks 5.2b/5.2c/5.2d): each owns its forward decision, the
	// operation_protocol_v1/hardware_v2 gates, and the crash-safe DAG, and records
	// its own device.attached event at the owner level. Only address-selector PCI is
	// converted; SR-IOV/type/vendor/mapping selectors keep the legacy running-only
	// attachPCIDevice path below (their resolve is side-effecting / Unimplemented in
	// the pure resolver, and the foundation UI only creates concrete-address PCI).
	if req.Disk != nil {
		out, err := s.attachDiskEntry(ctx, req, vmRec)
		if err != nil {
			return nil, err
		}
		s.recordVMEvent(ctx, req.VmName, "device.attached", "ok", "disk "+req.Disk.Name)
		return out, nil
	}
	if req.Nic != nil {
		return s.attachNICEntry(ctx, req, vmRec)
	}
	if req.PciDevice != nil {
		if kind, _ := corrosion.ClassifyPCISelector(req.PciDevice); kind == "address" {
			return s.attachPCIEntry(ctx, req, vmRec)
		}
		// Non-address selectors fall through to the legacy running-only path below.
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.AttachDevice(ctx, req)
	}
	// Mutation barrier: don't hot-plug while a resource operation holds the VM.
	if vmRec.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot attach a device to %q: an operation is in progress", req.VmName)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (
		out    *pb.VM
		detail string
	)
	switch {
	case req.PciDevice != nil:
		out, err = s.attachPCIDevice(ctx, req.VmName, req.PciDevice)
		detail = "pci device"
	default:
		return nil, status.Error(codes.InvalidArgument, "one of disk, nic, or pci_device must be specified")
	}
	if err != nil {
		return nil, err
	}
	s.recordVMEvent(ctx, req.VmName, "device.attached", "ok", detail)
	return out, nil
}

// DetachDevice hot-detaches a disk, NIC, or PCI device from a running VM.
func (s *Server) DetachDevice(ctx context.Context, req *pb.DetachDeviceRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}

	vmRec, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vmRec == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vmRec), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI detach are journaled, stopped-capable, and
	// at-most-once (Tasks 5.2b/5.2c/5.2d); each owns its forward + gates and records
	// its own device.detached event at the owner level. A PCI address that backs a
	// live address-kind vm_pci_intent takes the journaled path; any other PCI address
	// (attached via the legacy SR-IOV/type path or CreateVM ownership) keeps the
	// legacy running-only detachPCIDevice path below.
	if req.DiskName != "" {
		out, err := s.detachDiskEntry(ctx, req, vmRec)
		if err != nil {
			return nil, err
		}
		s.recordVMEvent(ctx, req.VmName, "device.detached", "ok", "disk "+req.DiskName)
		return out, nil
	}
	if req.NicMac != "" {
		return s.detachNICEntry(ctx, req, vmRec)
	}
	if req.PciAddress != "" {
		_, journaled, ierr := s.liveAddressIntent(ctx, vmRec.Name, req.PciAddress)
		if ierr != nil {
			return nil, status.Errorf(codes.Internal, "read PCI intents for %q: %v", req.VmName, ierr)
		}
		if journaled {
			return s.detachPCIEntry(ctx, req, vmRec)
		}
		// No concrete-address intent → legacy running-only path below.
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.DetachDevice(ctx, req)
	}
	// Mutation barrier: don't hot-unplug while a resource operation holds the VM.
	if vmRec.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot detach a device from %q: an operation is in progress", req.VmName)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (
		out    *pb.VM
		detail string
	)
	switch {
	case req.PciAddress != "":
		out, err = s.detachPCIDevice(ctx, req.VmName, req.PciAddress)
		detail = "pci " + req.PciAddress
	default:
		return nil, status.Error(codes.InvalidArgument, "one of disk_name, nic_mac, or pci_address must be specified")
	}
	if err != nil {
		return nil, err
	}
	s.recordVMEvent(ctx, req.VmName, "device.detached", "ok", detail)
	return out, nil
}

func (s *Server) attachPCIDevice(ctx context.Context, vmName string, spec *pb.DeviceSpec) (*pb.VM, error) {
	addrs, finish, err := s.allocateDevices(ctx, vmName, []*pb.DeviceSpec{spec})
	if err != nil {
		return nil, err
	}
	// Clear the durable device lease once the attach completes (or on the
	// rollback below); a crash before this runs is recovered at startup.
	defer finish()

	for _, addr := range addrs {
		if err := s.virt.AttachHostdev(vmName, addr); err != nil {
			// Roll back only the devices THIS attach claimed (not the VM's
			// pre-existing passthrough devices).
			s.releaseDeviceLeases(ctx, vmName, addrs)
			return nil, status.Errorf(codes.Internal, "attach PCI device %s: %v", addr, err)
		}
		slog.Info("PCI device attached", "vm", vmName, "address", addr)
	}

	s.publish("device.attached", vmName, fmt.Sprintf("pci:%v", addrs))
	return s.vmToProto(ctx, vmName)
}

func (s *Server) detachPCIDevice(ctx context.Context, vmName, pciAddress string) (*pb.VM, error) {
	if err := s.virt.DetachHostdev(vmName, pciAddress); err != nil {
		return nil, status.Errorf(codes.Internal, "detach PCI device %s: %v", pciAddress, err)
	}

	if err := vfio.Unbind(pciAddress, ""); err != nil {
		slog.Warn("VFIO unbind after detach failed", "address", pciAddress, "error", err)
	}

	corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, pciAddress, vmName)
	slog.Info("PCI device detached", "vm", vmName, "address", pciAddress)
	s.publish("device.detached", vmName, "pci:"+pciAddress)
	return s.vmToProto(ctx, vmName)
}

// countVMDisks returns the number of disks currently attached to a VM.
func countVMDisks(ctx context.Context, db *corrosion.Client, vmName string) int {
	disks, _ := corrosion.ListDisks(ctx, db, vmName)
	return len(disks)
}

// parseDiskSize parses sizes like "20G", "100G" into GB.
func parseDiskSize(size string) (int, error) {
	if size == "" {
		return 0, fmt.Errorf("size is required")
	}
	var n int
	var unit string
	_, err := fmt.Sscanf(size, "%d%s", &n, &unit)
	if err != nil {
		// Try plain number.
		_, err = fmt.Sscanf(size, "%d", &n)
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q", size)
		}
		return n, nil
	}
	switch unit {
	case "G", "GB", "g", "gb":
		return n, nil
	case "T", "TB", "t", "tb":
		return n * 1024, nil
	case "M", "MB", "m", "mb":
		if n < 1024 {
			return 1, nil
		}
		return n / 1024, nil
	default:
		return n, nil
	}
}
