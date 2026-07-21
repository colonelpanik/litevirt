package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"

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
	// Adoption gate (fail-closed): under the active hardware_v2 regime a blocked VM
	// must not have its hardware mutated until it is repaired + re-audited. No-op
	// pre-latch (adoption state is informational only then).
	if err := s.hardwareAdoptionRefused(ctx, vmRec.Name); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI attach are journaled, stopped-capable, and
	// at-most-once: each owns its forward decision, the
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
	// Adoption gate (fail-closed): under the active hardware_v2 regime a blocked VM
	// must not have its hardware mutated until it is repaired + re-audited. No-op
	// pre-latch (adoption state is informational only then).
	if err := s.hardwareAdoptionRefused(ctx, vmRec.Name); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI detach are journaled, stopped-capable, and
	// at-most-once; each owns its forward + gates and records
	// its own device.detached event at the owner level. A PCI address that backs a
	// live address-kind vm_pci_intent takes the journaled path; any other PCI address
	// (attached via the legacy SR-IOV/type path or CreateVM ownership) keeps the
	// legacy running-only detachPCIDevice path below.
	if req.DiskName != "" {
		out, err := s.detachDiskEntry(ctx, req, vmRec)
		if err != nil {
			return nil, err
		}
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

// maxDiskSizeGB is a sane upper bound on a requested disk size (in GB). It exists
// so the later uint64(sizeGB)*1024*1024*1024 byte-size conversion can never
// overflow — no real disk request needs a size anywhere near this cap.
const maxDiskSizeGB = 1 << 20 // ~1 PiB

// diskSizeRe matches an exact disk-size string: a run of digits, optional
// whitespace, then an optional unit suffix — and nothing else. The trailing
// $ anchor is what makes parsing exact: any leftover characters (garbage
// after a valid unit, a second token, a decimal point, a bare sign) fail to
// match rather than being silently ignored.
var diskSizeRe = regexp.MustCompile(`^([0-9]+)\s*([A-Za-z]*)$`)

// parseDiskSize parses sizes like "20G", "100G" into GB. It fails closed: a
// non-positive magnitude, an unrecognized unit, a magnitude that would scale
// beyond maxDiskSizeGB, or any input with trailing/malformed content beyond a
// plain "<digits><unit>" are all rejected rather than silently accepted (a
// bare unknown unit must NOT be treated as GiB, and garbage after a valid
// unit must NOT be truncated away).
func parseDiskSize(size string) (int, error) {
	if size == "" {
		return 0, fmt.Errorf("size is required")
	}
	m := diskSizeRe.FindStringSubmatch(size)
	if m == nil {
		return 0, fmt.Errorf("cannot parse %q", size)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q", size)
	}
	unit := m[2]
	if n <= 0 {
		return 0, fmt.Errorf("size must be positive: %q", size)
	}
	// Bound n before it is ever multiplied (the T/TB branch below computes
	// n*1024): without this, a large-but-parseable n can overflow the int64
	// multiply — wrapping to zero or negative — and slip past the final
	// gb > maxDiskSizeGB check with a nil error.
	if n > maxDiskSizeGB {
		return 0, fmt.Errorf("size %q exceeds the maximum allowed disk size", size)
	}
	var gb int
	switch unit {
	case "", "G", "GB", "g", "gb":
		gb = n
	case "T", "TB", "t", "tb":
		gb = n * 1024
	case "M", "MB", "m", "mb":
		if n < 1024 {
			gb = 1
		} else {
			gb = n / 1024
		}
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}
	if gb > maxDiskSizeGB {
		return 0, fmt.Errorf("size %q exceeds the maximum allowed disk size", size)
	}
	return gb, nil
}
