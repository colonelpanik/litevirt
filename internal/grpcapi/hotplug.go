package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/qcow2"
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
	// For a NIC attach, ensure the target network is provisioned on the VM's
	// host *before* we plug into its bridge. CreateNetwork only provisions on
	// the host it ran on; the network record may not have replicated to the
	// VM's host yet. This host (where the request first landed) typically holds
	// the record, so push a provision to the VM's host from here — otherwise
	// attachNIC there finds no local record and the attach fails with a cryptic
	// libvirt "Cannot get interface MTU on '<net>': No such device".
	if req.Nic != nil && req.Nic.Name != "" && vmRec.HostName != s.hostName {
		s.provisionNetworkOnRemote(ctx, vmRec.HostName, req.Nic.Name)
	}
	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.AttachDevice(ctx, req)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (out *pb.VM; detail string)
	switch {
	case req.Disk != nil:
		out, err = s.attachDisk(ctx, req.VmName, req.Disk)
		detail = "disk " + req.Disk.Name
	case req.Nic != nil:
		out, err = s.attachNIC(ctx, req.VmName, req.Nic)
		detail = "nic " + req.Nic.Name
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
	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.DetachDevice(ctx, req)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (out *pb.VM; detail string)
	switch {
	case req.DiskName != "":
		out, err = s.detachDisk(ctx, req.VmName, req.DiskName)
		detail = "disk " + req.DiskName
	case req.NicMac != "":
		out, err = s.detachNIC(ctx, req.VmName, req.NicMac)
		detail = "nic " + req.NicMac
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

func (s *Server) attachDisk(ctx context.Context, vmName string, spec *pb.DiskSpec) (*pb.VM, error) {
	bus := spec.Bus
	if bus == "" {
		bus = "virtio"
	}

	// Create disk file. Validate the names before they reach the path so a
	// hotplugged disk can't escape the disks directory.
	diskPath, err := libvirt.SafeDiskPath(s.dataDir, vmName, spec.Name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	sizeGB, err := parseDiskSize(spec.Size)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid disk size: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(diskPath), 0755); err != nil {
		return nil, status.Errorf(codes.Internal, "create disk dir: %v", err)
	}
	sizeBytes := uint64(sizeGB) * 1024 * 1024 * 1024
	if err := qcow2.Create(diskPath, sizeBytes, nil); err != nil {
		return nil, status.Errorf(codes.Internal, "create disk: %v", err)
	}

	// Pick a target device name (vdX for virtio, sdX for scsi/sata).
	diskCount := countVMDisks(ctx, s.db, vmName)
	prefix := "vd"
	if bus == "scsi" || bus == "sata" {
		prefix = "sd"
	}
	targetDev := fmt.Sprintf("%s%c", prefix, 'b'+diskCount)

	if err := s.virt.AttachDisk(vmName, diskPath, targetDev, bus); err != nil {
		return nil, status.Errorf(codes.Internal, "attach disk: %v", err)
	}

	// Record in DB.
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:      vmName,
		DiskName:    spec.Name,
		HostName:    s.hostName,
		Path:        diskPath,
		SizeBytes:   int64(sizeGB) * 1024 * 1024 * 1024,
		StorageType: "local",
		TargetDev:   targetDev,
	}); err != nil {
		slog.Warn("failed to record disk in DB", "vm", vmName, "disk", spec.Name, "error", err)
	}

	slog.Info("disk attached", "vm", vmName, "disk", spec.Name, "target", targetDev)
	s.publish("device.attached", vmName, "disk:"+spec.Name)
	return s.vmToProto(ctx, vmName)
}

func (s *Server) detachDisk(ctx context.Context, vmName, diskName string) (*pb.VM, error) {
	// Look up the disk's stored target device name.
	disks, _ := corrosion.ListDisks(ctx, s.db, vmName)
	var targetDev string
	for _, d := range disks {
		if d.DiskName == diskName {
			targetDev = d.TargetDev
			break
		}
	}
	if targetDev == "" {
		return nil, status.Errorf(codes.NotFound, "disk %q not found on VM %q", diskName, vmName)
	}

	if err := s.virt.DetachDisk(vmName, targetDev); err != nil {
		return nil, status.Errorf(codes.Internal, "detach disk: %v", err)
	}

	corrosion.SoftDeleteDisk(ctx, s.db, vmName, diskName)
	slog.Info("disk detached", "vm", vmName, "disk", diskName)
	s.publish("device.detached", vmName, "disk:"+diskName)
	return s.vmToProto(ctx, vmName)
}

func (s *Server) attachNIC(ctx context.Context, vmName string, spec *pb.NetworkAttachment) (*pb.VM, error) {
	mac := spec.Mac
	if mac == "" {
		mac = libvirt.GenerateMAC()
	}
	bridge := resolveBridge(ctx, s.db, spec.Name)

	// Ensure the bridge exists on this host — it may have been created
	// on a different node. Provision locally if needed.
	nr, _ := corrosion.GetNetwork(ctx, s.db, spec.Name)
	if nr != nil && nr.Config != "" {
		var def compose.NetworkDef
		if json.Unmarshal([]byte(nr.Config), &def) == nil {
			def.Type = nr.Type
			if def.Interface == "" {
				def.Interface = spec.Name
			}
			localIP := getLocalIP()
			if _, err := network.SafeProvision(ctx, s.db, spec.Name, def, localIP, s.hostName); err != nil {
				slog.Warn("attachNIC: failed to provision network locally", "network", spec.Name, "error", err)
			}
		}
	}

	model := spec.Model
	if model == "" {
		model = "virtio"
	}

	if err := s.virt.AttachNIC(vmName, bridge, model, mac); err != nil {
		return nil, status.Errorf(codes.Internal, "attach NIC: %v", err)
	}

	corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName:      vmName,
		NetworkName: spec.Name,
		MAC:         mac,
	})

	slog.Info("NIC attached", "vm", vmName, "network", spec.Name, "mac", mac)
	s.publish("device.attached", vmName, "nic:"+mac)
	return s.vmToProto(ctx, vmName)
}

func (s *Server) detachNIC(ctx context.Context, vmName, mac string) (*pb.VM, error) {
	if err := s.virt.DetachNIC(vmName, mac); err != nil {
		return nil, status.Errorf(codes.Internal, "detach NIC: %v", err)
	}

	corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, vmName, mac)
	slog.Info("NIC detached", "vm", vmName, "mac", mac)
	s.publish("device.detached", vmName, "nic:"+mac)
	return s.vmToProto(ctx, vmName)
}

func (s *Server) attachPCIDevice(ctx context.Context, vmName string, spec *pb.DeviceSpec) (*pb.VM, error) {
	addrs, err := s.allocateDevices(ctx, vmName, []*pb.DeviceSpec{spec})
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if err := s.virt.AttachHostdev(vmName, addr); err != nil {
			// Roll back VFIO bindings.
			s.releaseDevices(ctx, vmName)
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

	corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, pciAddress)
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
