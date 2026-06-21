package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// RescanHost triggers a PCI device rescan on the local host and updates the DB.
func (s *Server) RescanHost(ctx context.Context, req *pb.RescanHostRequest) (*pb.RescanHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Name != "" && req.Name != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Name, err)
		}
		defer conn.Close()
		return client.RescanHost(ctx, req)
	}

	// Get existing devices from DB to calculate diff.
	existing, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list existing devices: %v", err)
	}
	existingMap := make(map[string]bool, len(existing))
	for _, d := range existing {
		existingMap[d.Address] = true
	}

	// Scan the host.
	scanned, err := pci.Scan()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "PCI scan: %v", err)
	}

	interesting := pci.FilterInteresting(scanned)

	var added, removed int32
	scannedMap := make(map[string]bool, len(interesting))

	for _, d := range interesting {
		scannedMap[d.Address] = true
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName:      s.hostName,
			Address:       d.Address,
			VendorID:      d.VendorID,
			DeviceID:      d.DeviceID,
			VendorName:    d.VendorName,
			DeviceName:    d.DeviceName,
			Type:          d.Type,
			IOMMUGroup:    d.IOMMUGroup,
			SRIOVCapable:  d.SRIOVCapable,
			SRIOVVFsTotal: d.SRIOVVFsTotal,
			SRIOVVFsFree:  d.SRIOVVFsFree,
			Driver:        d.Driver,
			NUMANode:      d.NUMANode,
		}); err != nil {
			slog.Warn("failed to upsert PCI device", "address", d.Address, "error", err)
		}
		if !existingMap[d.Address] {
			added++
			s.publish("device.added", s.hostName, d.Address+" "+d.Type)
		}

		// Track individual VFs for SR-IOV capable PFs so that VF pool
		// exhaustion is properly detected (#36).
		if d.SRIOVCapable && d.SRIOVVFsTotal > 0 {
			vfAddrs, err := pci.ListVFs(d.Address)
			if err != nil {
				slog.Debug("rescan: list VFs", "pf", d.Address, "error", err)
				continue
			}
			for _, vfAddr := range vfAddrs {
				scannedMap[vfAddr] = true
				vfDev, scanErr := pci.ScanDevice(vfAddr)
				if scanErr != nil {
					continue
				}
				if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
					HostName:   s.hostName,
					Address:    vfDev.Address,
					VendorID:   vfDev.VendorID,
					DeviceID:   vfDev.DeviceID,
					VendorName: vfDev.VendorName,
					DeviceName: vfDev.DeviceName,
					Type:       vfDev.Type,
					IOMMUGroup: vfDev.IOMMUGroup,
					Driver:     vfDev.Driver,
					NUMANode:   vfDev.NUMANode,
				}); err != nil {
					slog.Debug("rescan: upsert VF", "address", vfAddr, "error", err)
				}
				if !existingMap[vfAddr] {
					added++
				}
			}
		}
	}

	// Mark disappeared devices.
	for _, d := range existing {
		if !scannedMap[d.Address] {
			removed++
			corrosion.SoftDeletePCIDevice(ctx, s.db, s.hostName, d.Address)
			s.publish("device.removed", s.hostName, d.Address+" "+d.Type)
			if d.VMName != "" {
				slog.Error("assigned device disappeared", "address", d.Address, "vm", d.VMName)
				s.publish("device.lost", d.VMName, d.Address+" was assigned to running VM")
			}
		}
	}

	// Build response.
	devices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	resp := &pb.RescanHostResponse{
		Added:   added,
		Removed: removed,
		Total:   int32(len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, pciDeviceToProto(d))
	}

	slog.Info("PCI rescan complete", "added", added, "removed", removed, "total", len(devices))
	return resp, nil
}

// ListHostDevices returns PCI devices for a host.
func (s *Server) ListHostDevices(ctx context.Context, req *pb.ListHostDevicesRequest) (*pb.ListHostDevicesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	hostName := req.Name
	if hostName == "" {
		hostName = s.hostName
	}

	devices, err := corrosion.ListPCIDevices(ctx, s.db, hostName, req.TypeFilter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list devices: %v", err)
	}

	resp := &pb.ListHostDevicesResponse{}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, pciDeviceToProto(d))
	}
	return resp, nil
}

// allocateDevices resolves DeviceSpec requests against host inventory,
// validates IOMMU group conflicts, assigns devices, binds to VFIO-PCI,
// and returns the PCI addresses for hostdev XML.
func (s *Server) allocateDevices(ctx context.Context, vmName string, specs []*pb.DeviceSpec) ([]string, error) {
	var addresses []string

	for _, spec := range specs {
		count := int(spec.Count)
		if count == 0 {
			count = 1
		}

		// Resource mapping (#14): resolve a cluster-wide mapping name to the
		// concrete PCI address registered for THIS host, then allocate it as an
		// exact pin. This is what lets a passthrough VM land on / migrate to any
		// host that has a device under the same mapping.
		if spec.Mapping != "" && spec.Address == "" {
			addr, err := corrosion.ResolveMappingAddress(ctx, s.db, spec.Mapping, s.hostName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "resolve resource mapping %q: %v", spec.Mapping, err)
			}
			if addr == "" {
				return nil, status.Errorf(codes.FailedPrecondition,
					"resource mapping %q has no device on host %s", spec.Mapping, s.hostName)
			}
			spec.Address = addr
		}

		// SR-IOV VF allocation: create a VF on-demand if requested.
		if spec.Sriov && spec.Address == "" {
			vfAddrs, err := s.allocateSRIOVVFs(ctx, vmName, spec, count)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, vfAddrs...)
			continue
		}

		// Exact address pinning.
		if spec.Address != "" {
			// Validate IOMMU group conflict before assignment.
			if err := s.checkIOMMUConflict(ctx, spec.Address, vmName); err != nil {
				return nil, err
			}

			addresses = append(addresses, spec.Address)
			if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, spec.Address, vmName); err != nil {
				slog.Warn("failed to record device assignment", "address", spec.Address, "error", err)
			}

			// Also assign IOMMU group siblings.
			groupAddrs, _ := s.iommuGroupSiblings(ctx, spec.Address)
			for _, a := range groupAddrs {
				if a != spec.Address {
					addresses = append(addresses, a)
					corrosion.AssignPCIDevice(ctx, s.db, s.hostName, a, vmName)
				}
			}
			continue
		}

		// Type-based allocation.
		available, err := corrosion.GetAvailableDevicesByType(ctx, s.db, s.hostName, spec.Type)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "query devices: %v", err)
		}

		// Filter by vendor/model if specified.
		var matched []corrosion.PCIDeviceRecord
		for _, d := range available {
			if spec.Vendor != "" && d.VendorID != spec.Vendor {
				continue
			}
			if spec.Model != "" && d.DeviceName != spec.Model {
				continue
			}
			matched = append(matched, d)
		}

		if len(matched) < count {
			return nil, status.Errorf(codes.ResourceExhausted,
				"need %d %s device(s) but only %d available on host %s",
				count, spec.Type, len(matched), s.hostName)
		}

		for i := 0; i < count; i++ {
			d := matched[i]

			// Validate IOMMU group conflict.
			if err := s.checkIOMMUConflict(ctx, d.Address, vmName); err != nil {
				return nil, err
			}

			addresses = append(addresses, d.Address)
			corrosion.AssignPCIDevice(ctx, s.db, s.hostName, d.Address, vmName)

			// IOMMU group siblings.
			groupAddrs, _ := s.iommuGroupSiblings(ctx, d.Address)
			for _, a := range groupAddrs {
				if a != d.Address {
					addresses = append(addresses, a)
					corrosion.AssignPCIDevice(ctx, s.db, s.hostName, a, vmName)
				}
			}
		}
	}

	// Bind all allocated devices to vfio-pci.
	for _, addr := range addresses {
		prevDriver, err := vfio.Bind(addr)
		if err != nil {
			slog.Warn("VFIO bind failed", "address", addr, "error", err)
			// Roll back: release all assigned devices.
			s.releaseDevices(ctx, vmName)
			return nil, status.Errorf(codes.Internal,
				"failed to bind device %s to vfio-pci: %v", addr, err)
		}
		slog.Info("device bound to vfio-pci", "address", addr, "previous_driver", prevDriver)
	}

	return addresses, nil
}

// releaseDevices unbinds all devices from vfio-pci and releases them in the DB.
func (s *Server) releaseDevices(ctx context.Context, vmName string) {
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		slog.Warn("failed to list devices for release", "vm", vmName, "error", err)
		return
	}

	for _, d := range devices {
		if d.VMName == vmName {
			if err := vfio.Unbind(d.Address, d.Driver); err != nil {
				slog.Warn("VFIO unbind failed", "address", d.Address, "error", err)
			} else {
				slog.Info("device unbound from vfio-pci", "address", d.Address, "restored_driver", d.Driver)
			}
		}
	}

	if err := corrosion.ReleasePCIDevicesByVM(ctx, s.db, vmName); err != nil {
		slog.Warn("failed to release PCI devices in DB", "vm", vmName, "error", err)
	}
}

// checkIOMMUConflict verifies that no device in the same IOMMU group
// is already assigned to a different VM. If a sibling is assigned to
// another VM, the allocation is rejected.
func (s *Server) checkIOMMUConflict(ctx context.Context, address, vmName string) error {
	devices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	var iommuGroup int = -1
	for _, d := range devices {
		if d.Address == address {
			iommuGroup = d.IOMMUGroup
			break
		}
	}
	if iommuGroup < 0 {
		return nil // no IOMMU group — no conflict possible
	}

	group, err := corrosion.GetDevicesByIOMMUGroup(ctx, s.db, s.hostName, iommuGroup)
	if err != nil {
		return nil // can't check — allow
	}

	for _, d := range group {
		if d.VMName != "" && d.VMName != vmName {
			return status.Errorf(codes.FailedPrecondition,
				"IOMMU group %d conflict: device %s is already assigned to VM %q, "+
					"cannot assign device %s from the same group to VM %q",
				iommuGroup, d.Address, d.VMName, address, vmName)
		}
	}
	return nil
}

// allocateSRIOVVFs creates VFs on-demand for an SR-IOV device spec and returns
// the PCI addresses of the created VFs.
func (s *Server) allocateSRIOVVFs(ctx context.Context, vmName string, spec *pb.DeviceSpec, count int) ([]string, error) {
	// Find a suitable PF (physical function).
	pfAddr := spec.Parent
	if pfAddr == "" {
		// Auto-select: find an SR-IOV capable device of the right type with free VFs.
		devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, spec.Type)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list devices: %v", err)
		}
		for _, d := range devices {
			if d.SRIOVCapable && d.SRIOVVFsFree >= count {
				pfAddr = d.Address
				break
			}
		}
		if pfAddr == "" {
			return nil, status.Errorf(codes.ResourceExhausted,
				"no SR-IOV capable %s device with %d free VFs on host %s",
				spec.Type, count, s.hostName)
		}
	}

	// Create VFs by writing to sriov_numvfs.
	vfAddrs, err := pci.CreateVFs(pfAddr, count)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to create %d VFs on PF %s: %v", count, pfAddr, err)
	}

	// Rescan to pick up new VFs in our inventory.
	for _, vfAddr := range vfAddrs {
		d, scanErr := pci.ScanDevice(vfAddr)
		if scanErr != nil {
			slog.Warn("failed to scan new VF", "address", vfAddr, "error", scanErr)
			continue
		}
		corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName:   s.hostName,
			Address:    d.Address,
			VendorID:   d.VendorID,
			DeviceID:   d.DeviceID,
			VendorName: d.VendorName,
			DeviceName: d.DeviceName,
			Type:       d.Type,
			IOMMUGroup: d.IOMMUGroup,
			Driver:     d.Driver,
			NUMANode:   d.NUMANode,
		})
		corrosion.AssignPCIDevice(ctx, s.db, s.hostName, vfAddr, vmName)
	}

	// Bind VFs to vfio-pci.
	for _, addr := range vfAddrs {
		if _, err := vfio.Bind(addr); err != nil {
			slog.Warn("VFIO bind VF failed", "address", addr, "error", err)
			s.releaseDevices(ctx, vmName)
			return nil, status.Errorf(codes.Internal,
				"failed to bind VF %s to vfio-pci: %v", addr, err)
		}
	}

	slog.Info("SR-IOV VFs allocated", "pf", pfAddr, "count", count, "vfs", vfAddrs, "vm", vmName)
	return vfAddrs, nil
}

// iommuGroupSiblings returns all PCI addresses in the same IOMMU group.
func (s *Server) iommuGroupSiblings(ctx context.Context, address string) ([]string, error) {
	devices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	for _, d := range devices {
		if d.Address == address && d.IOMMUGroup >= 0 {
			group, err := corrosion.GetDevicesByIOMMUGroup(ctx, s.db, s.hostName, d.IOMMUGroup)
			if err != nil {
				return nil, err
			}
			addrs := make([]string, len(group))
			for i, g := range group {
				addrs[i] = g.Address
			}
			return addrs, nil
		}
	}
	return []string{address}, nil
}

func pciDeviceToProto(d corrosion.PCIDeviceRecord) *pb.PCIDevice {
	var linkPeers []string
	if d.LinkPeers != "" {
		for _, p := range strings.Split(d.LinkPeers, ",") {
			if p = strings.TrimSpace(p); p != "" {
				linkPeers = append(linkPeers, p)
			}
		}
	}
	return &pb.PCIDevice{
		HostName:      d.HostName,
		Address:       d.Address,
		VendorId:      d.VendorID,
		DeviceId:      d.DeviceID,
		VendorName:    d.VendorName,
		DeviceName:    d.DeviceName,
		Type:          d.Type,
		IommuGroup:    int32(d.IOMMUGroup),
		SriovCapable:  d.SRIOVCapable,
		SriovVfsTotal: int32(d.SRIOVVFsTotal),
		SriovVfsFree:  int32(d.SRIOVVFsFree),
		Driver:        d.Driver,
		VmName:        d.VMName,
		NumaNode:      int32(d.NUMANode),
		PcieRootPort:  d.PCIeRootPort,
		PcieBridge:    d.PCIeBridge,
		LinkClique:    d.LinkClique,
		LinkPeers:     linkPeers,
	}
}
