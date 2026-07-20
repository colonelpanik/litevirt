package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

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
		if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
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
				if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
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

// ResolvedMember is one concrete host device that realizes a PCI passthrough
// request: the resolved BDF plus the intent/member identity used to key its
// vm_pci_realizations row and its `ua-<DeviceID>-<MemberID>` hostdev alias.
// Ordinal orders the members realizing a single request (primary = 0, then its
// IOMMU-group siblings, then subsequent count-N devices).
type ResolvedMember struct {
	DeviceID string
	MemberID string
	Address  string
	Ordinal  int
}

// allocateDevices resolves DeviceSpec requests against host inventory,
// validates IOMMU group conflicts, assigns devices, binds to VFIO-PCI,
// and returns the PCI addresses for hostdev XML.
//
// It is a thin composition of the pure resolve phase (resolveDeviceSpec /
// allocateSRIOVVFs) and the side-effecting acquire phase (acquireDeviceLeases):
// existing callers see identical behavior. It returns the resolved addresses AND
// a finish func: the durable device-lease entry (F1) is written before the vfio
// bind, and the CALLER must defer finish() so the lease is cleared once the VM
// row is finalized (or on the caller's own rollback). A crash before finish()
// runs leaves the entry for startup recovery (RecoverDeviceLeases) to roll back.
func (s *Server) allocateDevices(ctx context.Context, vmName string, specs []*pb.DeviceSpec) ([]string, func(), error) {
	noop := func() {}
	var members []ResolvedMember

	for _, spec := range specs {
		count := int(spec.Count)
		if count == 0 {
			count = 1
		}

		// SR-IOV VF allocation is inherently side-effecting — it CAS-claims free VFs
		// and may create a VF pool on-demand (writing host sysfs) — so it cannot be
		// part of the pure resolver and stays on this path. The claimed VFs flow into
		// acquireDeviceLeases alongside the rest for the durable lease + vfio bind.
		if spec.Sriov && spec.Address == "" {
			vfAddrs, err := s.allocateSRIOVVFs(ctx, vmName, spec, count)
			if err != nil {
				return nil, noop, err
			}
			for i, a := range vfAddrs {
				members = append(members, ResolvedMember{MemberID: fmt.Sprintf("m%d", i), Address: a, Ordinal: i})
			}
			continue
		}

		specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, "")
		if err != nil {
			return nil, noop, err
		}
		members = append(members, specMembers...)
	}

	finish, err := s.acquireDeviceLeases(ctx, vmName, members)
	if err != nil {
		return nil, noop, err
	}
	addresses := make([]string, 0, len(members))
	for _, m := range members {
		addresses = append(addresses, m.Address)
	}
	return addresses, finish, nil
}

// resolveDeviceSpec is the PURE selection/validation core shared by
// allocateDevices (from a live *pb.DeviceSpec) and resolveDeviceIntents (from a
// stored intent). It resolves ONE non-SR-IOV request to its concrete host
// device(s): a resource mapping to this host's pinned address, an exact address
// or a type/vendor/model match, each expanded to include its IOMMU-group
// siblings and validated against IOMMU-group conflicts. It performs NO
// AssignPCIDevice, NO VF creation and NO vfio bind — nothing that touches host
// hardware or inventory ownership — so it is safe to run while reconciling a
// stopped VM. deviceID (the intent id, "" for the live-spec path) is stamped
// onto every returned member.
func (s *Server) resolveDeviceSpec(ctx context.Context, vmName string, spec *pb.DeviceSpec, deviceID string) ([]ResolvedMember, error) {
	count := int(spec.Count)
	if count == 0 {
		count = 1
	}

	address := spec.Address
	// Resource mapping (#14): resolve a cluster-wide mapping name to the concrete
	// PCI address registered for THIS host, then treat it as an exact pin. This is
	// what lets a passthrough VM land on / migrate to any host that has a device
	// under the same mapping. Resolve into a local var — never mutate the input spec.
	if spec.Mapping != "" && address == "" {
		addr, err := corrosion.ResolveMappingAddress(ctx, s.db, spec.Mapping, s.hostName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "resolve resource mapping %q: %v", spec.Mapping, err)
		}
		if addr == "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"resource mapping %q has no device on host %s", spec.Mapping, s.hostName)
		}
		address = addr
	}

	var members []ResolvedMember
	ordinal := 0
	// addPrimary appends primary + its IOMMU-group siblings as ordered members.
	// The conflict check is on the primary only (a sibling shares the group, so a
	// conflicting other-VM owner is already caught by the primary's check).
	addPrimary := func(primary string) error {
		if err := s.checkIOMMUConflict(ctx, primary, vmName); err != nil {
			return err
		}
		members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", ordinal), Address: primary, Ordinal: ordinal})
		ordinal++
		groupAddrs, _ := s.iommuGroupSiblings(ctx, primary)
		for _, a := range groupAddrs {
			if a != primary {
				members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", ordinal), Address: a, Ordinal: ordinal})
				ordinal++
			}
		}
		return nil
	}

	// Exact address pinning (also the resolved-mapping path).
	if address != "" {
		if err := addPrimary(address); err != nil {
			return nil, err
		}
		return members, nil
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
		if err := addPrimary(matched[i].Address); err != nil {
			return nil, err
		}
	}
	return members, nil
}

// resolveDeviceIntents is the PURE resolver the topology-preserving reconcile
// primitive uses: it maps a VM's stored vm_pci_intent rows to the concrete host
// members they realize, touching no host hardware and no inventory ownership.
// An "address" intent resolves via its exclusive_key BDF; portable "mapping" /
// "type" intents decode their selector_payload (a protojson DeviceSpec) and run
// the shared resolveDeviceSpec selection. SR-IOV intents are NOT resolved here:
// realizing them CAS-claims and may create VFs (side effects), which belongs in
// the acquire phase (allocateSRIOVVFs) — wiring pure SR-IOV candidate selection
// into this resolver is deferred to the start-path task.
func (s *Server) resolveDeviceIntents(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord) ([]ResolvedMember, error) {
	var members []ResolvedMember
	for _, intent := range intents {
		switch intent.SelectorKind {
		case "sriov":
			return nil, status.Errorf(codes.Unimplemented,
				"SR-IOV intent %s: VF realization is side-effecting and handled by the acquire path, not the pure resolver", intent.DeviceID)
		case "address":
			addr := ""
			if intent.ExclusiveKey != nil {
				addr = *intent.ExclusiveKey
			}
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, &pb.DeviceSpec{Address: addr}, intent.DeviceID)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		default: // "mapping", "type"
			spec := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(intent.SelectorPayload), spec); err != nil {
				return nil, status.Errorf(codes.Internal, "decode selector payload for device %s: %v", intent.DeviceID, err)
			}
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, intent.DeviceID)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		}
	}
	return members, nil
}

// acquireDeviceLeases is the side-effecting counterpart to resolveDeviceIntents:
// it takes resolved members and records inventory ownership (AssignPCIDevice),
// writes the durable device-lease entry (F1) BEFORE the irreversible vfio bind,
// then binds every member to vfio-pci. On a bind failure it rolls back EXACTLY
// the devices this call claimed (releaseDeviceLeases) and clears the lease, so a
// crash before the VM row is finalized is recovered at startup. It returns the
// finish func the caller must defer to clear the lease once the row is durable.
//
// AssignPCIDevice is idempotent for a member already owned by vmName (e.g. an
// SR-IOV VF CAS-claimed during selection), so members from either resolve path
// are handled uniformly.
func (s *Server) acquireDeviceLeases(ctx context.Context, vmName string, members []ResolvedMember) (func(), error) {
	noop := func() {}
	addresses := make([]string, 0, len(members))
	for _, m := range members {
		addresses = append(addresses, m.Address)
	}

	for _, addr := range addresses {
		if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
			slog.Warn("failed to record device assignment", "address", addr, "error", err)
		}
	}

	// Durably record the claimed devices (F1 device lease) BEFORE the irreversible
	// vfio bind, so a crash before the VM row is finalized is rolled back at
	// startup. No-op unless the operation_protocol capability is active.
	finish := s.beginDeviceLease(ctx, vmName, addresses)

	for _, addr := range addresses {
		prevDriver, err := vfio.Bind(addr)
		if err != nil {
			slog.Warn("VFIO bind failed", "address", addr, "error", err)
			// Roll back only the devices this allocation claimed, and clear the
			// durable lease.
			s.releaseDeviceLeases(ctx, vmName, addresses)
			finish()
			return noop, status.Errorf(codes.Internal,
				"failed to bind device %s to vfio-pci: %v", addr, err)
		}
		slog.Info("device bound to vfio-pci", "address", addr, "previous_driver", prevDriver)
	}

	return finish, nil
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

// releaseDeviceLeases rolls back EXACTLY the devices an allocation claimed (unbind
// from vfio-pci + owner-scoped DB release), leaving the VM's pre-existing
// passthrough devices untouched. This is the rollback primitive for a FAILED
// allocation/attach — using the whole-VM releaseDevices there would over-release
// every device the VM already owned.
func (s *Server) releaseDeviceLeases(ctx context.Context, vmName string, addrs []string) {
	drivers := map[string]string{}
	if devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, ""); err == nil {
		for _, d := range devices {
			drivers[d.Address] = d.Driver
		}
	}
	for _, addr := range addrs {
		if err := vfio.Unbind(addr, drivers[addr]); err != nil {
			slog.Warn("VFIO unbind failed", "address", addr, "error", err)
		}
		// Owner-scoped: a no-op if another VM has since claimed this address.
		if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
			slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", err)
		}
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
