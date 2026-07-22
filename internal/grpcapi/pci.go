package grpcapi

import (
	"context"
	"errors"
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

	// Cross-spec exclusion set: the addresses already selected by earlier specs in
	// THIS request (primaries + IOMMU-group siblings + claimed SR-IOV VFs). The old
	// fused loop assigned each spec inline, so a later type/vendor spec's
	// GetAvailableDevicesByType saw a SHRINKING pool; resolving deferred assignment
	// to acquire, so every type spec would otherwise re-select the same free
	// device. Threading this set restores the pool-shrinking semantics PURELY — no
	// assignment in the resolve phase, just in-memory exclusion.
	selected := map[string]bool{}

	for _, spec := range specs {
		count := int(spec.Count)
		if count == 0 {
			count = 1
		}

		// SR-IOV VF allocation is inherently side-effecting — it CAS-claims free VFs
		// and may create a VF pool on-demand (writing host sysfs) — so it cannot be
		// part of the pure resolver and stays on this path. The claimed VFs flow into
		// acquireDeviceLeases alongside the rest for the durable lease + vfio bind.
		//
		// A resource-mapping spec is a concrete pin, not VF allocation: mapping
		// resolution must precede the SR-IOV branch (as in the original order), so a
		// Sriov+Mapping spec resolves the mapped device rather than allocating a VF.
		if spec.Sriov && spec.Address == "" && spec.Mapping == "" {
			vfAddrs, err := s.allocateSRIOVVFs(ctx, vmName, spec, count)
			if err != nil {
				return nil, noop, err
			}
			for i, a := range vfAddrs {
				members = append(members, ResolvedMember{MemberID: fmt.Sprintf("m%d", i), Address: a, Ordinal: i})
				selected[a] = true
			}
			continue
		}

		specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, "", selected)
		if err != nil {
			return nil, noop, err
		}
		// Freeze the resolved concrete BDF back onto a resource-mapping spec so
		// CreateVM's json.Marshal(spec) persists the pinned address (behavior-
		// preserving; making the mapping stay portable is a later phase's job). The
		// pure resolveDeviceSpec never mutates the spec — allocateDevices does.
		if spec.Mapping != "" && spec.Address == "" && len(specMembers) > 0 {
			spec.Address = specMembers[0].Address
		}
		members = append(members, specMembers...)
	}

	finish, _, err := s.acquireDeviceLeases(ctx, vmName, members)
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
//
// exclude is a cross-spec working set of addresses already chosen by earlier
// specs in the same request: type/vendor selection SKIPS any candidate in it, and
// each address this call selects (primary + IOMMU-group siblings) is added to it,
// so a subsequent spec sees the same shrunken pool the old inline-assign loop did.
// It is a caller-owned scratch map (never a *pb.DeviceSpec), so mutating it keeps
// the resolver pure w.r.t. host hardware and inventory ownership.
func (s *Server) resolveDeviceSpec(ctx context.Context, vmName string, spec *pb.DeviceSpec, deviceID string, exclude map[string]bool) ([]ResolvedMember, error) {
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
		exclude[primary] = true
		groupAddrs, _ := s.iommuGroupSiblings(ctx, primary)
		for _, a := range groupAddrs {
			if a != primary {
				members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", ordinal), Address: a, Ordinal: ordinal})
				ordinal++
				exclude[a] = true
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
	// Filter by vendor/model if specified, skipping any device already chosen by an
	// earlier spec in this request (the cross-spec pool-shrinking exclusion).
	var matched []corrosion.PCIDeviceRecord
	for _, d := range available {
		if exclude[d.Address] {
			continue
		}
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
	// Cross-intent exclusion set (see resolveDeviceSpec): a scratch map so two
	// type/vendor intents resolve to distinct devices, exactly as the live-spec
	// path. Local to this call — resolveDeviceIntents stays pure.
	selected := map[string]bool{}
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
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, &pb.DeviceSpec{Address: addr}, intent.DeviceID, selected)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		default: // "mapping", "type"
			spec := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(intent.SelectorPayload), spec); err != nil {
				return nil, status.Errorf(codes.Internal, "decode selector payload for device %s: %v", intent.DeviceID, err)
			}
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, intent.DeviceID, selected)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		}
	}
	return members, nil
}

// claimDeviceOwnership is the ONE shared, fail-closed inventory reservation used by
// EVERY PCI producer — CreateVM's allocateDevices, the running attach, AND the
// stopped concrete-address attach. It reads the current owner of each member once
// (no new statement), then per member:
//   - owner == vmName → an idempotent self-claim (e.g. an SR-IOV VF CAS-claimed
//     during selection, or a same-op retry / re-attach): keep it, NOT newly claimed.
//   - owner is a DIFFERENT non-empty VM → FAIL (AlreadyExists), rolling back the
//     members THIS call already claimed.
//   - present and unowned → corrosion.ClaimPCIDevice (CAS: assigns only if active
//     and unassigned); a false return (lost the race) or an error FAILS the same way.
//   - absent / tombstoned from inventory → FAIL CLOSED (FailedPrecondition): there
//     is no claimable ownership row, so we refuse rather than reserve nothing.
//
// It performs NO vfio bind and writes NO durable lease — ownership only, so it is
// safe on the stopped-attach declare path (the bind/lease/realization stay at VM
// start). It returns the addresses it NEWLY claimed and a release closure that
// owner-releases EXACTLY those (owner-scoped, a no-op for a self-owned member, and a
// no-op if another VM has since claimed the address) — the caller invokes release to
// undo the reservation on its own later failure, or uses the claimed list to scope a
// rollback so a self-owned reservation (a device reserved while the VM was off,
// FIX-9b) is never released by a failed operation. On any failure WITHIN the loop it
// rolls the newly-claimed members back itself before returning the error.
func (s *Server) claimDeviceOwnership(ctx context.Context, vmName string, members []ResolvedMember) ([]string, func(), error) {
	noop := func() {}

	// Current owners on this host, read once (no new statement): distinguishes
	// self-owned (idempotent), other-owned (conflict), present+unowned (CAS-claim)
	// and absent (fail closed).
	owners := map[string]string{}
	devs, lerr := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if lerr != nil {
		return nil, noop, status.Errorf(codes.Internal, "read PCI inventory: %v", lerr)
	}
	for _, d := range devs {
		owners[d.Address] = d.VMName
	}

	// claimed = the addresses THIS call took; release owner-releases exactly those
	// (never another VM's device, never a pre-existing self-owned reservation). No
	// vfio unbind — nothing is bound here.
	var claimed []string
	release := func() {
		for _, addr := range claimed {
			if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
				slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", err)
			}
		}
	}
	for _, m := range members {
		addr := m.Address
		owner, present := owners[addr]
		switch {
		case owner == vmName:
			// Already ours — idempotent self-claim; not newly claimed, nothing to do.
		case owner != "":
			release()
			return nil, noop, status.Errorf(codes.AlreadyExists,
				"PCI device %s (host %s) is already claimed by VM %q", addr, s.hostName, owner)
		case !present:
			// Absent / tombstoned from inventory: no claimable ownership row exists.
			// Fail CLOSED — a real passthrough device is discovered into host_pci_devices
			// before it can be assigned, so a missing BDF is an error, not a bind-anyway.
			release()
			return nil, noop, status.Errorf(codes.FailedPrecondition,
				"PCI device %s is not in host %s inventory", addr, s.hostName)
		default:
			// Present and unowned → atomic CAS claim.
			ok, cerr := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, addr, vmName)
			if cerr != nil {
				release()
				return nil, noop, status.Errorf(codes.Internal, "claim PCI device %s: %v", addr, cerr)
			}
			if !ok {
				// Lost the CAS race — another operation claimed it between the read and here.
				release()
				return nil, noop, status.Errorf(codes.AlreadyExists,
					"PCI device %s (host %s) was claimed by another operation", addr, s.hostName)
			}
			claimed = append(claimed, addr)
		}
	}
	return claimed, release, nil
}

// acquireDeviceLeases is the side-effecting counterpart to resolveDeviceIntents for
// the RUNNING / start path: it composes the shared claimDeviceOwnership reservation
// (the exclusive, fail-closed physical-double-bind guard) with the durable
// device-lease entry (F1) written BEFORE the irreversible vfio bind, then binds
// every member to vfio-pci. On a bind failure it rolls back the devices this call
// newly claimed (via the strict unbindAndReleaseOwnership primitive) and clears the
// lease — unless the release could not confirm the unbind, in which case it RETAINS
// the lease so a crash before the VM row is finalized is recovered at startup. It returns the finish func the caller must
// defer to clear the lease once the row is durable, AND the addresses it NEWLY claimed
// (a self-owned member is skipped → NOT in the list), so a caller's OWN post-acquire
// rollback can release exactly the devices this start took and never a pre-existing
// self-owned reserve-while-off reservation (FIX-9b/9c).
func (s *Server) acquireDeviceLeases(ctx context.Context, vmName string, members []ResolvedMember) (func(), []string, error) {
	noop := func() {}

	// Claim inventory ownership (fail-closed CAS) BEFORE any bind. On failure the
	// claim rolled back its own reservations, so there is nothing to unbind here.
	// claimed = the members THIS call newly took (a self-owned member is skipped and
	// is NOT in the list), so the bind-failure rollback can release exactly those and
	// never a pre-existing self-owned reservation.
	claimed, _, cerr := s.claimDeviceOwnership(ctx, vmName, members)
	if cerr != nil {
		return noop, nil, cerr
	}

	addresses := make([]string, 0, len(members))
	for _, m := range members {
		addresses = append(addresses, m.Address)
	}

	// Durably record the claimed devices (F1 device lease) BEFORE the irreversible
	// vfio bind, so a crash before the VM row is finalized is rolled back at
	// startup. No-op unless the operation_protocol capability is active.
	finish := s.beginDeviceLease(ctx, vmName, addresses)

	for _, addr := range addresses {
		prevDriver, err := vfio.Bind(addr)
		if err != nil {
			slog.Warn("VFIO bind failed", "address", addr, "error", err)
			// Roll back ONLY the devices THIS call newly claimed, via the strict all-or-
			// nothing primitive (unbind bound members by vfio ground truth, then owner-
			// release). A self-owned reservation (a device reserved while the VM was off,
			// FIX-9b) is NOT in `claimed`, so a failed start-time bind retains it rather than
			// silently dropping the reservation. When nothing is self-owned, `claimed` ==
			// every address.
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, claimed); rerr != nil {
				// A freshly-claimed member could not be confirmed unbound → leave it owned +
				// bound (recoverable, never unowned + bound) and RETAIN the durable device-
				// lease so RecoverDeviceLeases retries the release; do NOT finish().
				slog.Error("VFIO bind rollback: release incomplete — device lease retained for recovery", "vm", vmName, "error", rerr)
			} else {
				finish() // release converged (or nothing to release) → clear the durable lease
			}
			return noop, nil, status.Errorf(codes.Internal,
				"failed to bind device %s to vfio-pci: %v", addr, err)
		}
		slog.Info("device bound to vfio-pci", "address", addr, "previous_driver", prevDriver)
	}

	return finish, claimed, nil
}

// pciStartPreflight realizes a hardware_v2 VM's reserved PCI intents at start:
// it resolves every intent to concrete host members, acquires the device leases
// (CAS ownership + durable F1 lease + vfio bind), persists vm_pci_realizations
// (member_id + ua-alias + resolved_address — CONTRACT g) and reconciles the aliased
// <hostdev>s into the domain definition — everything that must be true BEFORE
// StartDomain. It fails CLOSED: a vanished/unacquirable device, a realization write
// failure, or a reconcile failure releases whatever was claimed and returns the
// error (the VM does not start).
//
// SR-IOV routing (CONTRACT a): resolveDeviceIntents returns Unimplemented for an
// sriov selector (VF realization is side-effecting), so an sriov intent is routed
// through allocateSRIOVVFs (the CAS-claim / VF-create acquire path); concrete-address,
// mapping and type intents go through the pure resolveDeviceIntents.
//
// On success it clears the durable F1 lease (the realization rows are the durable
// record now) and returns a release func the caller invokes ONLY if the subsequent
// StartDomain fails, so a failed start leaves no VM bound to devices it never used.
func (s *Server) pciStartPreflight(ctx context.Context, vm *corrosion.VMRecord, intents []corrosion.PCIIntentRecord) (release func(), err error) {
	// ── Resolve every intent to concrete members (routing SR-IOV to the allocator) ──
	var members []ResolvedMember
	var claimedSriov []string // VFs allocateSRIOVVFs CAS-claimed (released on a resolve failure)
	resolveFail := func(e error) (func(), error) {
		if len(claimedSriov) > 0 {
			// The VFs were CAS-claimed but never vfio-bound (allocateSRIOVVFs binds nothing),
			// so the strict primitive skips every unbind (IsBoundToVFIO=false) and just owner-
			// releases them — behavior-preserving. A release-write failure is only logged: the
			// resolve already failed and the residual owned VF converges on the next start's
			// self-owned skip.
			if rerr := s.unbindAndReleaseOwnership(ctx, vm.Name, claimedSriov); rerr != nil {
				slog.Warn("sr-iov resolve rollback: release incomplete", "vm", vm.Name, "error", rerr)
			}
		}
		return nil, e
	}
	for _, in := range intents {
		if in.SelectorKind == "sriov" {
			spec := &pb.DeviceSpec{}
			if uerr := protojson.Unmarshal([]byte(in.SelectorPayload), spec); uerr != nil {
				return resolveFail(status.Errorf(codes.Internal,
					"decode SR-IOV selector payload for device %s: %v", in.DeviceID, uerr))
			}
			count := int(spec.Count)
			if count == 0 {
				count = 1
			}
			vfAddrs, aerr := s.allocateSRIOVVFs(ctx, vm.Name, spec, count)
			if aerr != nil {
				return resolveFail(aerr)
			}
			for i, a := range vfAddrs {
				members = append(members, ResolvedMember{DeviceID: in.DeviceID, MemberID: fmt.Sprintf("m%d", i), Address: a, Ordinal: i})
				claimedSriov = append(claimedSriov, a)
			}
			continue
		}
		// address / mapping / type: the pure resolver.
		specMembers, rerr := s.resolveDeviceIntents(ctx, vm.Name, []corrosion.PCIIntentRecord{in})
		if rerr != nil {
			return resolveFail(rerr)
		}
		members = append(members, specMembers...)
	}

	if len(members) == 0 {
		// Intents that resolved to no members (should not happen — an intent yields ≥1
		// member); nothing to acquire, so start proceeds from the existing definition.
		return func() {}, nil
	}

	// ── Acquire leases: CAS ownership + durable F1 lease + vfio bind ──
	// On a bind failure acquireDeviceLeases self-cleans every device it touched
	// (owner-scoped release covers the SR-IOV VFs claimed above too) and clears the
	// lease, so nothing is left to release here. acquireClaimed = the addresses this
	// acquire NEWLY claimed (a self-owned reserve-while-off device is skipped → NOT in
	// it), so the post-acquire rollback below can release exactly what THIS start took.
	finish, acquireClaimed, aerr := s.acquireDeviceLeases(ctx, vm.Name, members)
	if aerr != nil {
		return nil, aerr
	}

	// The devices freshly claimed DURING THIS START: the VFs CAS-claimed in the resolve
	// phase (claimedSriov) ∪ the members acquire newly claimed (acquireClaimed). A
	// pre-existing self-owned reservation is in NEITHER, so scoping the post-acquire
	// rollback to this set releases only what this start took and RETAINS a
	// reserve-while-off reservation across a transient post-bind failure (FIX-9c). Dedupe
	// defensively (a VF claimed in resolve is self-owned at acquire, so acquire skips it —
	// the sets should not overlap, but a double-release is harmless either way).
	freshlyClaimed := make([]string, 0, len(claimedSriov)+len(acquireClaimed))
	seenFresh := map[string]bool{}
	for _, a := range append(append([]string{}, claimedSriov...), acquireClaimed...) {
		if !seenFresh[a] {
			seenFresh[a] = true
			freshlyClaimed = append(freshlyClaimed, a)
		}
	}

	// ── Persist realizations (CONTRACT g), grouped per device ──
	byDevice := map[string][]ResolvedMember{}
	var deviceOrder []string
	for _, m := range members {
		if _, seen := byDevice[m.DeviceID]; !seen {
			deviceOrder = append(deviceOrder, m.DeviceID)
		}
		byDevice[m.DeviceID] = append(byDevice[m.DeviceID], m)
	}
	rollback := func() error {
		// Release ONLY the devices THIS start freshly claimed — never a pre-existing
		// self-owned reserve-while-off reservation (FIX-9c). A retained self-owned device
		// is absent from freshlyClaimed, so it stays bound + owned = still reserved. Strict
		// (all-or-nothing): if a freshly-claimed member cannot be confirmed unbound, release
		// NOTHING and return the error so the caller leaves the start recovery-required (it
		// stays owned + bound, never unowned + bound). Tombstone realizations only once the
		// release has converged, so a recovery-required rollback keeps this start's rows.
		if rerr := s.unbindAndReleaseOwnership(ctx, vm.Name, freshlyClaimed); rerr != nil {
			return rerr
		}
		for _, dev := range deviceOrder {
			if terr := corrosion.TombstonePCIRealizations(ctx, s.db, vm.Name, dev); terr != nil {
				slog.Warn("pci start-preflight: tombstone realizations on rollback", "vm", vm.Name, "device", dev, "error", terr)
			}
		}
		return nil
	}
	for _, dev := range deviceOrder {
		if werr := s.writePCIRealizations(ctx, vm.Name, dev, byDevice[dev]); werr != nil {
			if rbErr := rollback(); rbErr != nil {
				// The release could not confirm the unbind → leave the start recovery-required:
				// do NOT finish() the lease (retain it), propagate so startVMLocked leaves it
				// recoverable. The freshly-claimed member stays owned + bound; retry converges.
				slog.Error("pci start-preflight: rollback release incomplete after realization write failure — left recoverable", "vm", vm.Name, "error", rbErr)
				return nil, status.Errorf(codes.Internal,
					"persist PCI realizations for %q failed and rollback could not release freshly-claimed device(s); left recoverable: %v", vm.Name, werr)
			}
			finish()
			return nil, status.Errorf(codes.Internal, "persist PCI realizations for %q: %v", vm.Name, werr)
		}
	}

	// ── Reconcile the aliased hostdevs into the domain definition ──
	if rerr := s.reconcileDomainDefinition(ctx, vm, members); rerr != nil {
		if rbErr := rollback(); rbErr != nil {
			slog.Error("pci start-preflight: rollback release incomplete after reconcile failure — left recoverable", "vm", vm.Name, "error", rbErr)
			return nil, status.Errorf(codes.Internal,
				"reconcile domain for %q failed and rollback could not release freshly-claimed device(s); left recoverable: %v", vm.Name, rerr)
		}
		finish()
		return nil, rerr
	}

	// Success: the realization rows are the durable record now — clear the F1 lease.
	// The returned release is invoked ONLY if the caller's StartDomain then fails; a
	// release that cannot confirm the unbind leaves the freshly-claimed member owned +
	// bound (recoverable on the operator's start retry), never unowned + bound.
	finish()
	return func() {
		if rbErr := rollback(); rbErr != nil {
			slog.Error("pci start-preflight: post-StartDomain-failure release incomplete — freshly-claimed device(s) left owned+bound (recoverable on retry)", "vm", vm.Name, "error", rbErr)
		}
	}, nil
}

// releaseDevices is the STRICT, HOST-SCOPED whole-VM PCI teardown: for every device
// THIS host records as owned by vmName it consults the ACTUAL vfio driver state
// (IsBoundToVFIO ground truth) and unbinds the ones still bound to vfio-pci, then
// releases ownership PER DEVICE and owner-scoped (ReleasePCIDevice) ONLY if EVERY unbind
// succeeded. If any unbind (or bound-check) failed it releases NOTHING and returns an
// error — the same all-or-nothing invariant unbindAndReleaseOwnership enforces per-member,
// applied to the whole VM set — so a still-bound device is NEVER left unowned-but-vfio-
// bound. A release-WRITE failure after a clean unbind is likewise recoverable: it returns
// the joined error so the caller does not complete over a leaked ownership row (a retry
// converges — an owner-scoped re-release of an already-released row is a 0-row no-op and an
// already-unbound device reads IsBoundToVFIO=false).
//
// It is HOST-SCOPED: it clears ONLY this host's ownership rows (the ones it just unbound).
// A device a stale/migrated VM still owns on a DIFFERENT host is left for THAT host's own
// teardown to release — clearing it here would leave the remote device unowned-but-vfio-
// bound, since this host cannot unbind on the remote host. Cross-host cleanup is each
// involved host's own responsibility.
//
// Both callers treat the error the same: they do NOT proceed past it. The pre-latch stop
// leaves the stop recoverable; VM delete FAILS before tombstoning the vms row (so it never
// leaves a stale owner of a deleted VM — which would block every future claim on that BDF),
// leaving the delete retryable once the operator resolves the stuck device.
func (s *Server) releaseDevices(ctx context.Context, vmName string) error {
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("list devices for release: %w", err)
	}

	var owned []string // THIS host's devices owned by vmName — the exact set to release
	var failures []error
	for _, d := range devices {
		if d.VMName != vmName {
			continue
		}
		owned = append(owned, d.Address)
		bound, berr := vfio.IsBoundToVFIO(d.Address)
		if berr != nil {
			// Cannot prove the binding state → fail closed (treat as an unbind failure) so
			// ownership is never released for a device we cannot confirm is unbound.
			failures = append(failures, fmt.Errorf("check vfio binding for %s: %w", d.Address, berr))
			continue
		}
		if !bound {
			continue // not bound → nothing to unbind (never Unbind a not-bound device)
		}
		if uerr := vfio.Unbind(d.Address, d.Driver); uerr != nil {
			failures = append(failures, fmt.Errorf("unbind %s from vfio-pci: %w", d.Address, uerr))
		} else {
			slog.Info("device unbound from vfio-pci", "address", d.Address, "restored_driver", d.Driver)
		}
	}

	if len(failures) > 0 {
		// Release NOTHING: every device stays owned by vmName and the still-bound ones stay
		// bound. This is the invariant that prevents an unowned-but-vfio-bound orphan.
		return fmt.Errorf("pci release: %d device(s) for %q could not be unbound: %w",
			len(failures), vmName, errors.Join(failures...))
	}

	// Every unbind succeeded → release ONLY this host's ownership rows, per device and
	// owner-scoped, so a remote host's rows are never touched. A release-write failure is
	// recoverable (see the doc comment): return the joined error rather than complete over
	// a leaked ownership row.
	var relFailures []error
	for _, addr := range owned {
		if rerr := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); rerr != nil {
			slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", rerr)
			relFailures = append(relFailures, fmt.Errorf("release %s ownership: %w", addr, rerr))
		}
	}
	if len(relFailures) > 0 {
		return fmt.Errorf("pci release: %d device(s) for %q could not be released in DB: %w",
			len(relFailures), vmName, errors.Join(relFailures...))
	}
	return nil
}

// unbindAndReleaseOwnership is the ALL-OR-NOTHING, crash-safe release primitive — the
// SOLE PCI release primitive, used by every op/recovery release site (the attach/start
// rollbacks, lease recovery, and both the live detach and its crash recovery). It
// discriminates bound-ness by the ACTUAL vfio driver state (vfio.IsBoundToVFIO), the
// ground truth — NOT by realization presence,
// which lies after a FIX-9c failed-start rollback that tombstones realizations while
// retaining the binding.
//
// It is OWNER-SCOPED: it first reads host_pci_devices ownership (fail-closed — a read
// error releases NOTHING and returns recoverable, since ownership can't be determined) and
// SKIPS any addr a DIFFERENT non-empty VM owns, in BOTH the unbind and the release loops.
// This is a no-op for every legitimate caller (they pass the VM's own realization/intent
// members or freshly-CAS-claimed addrs → owner == vmName); it only neutralizes the buggy
// legacy-detach-of-a-foreign-BDF case so NO caller can unbind another live VM's device.
//
// Per (owned/unowned) member: read the vfio driver state; if the device is bound to vfio-pci,
// unbind it (restoring the host driver from host_pci_devices.Driver). A device that is NOT
// bound is skipped — vfio.Unbind on a never-bound device is not a clean no-op (it clears
// driver_override and reprobes). A bound-check FS error counts as a failure.
//
//   - If ANY member's unbind (or bound-check) failed → RELEASE NOTHING (no
//     ReleasePCIDevice) and return the error. Every member stays owned, and the still-
//     bound ones stay bound, so the caller can leave the operation recovery-required. A
//     retry re-reads vfio state: a since-unbound member is skipped and the release
//     converges — never leaving a device unowned-but-vfio-bound.
//   - If every bound member unbound cleanly → owner-release ALL addrs (owner-scoped, a
//     no-op for a device another VM has since claimed). If any release WRITE errors,
//     attempt the rest anyway (a partial release is safe — owner-scoped release is
//     idempotent) and RETURN the joined error so the caller leaves the op recovery-
//     required rather than completing over a leaked, unclaimable ownership row. A retry
//     re-reads vfio state: the already-unbound members are skipped (IsBoundToVFIO=false)
//     and the owner-scoped re-release of an already-released device is a 0-row no-op, so
//     the release converges.
func (s *Server) unbindAndReleaseOwnership(ctx context.Context, vmName string, addrs []string) error {
	// Read host PCI ownership + the host-driver map. This read is the ONLY signal for which of
	// the passed addrs are actually vmName's, so it is fail-closed: if it ERRORS we cannot
	// determine ownership and must NOT act — release NOTHING and return a recoverable error
	// rather than proceed on an empty map and risk unbinding a device another VM owns. (An
	// operator-driven legacy detach forwards a raw BDF straight to this primitive; this
	// ownership scope is what stops it from tearing down a DIFFERENT live VM's passthrough.)
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("pci release: read device ownership for %q: %w", vmName, err)
	}
	drivers := map[string]string{}
	owners := map[string]string{}
	for _, d := range devices {
		drivers[d.Address] = d.Driver
		owners[d.Address] = d.VMName
	}

	var failures []error
	for _, addr := range addrs {
		// Owner-scope the unbind: NEVER touch an addr a DIFFERENT non-empty VM owns — that
		// would tear down its live passthrough. Only addrs owned by vmName (or genuinely
		// unowned) are ours to act on. This makes the primitive structurally safe for EVERY
		// caller, including the legacy detach that forwards an operator-supplied BDF.
		if owner := owners[addr]; owner != "" && owner != vmName {
			slog.Warn("pci release: skipping addr owned by another VM (not ours to unbind)",
				"caller_vm", vmName, "address", addr, "owner", owner)
			continue
		}
		bound, berr := vfio.IsBoundToVFIO(addr)
		if berr != nil {
			// Cannot prove the device's binding state → fail closed (treat as an unbind
			// failure) so we never release a device we can't confirm is unbound.
			failures = append(failures, fmt.Errorf("check vfio binding for %s: %w", addr, berr))
			continue
		}
		if !bound {
			continue // not bound → nothing to unbind (never Unbind a not-bound device)
		}
		if uerr := vfio.Unbind(addr, drivers[addr]); uerr != nil {
			failures = append(failures, fmt.Errorf("unbind %s from vfio-pci: %w", addr, uerr))
		}
	}

	if len(failures) > 0 {
		// Release NOTHING: a still-bound member stays owned + bound (recoverable). This is
		// the invariant that prevents an unowned-but-vfio-bound orphan.
		return fmt.Errorf("pci release: %d of %d member(s) could not be unbound: %w",
			len(failures), len(addrs), errors.Join(failures...))
	}

	var relFailures []error
	for _, addr := range addrs {
		// Same owner-scope on the release: skip an addr owned by another VM (the owner-scoped
		// ReleasePCIDevice would no-op on it anyway, but skip explicitly to avoid a spurious
		// relFailure and to keep the two loops' acted-on subset identical).
		if owner := owners[addr]; owner != "" && owner != vmName {
			continue
		}
		if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
			slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", err)
			relFailures = append(relFailures, fmt.Errorf("release %s ownership: %w", addr, err))
		}
	}
	if len(relFailures) > 0 {
		// The unbind already succeeded but a release WRITE failed → return recoverable so
		// the caller does NOT tombstone/complete over a leaked ownership row. The retry
		// converges: unbound members are skipped and owner-scoped re-release is a no-op.
		return fmt.Errorf("pci release: %d of %d member(s) could not be released in DB: %w",
			len(relFailures), len(addrs), errors.Join(relFailures...))
	}
	return nil
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
