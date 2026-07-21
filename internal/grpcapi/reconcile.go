package grpcapi

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// reconcileDomainDefinition realizes a VM's desired device state into its libvirt
// domain definition. It is the single primitive Phase 5 (hardware add/remove on a
// stopped VM) drives, and it deliberately sources every device set from the
// AUTHORITATIVE tables rather than the vms.spec blob:
//
//   - disks from vm_disks (device_kind=="disk") — this fixes the disk-drop bug: a
//     hot-plugged disk is written only to vm_disks, so rebuilding from spec.Disks
//     silently dropped it on redefine;
//   - NICs from the vm_nics/vm_interfaces overlay (MergedVMNICs);
//   - passthrough <hostdev>s from the UNION of the intent-resolved PCI members
//     (one <hostdev> per member, aliased "ua-<device>-<member>") and the
//     ownership-only host_pci_devices rows whose BDF no intent covers (alias-less,
//     matched by source address) — deduplicated by resolved concrete address so a
//     device that carries both an intent AND an ownership row is emitted exactly
//     once; fail-closed on an owned device that has vanished from the host,
//     mirroring UpdateVM.
//
// Scalar config (cpu/mem/machine/firmware/SB/TPM/boot) still comes from the spec
// blob; a scalar change is inherently a full topology regenerate and is NOT this
// primitive's concern (it stays in UpdateVM). When a prior inactive definition
// exists and the reconcile is a pure device-set change, it patches that XML in
// place (PatchInactiveDevices) so untouched devices keep their libvirt-assigned
// PCI slots/aliases; otherwise (first define, or an ownership-derived hostdev set
// that the alias-keyed patcher can't match) it full-regenerates from the spec.
// Either way it defines the domain with old-XML rollback on failure.
//
// It does NOT persist the spec, actuals, or machine-type pin — that is the
// caller's responsibility (UpdateVM owns spec durability).
func (s *Server) reconcileDomainDefinition(ctx context.Context, vm *corrosion.VMRecord, resolved []ResolvedMember) error {
	if vm == nil {
		return status.Errorf(codes.InvalidArgument, "reconcileDomainDefinition: nil vm record")
	}
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			return status.Errorf(codes.Internal, "decode spec for %q: %v", vm.Name, err)
		}
	}
	if spec.Name == "" {
		spec.Name = vm.Name
	}

	// ── Disks: authoritative from vm_disks (the disk-drop fix) ──
	dbDisks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read disks for %q: %v", vm.Name, err)
	}
	// Deterministic order by target dev so a first-define/regenerate is stable
	// (GetVMDisks does not order); the patch path keys by target dev so order
	// there is irrelevant.
	sort.SliceStable(dbDisks, func(i, j int) bool { return dbDisks[i].TargetDev < dbDisks[j].TargetDev })
	var diskConfigs []lv.DiskConfig
	var wantDisks []lv.WantDisk
	for idx, d := range dbDisks {
		if d.DeviceKind != "" && d.DeviceKind != "disk" {
			continue // only disk-shaped devices here (cdrom/etc. are not reconciled)
		}
		bus := diskBus(d)
		td := d.TargetDev
		if td == "" {
			td = lv.DiskDevName(bus, idx)
		}
		diskConfigs = append(diskConfigs, lv.DiskConfig{
			Name:            d.DiskName,
			Path:            d.Path,
			Bus:             bus,
			ControllerModel: d.ControllerModel,
			TargetDev:       td,
		})
		wantDisks = append(wantDisks, lv.WantDisk{
			TargetDev:       td,
			Bus:             bus,
			Path:            d.Path,
			ControllerModel: d.ControllerModel,
		})
	}

	// ── NICs: from the vm_nics/vm_interfaces overlay ──
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read NICs for %q: %v", vm.Name, err)
	}
	var netConfigs []lv.NetworkConfig
	var wantNICs []lv.WantNIC
	for _, n := range nics {
		model := n.Model
		if model == "" {
			model = "virtio"
		}
		bridge := resolveBridge(ctx, s.db, n.NetworkName)
		if strings.HasPrefix(bridge, "direct:") {
			direct := strings.TrimPrefix(bridge, "direct:")
			netConfigs = append(netConfigs, lv.NetworkConfig{Direct: direct, Model: model, MAC: n.MAC})
			wantNICs = append(wantNICs, lv.WantNIC{MAC: n.MAC, Direct: direct, Model: model})
			continue
		}
		netConfigs = append(netConfigs, lv.NetworkConfig{Bridge: bridge, Model: model, MAC: n.MAC})
		wantNICs = append(wantNICs, lv.WantNIC{MAC: n.MAC, Bridge: bridge, Model: model})
	}

	// ── Passthrough hostdevs: UNION of intent-resolved members and ownership-only ──
	//
	// The two device sources are NOT mutually exclusive. A VM can own a passthrough
	// device via an OWNERSHIP row alone (CreateVM, or the legacy SR-IOV/type attach
	// path, neither of which writes a vm_pci_intent) AND separately carry a
	// journaled concrete-address intent for a DIFFERENT device. Resolving ONLY
	// intents (as this path once did) silently DROPPED the ownership-only device
	// from the persistent definition the next time an intent-branch reconcile ran —
	// booting the guest without its GPU/NIC on the reconstruction path. So emit
	// BOTH sets, deduplicated by resolved concrete address: a device that carries
	// both an intent and an ownership row (the normal post-backfill state) is
	// emitted exactly once, keeping its intent alias.
	members := resolved
	if members == nil {
		// vm_pci_intent is unpopulated for a VM that predates journaled attach, so
		// resolving it would yield an empty set — only resolve when the VM actually
		// HAS intents; otherwise the union is ownership-only (the pre-journal path).
		intents, ierr := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
		if ierr != nil {
			return status.Errorf(codes.Internal, "read PCI intents for %q: %v", vm.Name, ierr)
		}
		if len(intents) > 0 {
			rmembers, rerr := s.resolveDeviceIntents(ctx, vm.Name, intents)
			if rerr != nil {
				return rerr
			}
			members = rmembers
		}
	}

	var hostdevConfigs []lv.HostdevConfig
	var wantHostdevs []lv.WantHostdev
	// aliaslessHostdev records whether the emitted set includes an ownership-only
	// (alias-less) <hostdev>; the alias-keyed patcher can't match those, so their
	// presence forces a full regenerate below (as the pure-ownership path always did).
	aliaslessHostdev := false
	// coveredByIntent is the set of concrete addresses the intent members already
	// emit, so an ownership row for the same BDF is not emitted a second time.
	coveredByIntent := map[string]bool{}
	if members != nil {
		// Cardinality fail-closed: a persisted realization set whose member count no
		// longer matches the resolver's output is hardware drift we refuse to paper
		// over silently. Dormant while vm_pci_realizations is unpopulated.
		if err := s.checkRealizationCardinality(ctx, vm.Name, members); err != nil {
			return err
		}
		for _, m := range members {
			alias := "ua-" + m.DeviceID + "-" + m.MemberID
			hostdevConfigs = append(hostdevConfigs, lv.HostdevConfig{Address: m.Address, Alias: alias})
			wantHostdevs = append(wantHostdevs, lv.WantHostdev{Alias: alias, Address: m.Address})
			coveredByIntent[m.Address] = true
		}
	}

	// Ownership-only devices: passthrough the VM owns per authoritative PCI
	// ownership whose BDF no intent above already emits. This is the ACTIVE
	// reconstruction path for a VM created before journaled attach AND the union
	// member that keeps a MIXED VM (some devices owned-only, some journaled) from
	// losing its owned-only hardware. Fail-closed on an owned device that has
	// vanished from the host (never boot the guest missing its passthrough
	// hardware) — mirrors UpdateVM. These carry no user alias, matching today's
	// redefine (matched by source address, not alias).
	live, tombstoned, oerr := corrosion.VMDeviceOwnership(ctx, s.db, s.hostName, vm.Name)
	if oerr != nil {
		return status.Errorf(codes.Internal, "read PCI ownership for %q: %v", vm.Name, oerr)
	}
	if len(tombstoned) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"cannot redefine %q: assigned PCI device(s) %v have vanished from host %s; resolve the missing hardware before updating",
			vm.Name, tombstoned, s.hostName)
	}
	for _, addr := range live {
		if coveredByIntent[addr] {
			continue // dedup: already emitted with its intent alias
		}
		hostdevConfigs = append(hostdevConfigs, lv.HostdevConfig{Address: addr})
		wantHostdevs = append(wantHostdevs, lv.WantHostdev{Address: addr})
		aliaslessHostdev = true
	}

	// ── Decide topology-preserving patch vs full regenerate ──
	// PatchInactiveDevices keys hostdevs by their <alias>; ownership-only hostdevs
	// have none, so when the emitted set includes any such device we full-regenerate
	// (rebuilding the whole hostdev set, exactly as UpdateVM does) rather than let
	// the alias-keyed patcher delete the unmatched, alias-less <hostdev>s.
	priorXML := ""
	if x, derr := s.virt.DumpXMLInactive(vm.Name); derr == nil {
		priorXML = x
	}
	usePatch := priorXML != "" && !aliaslessHostdev

	var newXML string
	if usePatch {
		patched, perr := lv.PatchInactiveDevices(priorXML, lv.WantDevices{
			Disks:    wantDisks,
			NICs:     wantNICs,
			Hostdevs: wantHostdevs,
		})
		if perr != nil {
			return status.Errorf(codes.Internal, "patch inactive devices for %q: %v", vm.Name, perr)
		}
		newXML = patched
	} else {
		vmCfg := baseDomainConfig(spec, diskConfigs, netConfigs, hostdevConfigs)
		// Preserve Secure Boot + vTPM across the regenerate (G1); verify the host can
		// still satisfy a requested SB/TPM before applying it.
		if spec.SecureBoot && !s.firmware.SecureBootAvailable() {
			return status.Errorf(codes.FailedPrecondition,
				"host %s has no Secure Boot OVMF firmware; cannot redefine %q with Secure Boot", s.hostName, vm.Name)
		}
		if spec.Tpm {
			if err := s.checkTPMHostSupport(); err != nil {
				return err
			}
		}
		s.firmware.ApplyTo(&vmCfg, s.dataDir, spec.Name, spec.SecureBoot, spec.Tpm)
		generated, gerr := lv.GenerateDomainXML(vmCfg)
		if gerr != nil {
			return status.Errorf(codes.Internal, "generate domain XML for %q: %v", vm.Name, gerr)
		}
		newXML = generated
	}

	// ── Define with old-XML rollback (mirrors UpdateVM vm.go:2581-2596) ──
	oldXML, _ := s.virt.DumpXML(vm.Name)
	_ = s.virt.UndefineDomainPreservingState(vm.Name)
	if err := s.virt.DefineDomain(newXML); err != nil {
		if oldXML != "" { // restore the prior definition (state preserved)
			_ = s.virt.DefineDomain(oldXML)
		}
		return status.Errorf(codes.Internal, "redefine domain %q: %v", vm.Name, err)
	}
	return nil
}

// diskBus resolves the libvirt bus for a stored vm_disks row. The stored bus is
// authoritative when present; otherwise it is inferred from the target-dev prefix
// (sdX ⇒ scsi, hdX ⇒ ide, else virtio) — the same inference the legacy redefine
// path used — because CreateVM and attachDisk persist target_dev but NOT bus.
func diskBus(d corrosion.DiskRecord) string {
	if d.Bus != "" {
		return d.Bus
	}
	if len(d.TargetDev) > 0 {
		switch d.TargetDev[0] {
		case 's':
			return "scsi"
		case 'h':
			return "ide"
		}
	}
	return "virtio"
}

// checkRealizationCardinality fails closed when a persisted vm_pci_realizations
// set for a device no longer matches the number of members the resolver produced
// for it — a hardware drift the reconcile must not silently apply. Dormant while
// vm_pci_realizations is unpopulated (pre-Phase-6/7).
func (s *Server) checkRealizationCardinality(ctx context.Context, vmName string, members []ResolvedMember) error {
	realizations, err := corrosion.ListVMPCIRealizations(ctx, s.db, vmName)
	if err != nil {
		return status.Errorf(codes.Internal, "read PCI realizations for %q: %v", vmName, err)
	}
	if len(realizations) == 0 {
		return nil
	}
	realizedCount := map[string]int{}
	for _, r := range realizations {
		realizedCount[r.DeviceID]++
	}
	resolvedCount := map[string]int{}
	for _, m := range members {
		resolvedCount[m.DeviceID]++
	}
	for deviceID, rc := range realizedCount {
		if got := resolvedCount[deviceID]; got != rc {
			return status.Errorf(codes.FailedPrecondition,
				"cannot reconcile %q: PCI device %s has %d realized member(s) but the resolver produced %d; refusing to change a realized passthrough set",
				vmName, deviceID, rc, got)
		}
	}
	return nil
}
