package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pci"
)

// BackfillHardwareTables populates the v42 typed-hardware tables (vm_nics,
// vm_disks.bus, vm_pci_intent) and the per-VM hardware-adoption state for every
// VM this host owns, from the pre-v42 authoritative sources (vm_interfaces, the
// stored VMSpec blob, and the persistent libvirt domain definition).
//
// It is IDEMPOTENT and UPSERT-KEYED so it is safe to run repeatedly and on
// several peers concurrently: NIC ids (DeterministicNICID) and PCI intent ids
// (DeterministicPCIIntentID) are pure functions of replicated inputs, so every
// peer synthesizes the byte-identical primary key and the writes converge into
// one row rather than forking into per-peer duplicates.
//
// Per-VM ISOLATION is a hard contract: one damaged VM (unreadable inactive
// definition, malformed blob, ambiguous device grouping) is recorded as
// hardware_adoption_blocked and the pass CONTINUES to the next VM. Backfill
// returns a non-nil error ONLY for a failure that prevents the pass from
// running at all (e.g. the initial owned-VM listing) — never because some VMs
// blocked.
func (s *Server) BackfillHardwareTables(ctx context.Context) error {
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return fmt.Errorf("hardware backfill: list owned VMs: %w", err)
	}
	for i := range vms {
		vm := &vms[i]
		// NIC and disk-bus backfill are best-effort per VM: a failure there is logged
		// but must not abort the pass or the subsequent PCI audit (which is what sets
		// the adoption verdict).
		if err := s.backfillVMNICs(ctx, vm); err != nil {
			slog.Warn("hardware backfill: NIC backfill failed", "vm", vm.Name, "error", err)
		}
		if err := s.backfillVMDiskBuses(ctx, vm); err != nil {
			slog.Warn("hardware backfill: disk-bus backfill failed", "vm", vm.Name, "error", err)
		}
		if adopted, reason := s.auditVMPCICompatibility(ctx, vm); !adopted {
			slog.Info("hardware backfill: VM PCI adoption blocked", "vm", vm.Name, "reason", reason)
		}
	}
	return nil
}

// backfillVMNICs upserts a vm_nics row for every live vm_interfaces NIC of vm,
// keyed by the deterministic (vmName, mac) id so the write converges under
// replication. Running twice is a no-op (INSERT OR REPLACE on the same key).
func (s *Server) backfillVMNICs(ctx context.Context, vm *corrosion.VMRecord) error {
	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
			VMName:         vm.Name,
			ID:             corrosion.DeterministicNICID(vm.Name, iface.MAC),
			NetworkName:    iface.NetworkName,
			Model:          "virtio", // legacy vm_interfaces has no model column
			MAC:            iface.MAC,
			Ordinal:        iface.Ordinal,
			IP:             iface.IP,
			TapDevice:      iface.TapDevice,
			SecurityGroups: encodeSecurityGroups(iface.SecurityGroups),
		}); err != nil {
			return err
		}
	}
	return nil
}

// encodeSecurityGroups mirrors corrosion.encodeSGs: a JSON list, or "" for an
// empty/nil set so UpsertNIC's nullIfEmpty stores SQL NULL. The stored form is
// byte-identical to what InsertInterface wrote, so the overlay join and
// replication converge.
func encodeSecurityGroups(sgs []string) string {
	if len(sgs) == 0 {
		return ""
	}
	b, err := json.Marshal(sgs)
	if err != nil {
		return ""
	}
	return string(b)
}

// backfillVMDiskBuses populates vm_disks.bus (CONTRACT e) for every live disk of
// vm whose bus column is still empty, so the disk bus can move fully into
// vm_disks (off the spec blob). The value comes from the stored VMSpec.Disks
// (matched by disk name); a legacy row lacking spec data falls back to the same
// target-dev heuristic resolveDiskBus applies elsewhere (sdX → scsi, else
// virtio). Idempotent: a disk whose bus is already set is skipped, so a rerun
// never rewrites it. The full DiskRecord is re-upserted (INSERT OR REPLACE),
// reusing the existing vm_disks insert shape — no new statement shape.
func (s *Server) backfillVMDiskBuses(ctx context.Context, vm *corrosion.VMRecord) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return err
	}
	specBuses := diskBusesFromSpec(vm.Spec)
	for _, d := range disks {
		if d.Bus != "" {
			continue // already populated — idempotent skip
		}
		d.Bus = resolveDiskBus("", specBuses[d.DiskName], d.TargetDev)
		if d.Bus == "" {
			continue // resolveDiskBus always yields a bus, but stay defensive
		}
		if err := corrosion.InsertDisk(ctx, s.db, d); err != nil {
			return err
		}
	}
	return nil
}

// auditVMPCICompatibility reconciles a VM's PCI passthrough intent against the
// AUTHORITATIVE membership source — the inactive (persistent) libvirt domain
// definition — and records the per-VM hardware-adoption verdict.
//
// Design (membership authority = inactive XML):
//   - The set of PCI devices the VM ACTUALLY has is the set of <hostdev> source
//     BDFs in the inactive definition (DumpXMLInactive). A device in the stored
//     VMSpec.Devices blob but ABSENT from that set was legacy-detached and is NOT
//     imported (prevents resurrection). A device owned in host_pci_devices but
//     absent from the inactive definition is a stale/incomplete-detach remnant —
//     quarantined (logged, not imported).
//   - VMSpec.Devices supplies SELECTOR RICHNESS for the devices that ARE present:
//     an addressed spec (resolved address present in the XML) imports with its
//     rich selector (classified via ClassifyPCISelector — a mapping-backed device
//     stays "mapping"/exclusive_key=NULL, an address device pins on its BDF); an
//     XML member with no matching rich spec imports as a concrete address.
//   - Duplicate identical selectors get distinct ids via the occurrence ordinal
//     (DeterministicPCIIntentID). When the selector↔member grouping cannot be
//     resolved unambiguously, the VM is BLOCKED rather than coalesced.
//   - No trustworthy inactive definition (DumpXMLInactive errors / no persistent
//     def) ⇒ blocked; the caller continues to the next VM.
//
// selector_payload is protojson-encoded (CONTRACT b) to match the resolver's
// protojson.Unmarshal decode. Returns (adopted, reason) and persists the verdict
// via SetHardwareAdoptionState.
func (s *Server) auditVMPCICompatibility(ctx context.Context, vm *corrosion.VMRecord) (bool, string) {
	// Membership authority: the persistent domain definition.
	if s.virt == nil {
		return s.blockAdoption(ctx, vm.Name, "no inactive domain definition")
	}
	xmlText, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil || xmlText == "" {
		return s.blockAdoption(ctx, vm.Name, "no inactive domain definition")
	}

	// Ordered, canonicalized set of hostdev source BDFs present in the definition.
	var xmlBDFs []string
	seen := map[string]bool{}
	for _, raw := range libvirt.HostdevSourcePCIAddresses(xmlText) {
		bdf, ok := pci.CanonicalBDF(raw)
		if !ok {
			slog.Warn("hardware backfill: skipping unparseable hostdev source address", "vm", vm.Name, "raw", raw)
			continue
		}
		if seen[bdf] {
			continue // the same host BDF cannot back two hostdevs
		}
		seen[bdf] = true
		xmlBDFs = append(xmlBDFs, bdf)
	}
	xmlSet := seen

	// Lease-only quarantine: a device this VM owns in host_pci_devices but absent
	// from the inactive definition is a stale/incomplete-detach remnant. It is NOT
	// imported (we import from the definition, not from ownership) — log it for
	// cleanup. This never blocks: the VM stays classifiable.
	if live, _, oerr := corrosion.VMDeviceOwnership(ctx, s.db, s.hostName, vm.Name); oerr == nil {
		for _, addr := range live {
			if bdf, ok := pci.CanonicalBDF(addr); ok && !xmlSet[bdf] {
				slog.Warn("hardware backfill: lease-only PCI device quarantined (owned but absent from inactive definition)",
					"vm", vm.Name, "address", bdf)
			}
		}
	}

	// Split the stored device specs into address-matched vs. portable selectors.
	spec := parseVMSpecBlob(vm.Spec)
	addressedByBDF := map[string][]*pb.DeviceSpec{}
	var portable []*pb.DeviceSpec
	for _, d := range spec.GetDevices() {
		if bdf, ok := pci.CanonicalBDF(d.GetAddress()); ok {
			addressedByBDF[bdf] = append(addressedByBDF[bdf], d)
		} else {
			portable = append(portable, d) // type/vendor/mapping-unresolved/sriov
		}
	}

	occ := map[string]int{} // occurrence counter per canonical selector
	var plan []corrosion.PCIIntentRecord
	var remaining []string // XML members not claimed by an addressed spec

	// Address-matched import, in document order (deterministic across peers).
	for _, bdf := range xmlBDFs {
		specs := addressedByBDF[bdf]
		switch {
		case len(specs) == 1:
			plan = append(plan, s.makeAddressedIntent(vm.Name, specs[0], bdf, occ))
		case len(specs) > 1:
			// Two specs resolve to the SAME single host member — cannot pair.
			return s.blockAdoption(ctx, vm.Name,
				fmt.Sprintf("ambiguous PCI grouping: multiple device specs resolve to host address %s", bdf))
		default:
			remaining = append(remaining, bdf)
		}
	}

	// Attribute the remaining (unclaimed) XML members to portable selectors.
	switch {
	case len(remaining) == 0:
		// Every member is accounted for; any portable specs are detached (not
		// present in the definition) and are correctly NOT imported.
	case len(portable) == 0:
		// No portable selectors: each unexplained member (an IOMMU-group sibling, or
		// an address device the blob doesn't carry) imports as a concrete address.
		for _, bdf := range remaining {
			plan = append(plan, s.makeConcreteAddressIntent(vm.Name, bdf, occ))
		}
	case len(portable) == len(remaining):
		// Clean 1:1: every portable selector is present, every member explained. The
		// specific selector↔member pairing does not affect the intent set (a portable
		// intent carries no BDF), so this is unambiguous.
		for _, d := range portable {
			plan = append(plan, s.makePortableIntent(vm.Name, d, occ))
		}
	case len(portable) > len(remaining):
		// Fewer members than portable selectors ⇒ some selectors were detached.
		// Unambiguous only when the portable selectors are interchangeable (all the
		// same canonical selector); otherwise we cannot tell which were detached.
		if !allSameCanonicalSelector(portable) {
			return s.blockAdoption(ctx, vm.Name,
				fmt.Sprintf("ambiguous PCI grouping: %d portable selectors for %d unclaimed hostdev member(s)", len(portable), len(remaining)))
		}
		for i := 0; i < len(remaining); i++ {
			plan = append(plan, s.makePortableIntent(vm.Name, portable[i], occ))
		}
	default: // len(portable) < len(remaining), remaining > 0
		// More unclaimed members than portable selectors can explain (count>1 /
		// IOMMU-sibling expansion): the grouping is ambiguous — block rather than
		// guess which members belong to which selector.
		return s.blockAdoption(ctx, vm.Name,
			fmt.Sprintf("ambiguous PCI grouping: %d portable selector(s) under-account for %d unclaimed hostdev member(s)", len(portable), len(remaining)))
	}

	// Commit the plan (atomic per VM: nothing was written on a block above).
	for _, rec := range plan {
		if err := corrosion.UpsertPCIIntent(ctx, s.db, rec); err != nil {
			return s.blockAdoption(ctx, vm.Name, fmt.Sprintf("failed to write PCI intent %s: %v", rec.DeviceID, err))
		}
	}
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, vm.Name, "adopted", ""); err != nil {
		slog.Warn("hardware backfill: set adopted state failed", "vm", vm.Name, "error", err)
	}
	return true, ""
}

// blockAdoption records the blocked verdict + reason and returns the audit's
// (adopted=false, reason) tuple.
func (s *Server) blockAdoption(ctx context.Context, vmName, reason string) (bool, string) {
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, vmName, "blocked", reason); err != nil {
		slog.Warn("hardware backfill: set blocked state failed", "vm", vmName, "error", err)
	}
	return false, reason
}

// makeAddressedIntent builds the intent for a VMSpec.Device whose resolved
// address is present in the inactive definition. The spec's address is
// normalized to the canonical member BDF so the exclusive_key (for an "address"
// kind) matches host_pci_devices and the payload carries a resolvable address.
func (s *Server) makeAddressedIntent(vmName string, d *pb.DeviceSpec, canonBDF string, occ map[string]int) corrosion.PCIIntentRecord {
	nd := proto.Clone(d).(*pb.DeviceSpec)
	nd.Address = canonBDF
	return s.makeIntentRecord(vmName, nd, occ)
}

// makePortableIntent builds the intent for a portable selector (type/vendor/
// mapping-unresolved/sriov) present in the definition — the spec is used as-is
// (it carries no concrete address to pin on).
func (s *Server) makePortableIntent(vmName string, d *pb.DeviceSpec, occ map[string]int) corrosion.PCIIntentRecord {
	return s.makeIntentRecord(vmName, d, occ)
}

// makeConcreteAddressIntent builds a concrete-address intent for an XML member
// that no rich spec explains (an IOMMU sibling, or an address device the blob
// lost): selector_kind="address", exclusive_key=BDF.
func (s *Server) makeConcreteAddressIntent(vmName, bdf string, occ map[string]int) corrosion.PCIIntentRecord {
	return s.makeIntentRecord(vmName, &pb.DeviceSpec{Address: bdf}, occ)
}

// makeIntentRecord classifies d, protojson-encodes it as the selector payload,
// and assigns the deterministic device_id with the per-canonical-selector
// occurrence ordinal so duplicate identical selectors do not collide.
func (s *Server) makeIntentRecord(vmName string, d *pb.DeviceSpec, occ map[string]int) corrosion.PCIIntentRecord {
	kind, exclusiveKey := corrosion.ClassifyPCISelector(d)
	payload, err := protojson.Marshal(d)
	if err != nil {
		// protojson.Marshal of a concrete DeviceSpec cannot fail in practice;
		// degrade to an empty payload rather than panic.
		slog.Warn("hardware backfill: protojson.Marshal device spec failed", "vm", vmName, "error", err)
		payload = []byte("{}")
	}
	canonical := corrosion.CanonicalPCISelector(d)
	occurrence := occ[canonical]
	occ[canonical] = occurrence + 1
	return corrosion.PCIIntentRecord{
		VMName:          vmName,
		DeviceID:        corrosion.DeterministicPCIIntentID(vmName, canonical, occurrence),
		HostName:        s.hostName,
		SelectorKind:    kind,
		SelectorPayload: string(payload),
		ExclusiveKey:    exclusiveKey,
	}
}

// parseVMSpecBlob decodes the stored VMSpec blob (encoding/json, as CreateVM
// persists it — NOT protojson). An empty or unparseable blob yields an empty
// spec (no devices to import), never an error — the audit still classifies the
// VM from its inactive definition.
func parseVMSpecBlob(blob string) *pb.VMSpec {
	spec := &pb.VMSpec{}
	if blob == "" {
		return spec
	}
	if err := json.Unmarshal([]byte(blob), spec); err != nil {
		return &pb.VMSpec{}
	}
	return spec
}

// allSameCanonicalSelector reports whether every spec in ds derives the same
// canonical selector — i.e. they are interchangeable duplicates.
func allSameCanonicalSelector(ds []*pb.DeviceSpec) bool {
	if len(ds) < 2 {
		return true
	}
	first := corrosion.CanonicalPCISelector(ds[0])
	for _, d := range ds[1:] {
		if corrosion.CanonicalPCISelector(d) != first {
			return false
		}
	}
	return true
}
