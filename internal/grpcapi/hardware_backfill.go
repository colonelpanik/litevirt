package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pci"
)

// hardwareBridgeInterval is how often RunHardwareBridge sweeps for legacy
// vm_interfaces rows to materialize into vm_nics. It is a convergence net for the
// rolling-upgrade window, not a hot path, so a coarse interval is deliberate.
const hardwareBridgeInterval = 30 * time.Second

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
	// CONTRACT h: the audit pass has classified every owned VM and populated the
	// typed-hardware tables, so this node now reads hardware correctly across the
	// transition. Mark it hardware_v2-advertise-ready (advertisedCapabilities gates
	// on this via hardwareV2Ready). Set only on the success path — an early return
	// above (the owned-VM listing failed) leaves the node not-ready, so it withholds
	// hardware_v2 and cannot help latch it. Per-VM blocks do NOT withhold readiness:
	// a blocked VM is recorded and fenced at its own mutation site, not a reason to
	// keep the whole node from reading the tables it did populate.
	s.hwV2Ready.Store(true)
	return nil
}

// RunHardwareBridge is the continuous legacy→vm_nics bridge (CONTRACT: transition
// convergence). On a coarse ticker it materializes vm_interfaces rows an OLD peer
// writes during the rolling-upgrade window into vm_nics under the deterministic
// (vm_name, mac) id, so the overlay converges toward vm_nics completeness. It is
// strictly one-directional (never writes vm_interfaces) and therefore safe for old
// peers, which ignore vm_nics; and idempotent/churn-free/non-regressing (see
// corrosion.BridgeVMNICs), so running it repeatedly and on several new nodes
// concurrently converges rather than forks. Runs until ctx is cancelled.
func (s *Server) RunHardwareBridge(ctx context.Context) {
	t := time.NewTicker(hardwareBridgeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.hardwareBridgeOnce(ctx); err != nil {
				slog.Warn("hardware bridge: pass failed", "error", err)
			}
		}
	}
}

// hardwareBridgeOnce runs a single bridge pass over EVERY VM the node can see (not
// just owned ones): an old peer that still writes only vm_interfaces owns its own
// VMs, so scoping to owned VMs would defeat the bridge's purpose. Per-VM failures
// are logged and the sweep continues (isolation); it returns an error only when the
// VM listing itself fails. Idempotent — safe to call every tick.
func (s *Server) hardwareBridgeOnce(ctx context.Context) error {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return fmt.Errorf("hardware bridge: list VMs: %w", err)
	}
	for i := range vms {
		if err := corrosion.BridgeVMNICs(ctx, s.db, vms[i].Name); err != nil {
			slog.Warn("hardware bridge: NIC materialization failed", "vm", vms[i].Name, "error", err)
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
//   - Selector↔member attribution is IOMMU-GROUP-AWARE. A portable selector (and
//     an addressed/mapping selector) re-expands at resolve time to its primary +
//     the primary's IOMMU-group siblings (resolveDeviceSpec.addPrimary), so a
//     multifunction card (GPU + its HDMI-audio function in one IOMMU group)
//     produces several <hostdev>s in the definition but is ONE intent. Members are
//     therefore attributed at IOMMU-GROUP granularity: an unclaimed member that is
//     an IOMMU sibling of an already-attributed primary belongs to THAT intent, and
//     portable selectors are matched against the count of independent IOMMU-group
//     UNITS, not the raw member count.
//   - Duplicate identical selectors get distinct ids via the occurrence ordinal
//     (DeterministicPCIIntentID). When the grouping is GENUINELY ambiguous —
//     independent IOMMU-group units a selector set cannot account for — the VM is
//     BLOCKED rather than coalesced.
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
	// unparseable records that the definition carried a hostdev whose source
	// address did not parse: the derived plan is then INCOMPLETE, so the
	// stale-intent reconciliation below is skipped (a present-but-unparseable
	// device must never have its intent dropped).
	var xmlBDFs []string
	seen := map[string]bool{}
	unparseable := false
	for _, raw := range libvirt.HostdevSourcePCIAddresses(xmlText) {
		bdf, ok := pci.CanonicalBDF(raw)
		if !ok {
			slog.Warn("hardware backfill: skipping unparseable hostdev source address", "vm", vm.Name, "raw", raw)
			unparseable = true
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
	var remaining []string          // XML members not claimed by an addressed spec
	var addressedPrimaries []string // addressed members whose intent re-expands to its IOMMU-group siblings

	// Address-matched import, in document order (deterministic across peers).
	for _, bdf := range xmlBDFs {
		specs := addressedByBDF[bdf]
		switch {
		case len(specs) == 1:
			plan = append(plan, s.makeAddressedIntent(vm.Name, specs[0], bdf, occ))
			addressedPrimaries = append(addressedPrimaries, bdf)
		case len(specs) > 1:
			// Two specs resolve to the SAME single host member — cannot pair.
			return s.blockAdoption(ctx, vm.Name,
				fmt.Sprintf("ambiguous PCI grouping: multiple device specs resolve to host address %s", bdf))
		default:
			remaining = append(remaining, bdf)
		}
	}

	// An addressed (or mapping-with-resolved-address) intent re-expands to its
	// primary + IOMMU-group siblings at resolve time (resolveDeviceSpec.addPrimary),
	// so an unclaimed XML member that is a sibling of an addressed primary belongs to
	// THAT intent's expansion — not a separate host-pinned concrete intent. Drop such
	// siblings from `remaining` so they neither import twice nor trip the block.
	// (Fixes a {mapping,address} selector's IOMMU sibling being imported as a
	// separate host-pinned concrete-address intent.)
	if len(addressedPrimaries) > 0 && len(remaining) > 0 {
		absorbed := map[string]bool{}
		for _, p := range addressedPrimaries {
			for sib := range s.iommuGroupSiblingSet(ctx, p) {
				absorbed[sib] = true
			}
		}
		kept := remaining[:0:0]
		for _, r := range remaining {
			if absorbed[r] {
				continue
			}
			kept = append(kept, r)
		}
		remaining = kept
	}

	// Attribute the remaining (unclaimed) XML members to portable selectors at
	// IOMMU-GROUP granularity: each portable selector re-expands to a primary + its
	// IOMMU-group siblings, so it accounts for ONE independent IOMMU-group unit — not
	// one raw member. A multifunction GPU (GPU + audio in one group) is therefore one
	// unit, one portable selector, one intent.
	switch {
	case len(remaining) == 0:
		// Every member is accounted for (by an addressed intent or an addressed
		// primary's absorbed IOMMU siblings); any portable specs are detached (not
		// present in the definition) and are correctly NOT imported.
	case len(portable) == 0:
		// No portable selectors: each unexplained member (an IOMMU-group sibling, or
		// an address device the blob doesn't carry) imports as a concrete address.
		for _, bdf := range remaining {
			plan = append(plan, s.makeConcreteAddressIntent(vm.Name, bdf, occ))
		}
	default: // len(portable) > 0 && len(remaining) > 0
		// Group the surviving members into independent IOMMU-group units and match
		// against the portable-selector COUNT. The specific selector↔unit pairing does
		// not affect the intent set (a portable intent carries no BDF).
		units := len(s.clusterByIOMMUGroup(ctx, remaining))
		switch {
		case len(portable) == units:
			// Clean: one portable selector per IOMMU-group unit (the common
			// multifunction-GPU case: one type selector, one {GPU,audio} group).
			for _, d := range portable {
				plan = append(plan, s.makePortableIntent(vm.Name, d, occ))
			}
		case len(portable) > units:
			// Fewer units than portable selectors ⇒ some selectors were detached.
			// Unambiguous only when the portable selectors are interchangeable (all the
			// same canonical selector); otherwise we cannot tell which were detached.
			if !allSameCanonicalSelector(portable) {
				return s.blockAdoption(ctx, vm.Name,
					fmt.Sprintf("ambiguous PCI grouping: %d portable selectors for %d IOMMU-group unit(s)", len(portable), units))
			}
			for i := 0; i < units; i++ {
				plan = append(plan, s.makePortableIntent(vm.Name, portable[i], occ))
			}
		default: // len(portable) < units
			// More independent IOMMU-group units than portable selectors can explain:
			// genuine ambiguity — block rather than guess which members belong to which
			// selector.
			return s.blockAdoption(ctx, vm.Name,
				fmt.Sprintf("ambiguous PCI grouping: %d portable selector(s) under-account for %d IOMMU-group unit(s)", len(portable), units))
		}
	}

	// Commit the plan. On a block above nothing was written; this is the confident,
	// complete success path, so it RECONCILES the VM's live intent set to EXACTLY
	// the derived plan — not just upserts. A device detached from the definition
	// AFTER a prior adoption (e.g. an old peer that removed a hostdev it didn't
	// understand but left the intent) would otherwise leave a stale intent live,
	// and reconcileDomainDefinition would RESTORE the detached device at next start.
	//
	// This is a sequential commit, not one ExecuteBatch, BY DESIGN: every write here
	// reuses an EXISTING corrosion accessor whose statement shape is already in the
	// ledger, so stmtshapecheck's builder-statement count is unchanged. A new in-place
	// batch in this package would enumerate as additional builder statements (even
	// though the shapes are already registered), changing that count. The tradeoff is
	// a small partial-write window on a mid-commit error; we fail closed (blockAdoption)
	// consistently there, matching the pre-existing upsert-error handling.
	for _, rec := range plan {
		if err := corrosion.UpsertPCIIntent(ctx, s.db, rec); err != nil {
			return s.blockAdoption(ctx, vm.Name, fmt.Sprintf("failed to write PCI intent %s: %v", rec.DeviceID, err))
		}
	}

	// Reconcile away stale intents: live vm_pci_intent rows whose device_id is NOT in
	// the derived plan (their device is no longer in the definition). SKIP entirely
	// when the definition carried an unparseable hostdev source address — the plan is
	// incomplete and dropping a present-but-unparseable device's intent is worse than
	// leaving a stale one. The empty-plan case (every device detached) correctly
	// tombstones every live intent, which is exactly the rolling-upgrade scenario.
	if unparseable {
		slog.Warn("hardware backfill: skipping stale-intent reconciliation (unparseable hostdev source address present)", "vm", vm.Name)
	} else {
		planIDs := make(map[string]bool, len(plan))
		for _, rec := range plan {
			planIDs[rec.DeviceID] = true
		}
		// ListVMPCIIntents already returns only LIVE rows (deleted_at IS NULL).
		live, err := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
		if err != nil {
			return s.blockAdoption(ctx, vm.Name, fmt.Sprintf("failed to list live PCI intents for reconcile: %v", err))
		}
		for _, in := range live {
			if planIDs[in.DeviceID] {
				continue // present in the plan — keep it
			}
			// Realizations first, intent LAST: the intent row is the durable retry
			// anchor. If either tombstone fails, leaving the intent live means the
			// NEXT audit's stale-set derivation (ListVMPCIIntents — live rows only)
			// re-lists it and retries both; TombstonePCIRealizations is idempotent,
			// so a retry after a partial success is safe. Tombstoning the intent
			// first (the prior order) would drop it off that live-rows scan on any
			// subsequent realization-tombstone failure, orphaning the realization
			// rows with nothing left to revisit them.
			if err := corrosion.TombstonePCIRealizations(ctx, s.db, vm.Name, in.DeviceID); err != nil {
				return s.blockAdoption(ctx, vm.Name, fmt.Sprintf("failed to tombstone stale PCI realizations %s: %v", in.DeviceID, err))
			}
			if err := corrosion.TombstonePCIIntent(ctx, s.db, vm.Name, in.DeviceID); err != nil {
				return s.blockAdoption(ctx, vm.Name, fmt.Sprintf("failed to tombstone stale PCI intent %s: %v", in.DeviceID, err))
			}
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

// buildPCIIntents builds one vm_pci_intent row per entry in devices, in
// document order, sharing a single occurrence counter across the whole call
// (see makeIntentRecord) so duplicate identical selectors don't collide. This
// is the SAME canonicalize-then-classify sequence CreateVM originally ran
// inline; it is now the one place every VM producer with a spec.Devices list
// builds its create-time PCI intents, so the canonicalization fix below can
// never be reintroduced-missing in a future producer.
//
// A concrete address is canonicalized before hashing (on a proto.Clone of the
// DeviceSpec — devices itself, which a caller may later json.Marshal verbatim
// for persistence, is never mutated): the Phase-6 backfill audit's
// makeAddressedIntent normalizes to the libvirt-canonicalized XML BDF, so an
// intent built from a non-canonical concrete BDF (e.g. "41:00.0") would
// otherwise hash to a different device_id than the backfill derives for the
// same physical device, forking into a divergent duplicate row.
//
// Returns nil for an empty/nil devices — the common case for a producer with
// no PCI passthrough (clone, promote).
func (s *Server) buildPCIIntents(vmName string, devices []*pb.DeviceSpec) []corrosion.PCIIntentRecord {
	var pciIntents []corrosion.PCIIntentRecord
	occ := map[string]int{}
	for _, d := range devices {
		nd := d
		if d.Address != "" {
			if canon, ok := pci.CanonicalBDF(d.Address); ok {
				nd = proto.Clone(d).(*pb.DeviceSpec)
				nd.Address = canon
			}
		}
		pciIntents = append(pciIntents, s.makeIntentRecord(vmName, nd, occ))
	}
	return pciIntents
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
		DeviceID:        corrosion.DeterministicPCIIntentID(canonical, occurrence),
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

// iommuGroupSiblingSet returns the canonical IOMMU-group siblings of primary
// (INCLUDING primary itself) as a set, using host_pci_devices.iommu_group — the
// SAME topology source resolveDeviceSpec.addPrimary expands a request with. A
// device with no known group (absent from host_pci_devices, or iommu_group < 0)
// yields just itself, so an unknown topology never coalesces distinct members.
func (s *Server) iommuGroupSiblingSet(ctx context.Context, primary string) map[string]bool {
	set := map[string]bool{primary: true}
	sibs, _ := s.iommuGroupSiblings(ctx, primary)
	for _, sib := range sibs {
		if bdf, ok := pci.CanonicalBDF(sib); ok {
			set[bdf] = true
		}
	}
	return set
}

// clusterByIOMMUGroup partitions members into independent IOMMU-group UNITS: two
// members share a cluster iff they are IOMMU-group siblings (host_pci_devices.
// iommu_group). A member with no known group is its own singleton. Each cluster is
// exactly what ONE selector re-expands to at resolve time, so the cluster COUNT —
// not the raw member count — is what a portable-selector set must account for.
func (s *Server) clusterByIOMMUGroup(ctx context.Context, members []string) [][]string {
	assigned := map[string]bool{}
	var clusters [][]string
	for _, m := range members {
		if assigned[m] {
			continue
		}
		sibs := s.iommuGroupSiblingSet(ctx, m)
		var cluster []string
		for _, n := range members {
			if !assigned[n] && (n == m || sibs[n]) {
				cluster = append(cluster, n)
				assigned[n] = true
			}
		}
		clusters = append(clusters, cluster)
	}
	return clusters
}
