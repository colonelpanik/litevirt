package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// Journaled, stopped-capable, at-most-once CONCRETE-ADDRESS PCI attach/detach —
// the disk/NIC journaled machinery applied to PCI passthrough, but ONLY for a
// selector that ClassifyPCISelector resolves to
// selector_kind=="address": the same operation_protocol_v1/hardware_v2 gates, the
// shared owner-side at-most-once claim (deviceOpOutcome/deviceOpFromPeer), the same
// journal-before-mutate DAG, and directional compensation. It additionally owns the
// hardware-foundation PCI specifics: it acquires device leases + binds VFIO for a
// RUNNING attach (resolved BDF + IOMMU-group siblings = the realized members),
// live-attaches an aliased <hostdev> per member, and persists BOTH vm_pci_intent
// AND vm_pci_realizations (contract (g): reconcile only READS realizations; attach
// MUST WRITE them). A STOPPED attach RESERVES the intent only — no bind, no lease,
// no realization — and reconcileDomainDefinition builds the hostdev from pure
// intent-resolution (the bind/realization happen later at VM start). The SR-IOV /
// type / vendor / mapping selectors KEEP the existing running-only attachPCIDevice
// path unchanged (see hotplug.go routing).

// ── request hashes ──────────────────────────────────────────────────────────

// attachPCIRequestHash is the canonical semantic hash for a concrete-address PCI
// attach: the normalized BDF is the request identity (the resolved members +
// aliases are allocation outcomes, not part of the request — mirrors
// attachDiskRequestHash excluding the allocated target_dev).
func attachPCIRequestHash(vmName, address string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("attach-pci|%s|%s", vmName, strings.ToLower(address))))
	return hex.EncodeToString(sum[:])
}

// detachPCIRequestHash is the canonical semantic hash for a concrete-address PCI
// detach — the BDF is the immutable identity a detach acts on.
func detachPCIRequestHash(vmName, address string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("detach-pci|%s|%s", vmName, strings.ToLower(address))))
	return hex.EncodeToString(sum[:])
}

// pciMemberAlias derives the stable hostdev alias a member is attached under —
// "ua-<device_id>-<member_id>" — identical to the alias reconcileDomainDefinition
// emits from the same intent, so a running live-attach and a later
// stopped/start-time reconcile agree on the persistent-definition hostdev.
func pciMemberAlias(deviceID, memberID string) string {
	return "ua-" + deviceID + "-" + memberID
}

// hostdevAliasInXML reports whether a domain XML carries a <hostdev> whose
// <alias name=...> matches alias (either quote style). Mirrors diskDevInXML /
// nicMacInXML — the definition-membership substring check, keyed on the hostdev's
// stable user alias.
func hostdevAliasInXML(xmlText, alias string) bool {
	if xmlText == "" || alias == "" {
		return false
	}
	return strings.Contains(xmlText, "name='"+alias+"'") || strings.Contains(xmlText, `name="`+alias+`"`)
}

// ── pre-latch spec dual-write helpers (§8) ────────────────────────────────────

// appendPCIDeviceToSpec returns specJSON with the concrete-address DeviceSpec added
// to VMSpec.Devices (the pre-latch compatibility write a pre-hardware_v2 reader
// consumes). Idempotent: an address already present in Devices is left as-is.
func appendPCIDeviceToSpec(specJSON string, dev *pb.DeviceSpec) (string, error) {
	spec := &pb.VMSpec{}
	if specJSON != "" {
		if err := json.Unmarshal([]byte(specJSON), spec); err != nil {
			return "", err
		}
	}
	for _, d := range spec.Devices {
		if strings.EqualFold(d.Address, dev.Address) {
			return specJSON, nil // already present
		}
	}
	spec.Devices = append(spec.Devices, dev)
	b, err := json.Marshal(spec)
	return string(b), err
}

// removePCIDeviceFromSpec returns specJSON with the concrete-address DeviceSpec
// whose Address matches removed from VMSpec.Devices (the pre-latch mirror of a
// detach). A no-op when the address is absent.
func removePCIDeviceFromSpec(specJSON, address string) (string, error) {
	spec := &pb.VMSpec{}
	if specJSON != "" {
		if err := json.Unmarshal([]byte(specJSON), spec); err != nil {
			return "", err
		}
	}
	kept := spec.Devices[:0:0]
	for _, d := range spec.Devices {
		if strings.EqualFold(d.Address, address) {
			continue
		}
		kept = append(kept, d)
	}
	spec.Devices = kept
	b, err := json.Marshal(spec)
	return string(b), err
}

// ── ATTACH ──────────────────────────────────────────────────────────────────

// attachPCIEntry is the entry-node half for a concrete-address PCI attach,
// mirroring attachDiskEntry/attachNICEntry: it enforces the operation_protocol_v1
// prerequisite, mints/derives the operation identity, runs the same-entry
// response-replay idempotency layer, and either forwards to the owner (raw key
// stripped, op identity in trusted peer metadata) or executes locally.
func (s *Server) attachPCIEntry(ctx context.Context, req *pb.AttachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	spec := req.PciDevice
	if spec.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "pci device address is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"pci attach requires the operation_protocol_v1 capability to be active")
	}

	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.attachPCIOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString() // keyless call: a per-attempt id (no cross-retry dedup)
	}
	opID := corrosion.DeterministicOperationID("AttachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := attachPCIRequestHash(vmRec.Name, spec.Address)

	if req.IdempotencyKey != "" {
		replay, claimID, ierr := s.idempotencyBegin(ctx, req.IdempotencyKey, "AttachDevice", idempotencyRequestHash(req))
		if ierr != nil {
			return nil, ierr
		}
		if replay != nil {
			out := &pb.VM{}
			if proto.Unmarshal(replay, out) != nil {
				return nil, status.Error(codes.Internal, "corrupt idempotency record")
			}
			return out, nil
		}
		stopHB := s.startIdempotencyHeartbeat(ctx, req.IdempotencyKey, claimID)
		defer func() {
			stopHB()
			if ferr := s.idempotencyFinish(ctx, req.IdempotencyKey, claimID, resp, retErr); ferr != nil && retErr == nil {
				resp, retErr = nil, ferr
			}
		}()
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		fwd := proto.Clone(req).(*pb.AttachDeviceRequest)
		fwd.IdempotencyKey = "" // owner must NOT re-enter the entry idempotency layer
		resp, retErr = client.AttachDevice(withDeviceOpMetadata(ctx, opID, reqHash), fwd)
		return resp, retErr
	}

	resp, retErr = s.attachPCIOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// attachPCIOwner runs on the VM's owning host under the VM lock — the at-most-once
// execution point, mirroring attachDiskOwner/attachNICOwner. It reduces the
// replicated operation's state (reconstructing a prior outcome instead of
// re-running), enforces the concrete-address exclusivity invariant, derives the
// deterministic intent id, and — pre-latch — folds the concrete DeviceSpec into the
// desired spec passed to BeginVMOperation (the barrier claim atomically commits the
// vms.spec dual-write; latched → the spec is unchanged, intent-only).
func (s *Server) attachPCIOwner(ctx context.Context, req *pb.AttachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
	unlock := s.lockVM(vmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", vmName, vm.HostName)
	}

	if out, oerr, handled := s.deviceOpOutcome(ctx, vm, opID, reqHash, corrosion.OpDeviceAttach); handled {
		return out, oerr
	}

	latched := s.hardwareV2Latched(ctx)
	running := vm.State == "running"
	if !running && !latched {
		return nil, status.Errorf(codes.FailedPrecondition,
			"stopped-VM PCI attach for %q is not available until hardware_v2 is active", vmName)
	}

	spec := req.PciDevice
	kind, exclusiveKey := corrosion.ClassifyPCISelector(spec)
	if kind != "address" || exclusiveKey == nil {
		return nil, status.Errorf(codes.Internal, "attachPCIOwner reached with a non-address selector for %q", vmName)
	}
	normAddr := *exclusiveKey

	// Exclusivity: a given host BDF may back at most one VM's live intent. A read
	// failure must FAIL the operation fail-closed BEFORE any mutation — swallowing it
	// would let two VMs claim the same passthrough device.
	owner, err := corrosion.PCIIntentExclusiveOwner(ctx, s.db, s.hostName, normAddr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check PCI exclusivity for %q: %v", vmName, err)
	}
	if owner != "" && owner != vmName {
		return nil, status.Errorf(codes.AlreadyExists,
			"PCI device %s (host %s) is already claimed by VM %q", normAddr, s.hostName, owner)
	}
	if owner == vmName {
		return nil, status.Errorf(codes.AlreadyExists, "PCI device %s is already attached to VM %q", normAddr, vmName)
	}

	deviceID := corrosion.DeterministicPCIIntentID(corrosion.CanonicalPCISelector(spec), 0)
	payload, perr := protojson.Marshal(spec)
	if perr != nil {
		return nil, status.Errorf(codes.Internal, "encode selector payload: %v", perr)
	}

	// Pre-latch dual-write: fold the concrete DeviceSpec into the desired spec so the
	// barrier claim commits vms.spec.Devices atomically (a pre-hardware_v2 reader still
	// sees the device). Latched → the spec is unchanged (vm_pci_intent is authoritative).
	desiredSpec := vm.Spec
	if !latched {
		ds, merr := appendPCIDeviceToSpec(vm.Spec, &pb.DeviceSpec{Address: normAddr})
		if merr != nil {
			return nil, status.Errorf(codes.Internal, "encode desired spec: %v", merr)
		}
		desiredSpec = ds
	}

	op := corrosion.OperationRecord{
		ID:             opID,
		Method:         "AttachDevice",
		Principal:      callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:        vm.Project,
		ResourceKind:   "vm",
		ResourceID:     vmName,
		OperationKind:  string(corrosion.OpDeviceAttach),
		RequestHash:    reqHash,
		IdempotencyKey: idemKey,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, desiredSpec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different PCI attach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot attach a PCI device to %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executePCIAttach(ctx, vm, spec, normAddr, deviceID, string(payload), opID, vm.OwnerEpoch, newGen, running, !latched)
}

// pciAttachRollback carries the state needed to compensate a failed concrete-address
// attach. Directional compensation rolls BACK (§8): inverse live-detach attached
// members → releaseDeviceLeases (unbind + owner-release) → tombstone realization +
// intent rows → restore the prior definition + (pre-latch) the prior spec.
type pciAttachRollback struct {
	vm                  *corrosion.VMRecord
	opID                string
	epoch               int64
	newGen              int64
	deviceID            string
	pciAddress          string // normalized primary BDF
	members             []ResolvedMember
	origSpec            string // spec before the pre-latch dual-write, restored on rollback
	running             bool
	dualWrite           bool // this execution folded the DeviceSpec into vms.spec (pre-latch)
	leaseFinish         func()
	acquired            bool     // acquireDeviceLeases succeeded (vfio bound + ownership)
	attachedAddrs       []string // members whose live hostdev attach succeeded
	intentWritten       bool
	realizationsWritten bool
}

// executePCIAttach realizes the attach DAG under the lock: resolve the concrete
// members (pure) → journal the plan → RUNNING: acquire leases (vfio bind) + live
// attach each aliased <hostdev> + commit vm_pci_intent AND vm_pci_realizations;
// STOPPED: reserve vm_pci_intent only (no bind/lease/realization) then
// reconcileDomainDefinition builds the hostdev from pure intent-resolution → verify
// both-state membership → CompleteVMOperation. Any failure routes to failPCIAttach.
func (s *Server) executePCIAttach(ctx context.Context, vm *corrosion.VMRecord, spec *pb.DeviceSpec, normAddr, deviceID, selectorPayload, opID string, epoch, newGen int64, running, dualWrite bool) (*pb.VM, error) {
	rb := &pciAttachRollback{vm: vm, opID: opID, epoch: epoch, newGen: newGen, deviceID: deviceID,
		pciAddress: normAddr, origSpec: vm.Spec, running: running, dualWrite: dualWrite}

	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepReserved)

	// Resolve the concrete members (BDF + IOMMU-group siblings). PURE — no vfio bind,
	// no ownership mutation — safe on both the running and stopped paths. The stopped
	// path uses the members only to compute the expected aliases for verification;
	// reconcileDomainDefinition resolves the same intent independently.
	members, rerr := s.resolveDeviceSpec(ctx, vm.Name, &pb.DeviceSpec{Address: normAddr}, deviceID, map[string]bool{})
	if rerr != nil {
		return s.failPCIAttach(ctx, rb, status.Code(rerr), fmt.Errorf("resolve PCI device %s: %w", normAddr, rerr))
	}
	rb.members = members

	// Journal the plan BEFORE the irreversible bind/attach so a crash recovers.
	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	if s.opJournal != nil {
		addrs := make([]string, len(members))
		for i, m := range members {
			addrs[i] = m.Address
		}
		entry := opjournal.Entry{
			OperationID:    opID,
			OwnerEpoch:     epoch,
			SpecGeneration: newGen,
			ResourceID:     vm.Name,
			Kind:           "device_attach",
			Stage:          "planned",
			Artifacts: map[string]string{
				"device_id":              deviceID,
				"pci_address":            normAddr,
				"member_addresses":       strings.Join(addrs, ","),
				"selector_payload":       selectorPayload,
				"prior_active_xml":       priorActive,
				"prior_inactive_xml":     priorInactive,
				"member_active_before":   strconv.FormatBool(hostdevAliasInXML(priorActive, pciMemberAlias(deviceID, "m0"))),
				"member_inactive_before": strconv.FormatBool(hostdevAliasInXML(priorInactive, pciMemberAlias(deviceID, "m0"))),
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			// No side effect yet → clean terminal failure.
			return s.failPCIAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal attach plan: %w", err))
		}
	}

	intent := corrosion.PCIIntentRecord{
		VMName: vm.Name, DeviceID: deviceID, HostName: s.hostName,
		SelectorKind: "address", SelectorPayload: selectorPayload, ExclusiveKey: &normAddr,
	}

	if running {
		// Acquire the durable device lease + bind every member to vfio-pci BEFORE the
		// live attach; on failure acquire already rolled back its own binds.
		finish, aerr := s.acquireDeviceLeases(ctx, vm.Name, members)
		if aerr != nil {
			return s.failPCIAttach(ctx, rb, status.Code(aerr), fmt.Errorf("acquire device leases: %w", aerr))
		}
		rb.acquired = true
		rb.leaseFinish = finish
		s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepClaimed)

		for _, m := range members {
			alias := pciMemberAlias(deviceID, m.MemberID)
			if err := s.virt.AttachHostdevWithAlias(vm.Name, m.Address, alias); err != nil {
				return s.failPCIAttach(ctx, rb, codes.Internal, fmt.Errorf("attach PCI hostdev %s: %w", m.Address, err))
			}
			rb.attachedAddrs = append(rb.attachedAddrs, m.Address)
		}
		if err := corrosion.UpsertPCIIntent(ctx, s.db, intent); err != nil {
			return s.failPCIAttach(ctx, rb, codes.Internal, fmt.Errorf("record PCI intent: %w", err))
		}
		rb.intentWritten = true
		if err := s.writePCIRealizations(ctx, vm.Name, deviceID, members); err != nil {
			return s.failPCIAttach(ctx, rb, codes.Internal, err)
		}
		rb.realizationsWritten = true
	} else {
		// Stopped RESERVE: intent only (no bind, no lease, no realization — those happen
		// at VM start). reconcileDomainDefinition builds the hostdev from the intent.
		if err := corrosion.UpsertPCIIntent(ctx, s.db, intent); err != nil {
			return s.failPCIAttach(ctx, rb, codes.Internal, fmt.Errorf("record PCI intent: %w", err))
		}
		rb.intentWritten = true
		s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepClaimed)
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			return s.failPCIAttach(ctx, rb, codes.Internal, fmt.Errorf("reconcile definition: %w", err))
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepBound)

	// Verify terminal membership before completing (§8): on the running path every
	// member's aliased hostdev must be present in BOTH the live domain AND the
	// persistent (inactive) definition, because the live attach applies live+config.
	divergence, verr := s.verifyPCIAttached(vm.Name, deviceID, members, running)
	if verr != nil {
		if running && divergence {
			return s.failPCIAttach(ctx, rb, codes.Internal, fmt.Errorf("verify attach membership: %w", verr))
		}
		slog.Error("pci attach: membership unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", verr)
		return nil, status.Errorf(codes.Internal, "pci attach for %q could not be verified; left recoverable: %v", vm.Name, verr)
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepAttached)

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		// The device is fully attached (bound + realized), but the barrier could not be
		// cleared — the CAS precondition no longer holds (ownership/generation moved
		// underneath the op) or the write failed. Do NOT remove the journal, clear the
		// device lease, or report success; leave the operation recovery-required.
		slog.Error("pci attach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "pci attach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
	}
	if rb.leaseFinish != nil {
		rb.leaseFinish() // VM row is durable — clear the crash-recovery lease.
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("pci attach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("pci device attached", "vm", vm.Name, "address", normAddr, "device", deviceID)
	s.recordVMEvent(ctx, vm.Name, "device.attached", "ok", "pci "+normAddr)
	s.publish("device.attached", vm.Name, "pci:"+normAddr)
	return s.vmToProto(ctx, vm.Name)
}

// writePCIRealizations persists one vm_pci_realizations row per resolved member —
// the concrete host device(s) actually attached — carrying the member id, resolved
// address, hostdev alias, and ordinal (contract (g): attach MUST write these;
// reconcile only reads them). Any DB error fails the operation.
func (s *Server) writePCIRealizations(ctx context.Context, vmName, deviceID string, members []ResolvedMember) error {
	for _, m := range members {
		if err := corrosion.UpsertPCIRealization(ctx, s.db, corrosion.PCIRealizationRecord{
			VMName: vmName, DeviceID: deviceID, MemberID: m.MemberID, HostName: s.hostName,
			ResolvedAddress: m.Address, XMLAlias: pciMemberAlias(deviceID, m.MemberID), Ordinal: m.Ordinal,
		}); err != nil {
			return fmt.Errorf("record PCI realization %s/%s: %w", deviceID, m.MemberID, err)
		}
	}
	return nil
}

// failPCIAttach compensates a failed attach by rolling BACK (§8): inverse
// live-detach the members this execution attached, releaseDeviceLeases (unbind
// vfio + owner-release the devices this attach claimed, and clear the durable
// lease), tombstone the realization + intent rows THIS execution wrote, restore the
// prior inactive definition on the stopped path, and — pre-latch — restore the
// prior spec. If the rollback fully completes it records a terminal failure +
// clears the barrier; otherwise the operation is left NON-TERMINAL for recovery.
func (s *Server) failPCIAttach(ctx context.Context, rb *pciAttachRollback, code codes.Code, cause error) (*pb.VM, error) {
	rolledBack := true

	for _, addr := range rb.attachedAddrs {
		if err := s.virt.DetachHostdev(rb.vm.Name, addr); err != nil {
			slog.Error("pci attach rollback: inverse-detach failed", "vm", rb.vm.Name, "address", addr, "error", err)
			rolledBack = false
		}
	}
	if rb.acquired {
		addrs := make([]string, len(rb.members))
		for i, m := range rb.members {
			addrs[i] = m.Address
		}
		s.releaseDeviceLeases(ctx, rb.vm.Name, addrs)
		if rb.leaseFinish != nil {
			rb.leaseFinish()
		}
	}
	if rb.realizationsWritten {
		if err := corrosion.TombstonePCIRealizations(ctx, s.db, rb.vm.Name, rb.deviceID); err != nil {
			slog.Error("pci attach rollback: tombstone realizations failed", "vm", rb.vm.Name, "device", rb.deviceID, "error", err)
			rolledBack = false
		}
	}
	if rb.intentWritten {
		if err := corrosion.TombstonePCIIntent(ctx, s.db, rb.vm.Name, rb.deviceID); err != nil {
			slog.Error("pci attach rollback: tombstone intent failed", "vm", rb.vm.Name, "device", rb.deviceID, "error", err)
			rolledBack = false
		} else if !rb.running {
			// Restore the prior inactive definition: re-reconcile now that the intent is
			// gone drops the hostdev we added from the definition.
			if err := s.reconcileDomainDefinition(ctx, rb.vm, nil); err != nil {
				slog.Error("pci attach rollback: re-reconcile to drop hostdev failed", "vm", rb.vm.Name, "error", err)
				rolledBack = false
			}
		}
	}

	if !rolledBack {
		slog.Error("pci attach: rollback incomplete — operation left recoverable", "vm", rb.vm.Name, "op", rb.opID, "cause", cause)
		return nil, status.Errorf(code, "pci attach for %q failed and rollback is incomplete; left recoverable: %v", rb.vm.Name, cause)
	}

	s.appendOpStep(ctx, rb.opID, rb.epoch, corrosion.OpDeviceAttach, corrosion.OpStepRollbackCompleted)
	applied, ferr := s.db.FailVMOperation(ctx, rb.vm.Name, rb.opID, rb.epoch, rb.newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("pci attach: recording terminal failure failed — recovery will reconcile", "vm", rb.vm.Name, "op", rb.opID, "error", ferr)
	case !applied:
		// The barrier was NOT cleared — ownership may have moved on. Do not touch the
		// (possibly no-longer-ours) desired spec or the journal; leave the operation
		// recovery-required.
		slog.Error("pci attach: terminal-failure CAS did not apply — left recoverable", "vm", rb.vm.Name, "op", rb.opID)
	default:
		// Restore the pre-latch spec dual-write now that the barrier is clear (best-effort:
		// the op is already terminally failed; a residual Devices entry only affects a
		// pre-hardware_v2 reader and is corrected by the next reconcile).
		if rb.dualWrite {
			if _, _, err := corrosion.MutateDesiredSpec(ctx, s.db, rb.vm.Name, func(string) (string, error) {
				return rb.origSpec, nil
			}); err != nil {
				slog.Warn("pci attach rollback: restore pre-latch spec failed", "vm", rb.vm.Name, "error", err)
			}
		}
		if s.opJournal != nil {
			_ = s.opJournal.Remove(rb.opID)
		}
	}
	s.recordVMEvent(ctx, rb.vm.Name, "device.attached", "error", "pci "+rb.pciAddress)
	return nil, status.Error(code, cause.Error())
}

// verifyPCIAttached asserts every member's aliased hostdev landed in the
// authoritative definition(s) after an attach, mirroring verifyDiskAttached. On the
// RUNNING path each alias must be present in BOTH the live domain AND the persistent
// (inactive) definition; on the STOPPED path only the inactive definition. The
// divergence flag is meaningful only when err != nil (true = read succeeded but
// membership wrong → compensate; false = a read failed → leave recoverable).
func (s *Server) verifyPCIAttached(vmName, deviceID string, members []ResolvedMember, running bool) (divergence bool, err error) {
	inactive, ierr := s.virt.DumpXMLInactive(vmName)
	if ierr != nil {
		return false, fmt.Errorf("read inactive definition: %w", ierr)
	}
	var live string
	if running {
		l, lerr := s.virt.DumpXML(vmName)
		if lerr != nil {
			return false, fmt.Errorf("read live domain: %w", lerr)
		}
		live = l
	}
	for _, m := range members {
		alias := pciMemberAlias(deviceID, m.MemberID)
		if running && !hostdevAliasInXML(live, alias) {
			return true, fmt.Errorf("hostdev %s absent from the live domain after attach", alias)
		}
		if !hostdevAliasInXML(inactive, alias) {
			if running {
				return true, fmt.Errorf("hostdev %s absent from the persistent definition after attach", alias)
			}
			return true, fmt.Errorf("hostdev %s absent from the inactive definition after reconcile", alias)
		}
	}
	return false, nil
}

// ── DETACH ──────────────────────────────────────────────────────────────────

// detachPCIEntry mirrors attachPCIEntry for the concrete-address detach path.
func (s *Server) detachPCIEntry(ctx context.Context, req *pb.DetachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	if req.PciAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "pci_address is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"pci detach requires the operation_protocol_v1 capability to be active")
	}

	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.detachPCIOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString()
	}
	opID := corrosion.DeterministicOperationID("DetachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := detachPCIRequestHash(vmRec.Name, req.PciAddress)

	if req.IdempotencyKey != "" {
		replay, claimID, ierr := s.idempotencyBegin(ctx, req.IdempotencyKey, "DetachDevice", idempotencyRequestHash(req))
		if ierr != nil {
			return nil, ierr
		}
		if replay != nil {
			out := &pb.VM{}
			if proto.Unmarshal(replay, out) != nil {
				return nil, status.Error(codes.Internal, "corrupt idempotency record")
			}
			return out, nil
		}
		stopHB := s.startIdempotencyHeartbeat(ctx, req.IdempotencyKey, claimID)
		defer func() {
			stopHB()
			if ferr := s.idempotencyFinish(ctx, req.IdempotencyKey, claimID, resp, retErr); ferr != nil && retErr == nil {
				resp, retErr = nil, ferr
			}
		}()
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		fwd := proto.Clone(req).(*pb.DetachDeviceRequest)
		fwd.IdempotencyKey = ""
		resp, retErr = client.DetachDevice(withDeviceOpMetadata(ctx, opID, reqHash), fwd)
		return resp, retErr
	}

	resp, retErr = s.detachPCIOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// detachPCIOwner is the at-most-once owner path for a concrete-address PCI detach.
func (s *Server) detachPCIOwner(ctx context.Context, req *pb.DetachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
	unlock := s.lockVM(vmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", vmName, vm.HostName)
	}

	if out, oerr, handled := s.deviceOpOutcome(ctx, vm, opID, reqHash, corrosion.OpDeviceDetach); handled {
		return out, oerr
	}

	latched := s.hardwareV2Latched(ctx)
	running := vm.State == "running"
	if !running && !latched {
		return nil, status.Errorf(codes.FailedPrecondition,
			"stopped-VM PCI detach for %q is not available until hardware_v2 is active", vmName)
	}

	normAddr := strings.ToLower(req.PciAddress)
	// Resolve the intent this address backs — a read failure must FAIL the op
	// fail-closed before any mutation.
	deviceID, found, ierr := s.liveAddressIntent(ctx, vmName, normAddr)
	if ierr != nil {
		return nil, status.Errorf(codes.Internal, "read PCI intents for %q: %v", vmName, ierr)
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "PCI device %s not found on VM %q", normAddr, vmName)
	}

	// Pre-latch: mirror the detach into vms.spec.Devices via the barrier claim.
	desiredSpec := vm.Spec
	if !latched {
		ds, merr := removePCIDeviceFromSpec(vm.Spec, normAddr)
		if merr != nil {
			return nil, status.Errorf(codes.Internal, "encode desired spec: %v", merr)
		}
		desiredSpec = ds
	}

	op := corrosion.OperationRecord{
		ID:             opID,
		Method:         "DetachDevice",
		Principal:      callerUsername(ctx) + "@" + callerRealm(ctx),
		Project:        vm.Project,
		ResourceKind:   "vm",
		ResourceID:     vmName,
		OperationKind:  string(corrosion.OpDeviceDetach),
		RequestHash:    reqHash,
		IdempotencyKey: idemKey,
	}
	applied, err := s.db.BeginVMOperation(ctx, op, desiredSpec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different PCI detach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot detach a PCI device from %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executePCIDetach(ctx, vm, normAddr, deviceID, opID, vm.OwnerEpoch, newGen, running)
}

// liveAddressIntent returns the device_id of the LIVE address-kind vm_pci_intent
// for vmName whose exclusive_key matches normAddr (already lower-cased), and
// whether one was found. Used to route a detach to the journaled concrete-address
// path and to identify the intent to retract.
func (s *Server) liveAddressIntent(ctx context.Context, vmName, normAddr string) (deviceID string, found bool, err error) {
	intents, ierr := corrosion.ListVMPCIIntents(ctx, s.db, vmName)
	if ierr != nil {
		return "", false, ierr
	}
	for _, in := range intents {
		if in.SelectorKind == "address" && in.ExclusiveKey != nil && strings.EqualFold(*in.ExclusiveKey, normAddr) {
			return in.DeviceID, true, nil
		}
	}
	return "", false, nil
}

// executePCIDetach realizes the detach DAG under the lock: journal the plan →
// RUNNING: live-detach every realized member + releaseDeviceLeases + tombstone
// realizations & intent; STOPPED: tombstone realizations & intent then reconcile →
// verify absence → CompleteVMOperation. Compensation rolls FORWARD (§8): once the
// live detach has run the bookkeeping is retried to completion; if it cannot
// complete the operation is left NON-TERMINAL for recovery — never re-attached.
func (s *Server) executePCIDetach(ctx context.Context, vm *corrosion.VMRecord, normAddr, deviceID, opID string, epoch, newGen int64, running bool) (*pb.VM, error) {
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepReserved)

	// The realized members are the concrete host devices to live-detach + release.
	realizations, rerr := corrosion.ListVMPCIRealizations(ctx, s.db, vm.Name)
	if rerr != nil {
		return s.failPCIDetachClean(ctx, vm, opID, epoch, newGen, normAddr,
			codes.Internal, fmt.Errorf("read PCI realizations: %w", rerr))
	}
	var memberAddrs, memberAliases []string
	for _, r := range realizations {
		if r.DeviceID != deviceID {
			continue
		}
		memberAddrs = append(memberAddrs, r.ResolvedAddress)
		memberAliases = append(memberAliases, r.XMLAlias)
	}

	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	if s.opJournal != nil {
		entry := opjournal.Entry{
			OperationID:    opID,
			OwnerEpoch:     epoch,
			SpecGeneration: newGen,
			ResourceID:     vm.Name,
			Kind:           "device_detach",
			Stage:          "planned",
			Artifacts: map[string]string{
				"device_id":          deviceID,
				"pci_address":        normAddr,
				"member_addresses":   strings.Join(memberAddrs, ","),
				"prior_active_xml":   priorActive,
				"prior_inactive_xml": priorInactive,
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			return s.failPCIDetachClean(ctx, vm, opID, epoch, newGen, normAddr,
				codes.Unavailable, fmt.Errorf("journal detach plan: %w", err))
		}
	}

	if running {
		for _, addr := range memberAddrs {
			if err := s.virt.DetachHostdev(vm.Name, addr); err != nil {
				// The irreversible step failed and nothing has committed → clean terminal fail.
				return s.failPCIDetachClean(ctx, vm, opID, epoch, newGen, normAddr,
					codes.Internal, fmt.Errorf("detach PCI hostdev %s: %w", addr, err))
			}
		}
		// Release the devices this VM held + retry the row bookkeeping to completion.
		s.releaseDeviceLeases(ctx, vm.Name, memberAddrs)
		if !s.retryPCIRowTombstone(ctx, vm.Name, deviceID) {
			slog.Error("pci detach: row tombstone failed after live detach — left recoverable", "vm", vm.Name, "op", opID)
			return nil, status.Errorf(codes.Internal, "pci detach for %q applied but bookkeeping incomplete; left recoverable", vm.Name)
		}
	} else {
		if err := corrosion.TombstonePCIRealizations(ctx, s.db, vm.Name, deviceID); err != nil {
			return s.failPCIDetachClean(ctx, vm, opID, epoch, newGen, normAddr,
				codes.Internal, fmt.Errorf("tombstone PCI realizations: %w", err))
		}
		if err := corrosion.TombstonePCIIntent(ctx, s.db, vm.Name, deviceID); err != nil {
			return s.failPCIDetachClean(ctx, vm, opID, epoch, newGen, normAddr,
				codes.Internal, fmt.Errorf("tombstone PCI intent: %w", err))
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			slog.Error("pci detach: reconcile after tombstone failed — left recoverable", "vm", vm.Name, "op", opID, "error", err)
			return nil, status.Errorf(codes.Internal, "pci detach for %q applied but definition not reconciled; left recoverable: %v", vm.Name, err)
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepAttached)

	if err := s.verifyPCIDetached(vm.Name, memberAliases, running); err != nil {
		slog.Error("pci detach: absence unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", err)
		return nil, status.Errorf(codes.Internal, "pci detach for %q could not be verified; left recoverable: %v", vm.Name, err)
	}

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		slog.Error("pci detach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "pci detach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("pci detach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("pci device detached", "vm", vm.Name, "address", normAddr, "device", deviceID)
	s.recordVMEvent(ctx, vm.Name, "device.detached", "ok", "pci "+normAddr)
	s.publish("device.detached", vm.Name, "pci:"+normAddr)
	return s.vmToProto(ctx, vm.Name)
}

// retryPCIRowTombstone retries the intent + realization tombstones a bounded number
// of times (the forward-compensation retry after a successful live detach). Both
// are idempotent UPDATEs, so re-running an already-applied one is harmless.
func (s *Server) retryPCIRowTombstone(ctx context.Context, vmName, deviceID string) bool {
	for attempt := 0; attempt < resizeApplyAttempts; attempt++ {
		if err := corrosion.TombstonePCIRealizations(ctx, s.db, vmName, deviceID); err != nil {
			continue
		}
		if err := corrosion.TombstonePCIIntent(ctx, s.db, vmName, deviceID); err != nil {
			continue
		}
		return true
	}
	return false
}

// failPCIDetachClean records a terminal detach failure + clears the barrier when
// NOTHING was applied to the domain (the live detach never ran and no row was
// tombstoned), so the VM is unchanged and mutable again. It never touches the
// device's host inventory or backing hardware.
func (s *Server) failPCIDetachClean(ctx context.Context, vm *corrosion.VMRecord, opID string, epoch, newGen int64, normAddr string, code codes.Code, cause error) (*pb.VM, error) {
	applied, ferr := s.db.FailVMOperation(ctx, vm.Name, opID, epoch, newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("pci detach: recording terminal failure failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", ferr)
	case !applied:
		slog.Error("pci detach: terminal-failure CAS did not apply — left recoverable", "vm", vm.Name, "op", opID)
	default:
		if s.opJournal != nil {
			_ = s.opJournal.Remove(opID)
		}
	}
	s.recordVMEvent(ctx, vm.Name, "device.detached", "error", "pci "+normAddr)
	return nil, status.Error(code, cause.Error())
}

// verifyPCIDetached asserts every member's aliased hostdev is GONE from the
// authoritative definition(s), mirroring verifyDiskDetached. On the RUNNING path
// each alias must be absent from BOTH the live domain AND the persistent (inactive)
// definition; on the STOPPED path only the inactive definition.
func (s *Server) verifyPCIDetached(vmName string, memberAliases []string, running bool) error {
	inactive, ierr := s.virt.DumpXMLInactive(vmName)
	if ierr != nil {
		return fmt.Errorf("read inactive definition: %w", ierr)
	}
	var live string
	if running {
		l, lerr := s.virt.DumpXML(vmName)
		if lerr != nil {
			return fmt.Errorf("read live domain: %w", lerr)
		}
		live = l
	}
	for _, alias := range memberAliases {
		if running && hostdevAliasInXML(live, alias) {
			return fmt.Errorf("hostdev %s still present in the live domain after detach", alias)
		}
		if hostdevAliasInXML(inactive, alias) {
			return fmt.Errorf("hostdev %s still present in the persistent definition after detach", alias)
		}
	}
	return nil
}
