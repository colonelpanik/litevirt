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
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// Journaled, stopped-capable, at-most-once NIC attach/detach. This is the disk
// path's machinery (hotplug_disk.go) APPLIED to NICs: the same
// operation_protocol_v1/hardware_v2 gates, the same owner-side at-most-once claim
// (deviceOpOutcome/deviceOpFromPeer, shared verbatim with disk), the same
// journal-before-mutate DAG, and the same directional compensation. It additionally
// implements the v42 hardware-foundation transition for NICs specifically: a
// pre-latch dual-write to legacy vm_interfaces alongside the new vm_nics (§4.2/§8),
// gated same-network-duplicate rejection, and persisting the model/security_groups
// that the pre-conversion attachNIC silently dropped. The PCI path keeps its
// current running-only behavior.

// ── request hashes ──────────────────────────────────────────────────────────

// attachNICRequestHash is the canonical semantic hash for a NIC attach, covering
// every entry-supplied field EXCEPT the mac when the client left it blank (an
// auto-generated mac is an allocation outcome, not part of the request identity —
// mirrors attachDiskRequestHash excluding the allocated target_dev).
func attachNICRequestHash(vmName string, spec *pb.NetworkAttachment) string {
	model := spec.Model
	if model == "" {
		model = "virtio"
	}
	sgs := append([]string{}, spec.SecurityGroups...)
	sortStrings(sgs)
	sum := sha256.Sum256([]byte(fmt.Sprintf("attach-nic|%s|%s|%s|%s|%s|%s",
		vmName, spec.Name, model, spec.Mac, spec.Ip, strings.Join(sgs, ","))))
	return hex.EncodeToString(sum[:])
}

// detachNICRequestHash is the canonical semantic hash for a NIC detach — the mac is
// the immutable identity a detach acts on.
func detachNICRequestHash(vmName, mac string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("detach-nic|%s|%s", vmName, strings.ToLower(mac))))
	return hex.EncodeToString(sum[:])
}

// sortStrings sorts a []string in place with a tiny insertion sort — avoids
// pulling in "sort" for a handful of security-group names in a request hash.
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}

// encodeNICSecurityGroups JSON-encodes a security-group name list for storage in
// vm_nics.security_groups (mirrors corrosion's private encodeSGs, which vm_nics'
// own writer path does not expose to callers outside the package).
func encodeNICSecurityGroups(sgs []string) (string, error) {
	if len(sgs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(sgs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nicMacInXML reports whether a domain XML carries an <interface> whose <mac
// address> matches mac. Case-insensitive: libvirt normalizes MAC case and a
// client-supplied mac may not match that normalization. Mirrors diskDevInXML —
// the same kind of definition-membership substring check, keyed on the NIC's
// immutable identity instead of a disk's target-dev.
func nicMacInXML(xmlText, mac string) bool {
	if xmlText == "" || mac == "" {
		return false
	}
	lx := strings.ToLower(xmlText)
	lm := strings.ToLower(mac)
	return strings.Contains(lx, "address='"+lm+"'") || strings.Contains(lx, `address="`+lm+`"`)
}

// ── ATTACH ──────────────────────────────────────────────────────────────────

// attachNICEntry is the entry-node half, mirroring attachDiskEntry: enforces the
// operation_protocol_v1 prerequisite, mints/derives the operation identity, runs the
// same-entry response-replay idempotency layer, and either forwards to the owner or
// executes locally. Preserves the pre-conversion cross-host network-provisioning
// push (best-effort — the owner also double-checks locally in executeNICAttach).
func (s *Server) attachNICEntry(ctx context.Context, req *pb.AttachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	spec := req.Nic
	if spec.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "nic network name is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"nic attach requires the operation_protocol_v1 capability to be active")
	}

	// Owner leg of a peer forward: trust the entry node's op identity, skip the entry
	// idempotency layer, go straight to the at-most-once owner path.
	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.attachNICOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	// Cross-host race: push the network's provisioning to the VM's owning host
	// before this attach reaches it, so a forwarded attachNIC there doesn't find an
	// unprovisioned bridge (see provisionNetworkOnRemote).
	if vmRec.HostName != s.hostName {
		s.provisionNetworkOnRemote(ctx, vmRec.HostName, spec.Name)
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString() // keyless call: a per-attempt id (no cross-retry dedup)
	}
	opID := corrosion.DeterministicOperationID("AttachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := attachNICRequestHash(vmRec.Name, spec)

	// Layer 1: same-entry byte-exact replay (only when the CLIENT supplied a key).
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

	// Forward to the owning host.
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

	resp, retErr = s.attachNICOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// attachNICOwner runs on the VM's owning host under the VM lock — the at-most-once
// execution point, mirroring attachDiskOwner. BEFORE any side effect it reduces the
// replicated operation's state and reconstructs a prior outcome instead of
// re-running; only a pristine claim proceeds. NIC membership reads go through the
// vm_nics/vm_interfaces overlay (MergedVMNICs, §4.2) so the duplicate/mac checks see
// both tables' rows regardless of which one a given peer currently writes.
func (s *Server) attachNICOwner(ctx context.Context, req *pb.AttachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
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
			"stopped-VM NIC attach for %q is not available until hardware_v2 is active", vmName)
	}

	spec := req.Nic
	mac := spec.Mac
	if mac == "" {
		mac = lv.GenerateMAC()
	}
	model := spec.Model
	if model == "" {
		model = "virtio"
	}
	sgsJSON, sgErr := encodeNICSecurityGroups(spec.SecurityGroups)
	if sgErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "encode security groups: %v", sgErr)
	}

	// Membership read via the overlay (§4.2) — a read failure must FAIL the
	// operation before any mutation (fail-closed): swallowing it would let a
	// duplicate mac/network pass the check and miscount the ordinal.
	existing, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list NICs for %q: %v", vmName, err)
	}
	for _, n := range existing {
		if strings.EqualFold(n.MAC, mac) {
			return nil, status.Errorf(codes.AlreadyExists, "a NIC with MAC %q is already attached to VM %q", mac, vmName)
		}
	}
	if !latched {
		// The legacy vm_interfaces PK is (vm_name, network_name) — it cannot
		// represent a second NIC on the same network. Reject pre-latch; the v42
		// vm_nics PK is (vm_name, id) so this is safe once latched.
		for _, n := range existing {
			if n.NetworkName == spec.Name {
				return nil, status.Errorf(codes.AlreadyExists,
					"VM %q already has a NIC on network %q; multiple NICs per network require hardware_v2", vmName, spec.Name)
			}
		}
	}
	ordinal := len(existing)
	nicID := corrosion.DeterministicNICID(vmName, mac)

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
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different NIC attach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot attach a NIC to %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executeNICAttach(ctx, vm, spec, mac, model, nicID, sgsJSON, ordinal, opID, vm.OwnerEpoch, newGen, running, latched)
}

// nicAttachRollback carries the state needed to compensate a failed attach. Split
// into nicRowWritten/legacyRowWritten (rather than one rowWritten bool, as disk's
// single-table attachRollback uses) because the pre-latch dual-write can partially
// land — the authoritative vm_nics write can succeed while the legacy vm_interfaces
// write fails, and rollback must undo exactly what committed, nothing more.
type nicAttachRollback struct {
	vm               *corrosion.VMRecord
	opID             string
	epoch            int64
	newGen           int64
	mac              string
	nicID            string
	networkName      string
	running          bool
	dualWrite        bool // this execution also writes vm_interfaces (pre-latch)
	attached         bool // live AttachNIC succeeded
	nicRowWritten    bool // vm_nics UpsertNIC succeeded
	legacyRowWritten bool // vm_interfaces InsertInterface succeeded
}

// ensureNICNetworkProvisioned resolves networkName's bridge and, if the network has
// a local record not yet provisioned on THIS host, provisions it and reconciles the
// firewall — preserving the pre-conversion attachNIC's fail-closed behavior (§12):
// a successful provision whose isolation drop didn't apply must fail the attach
// rather than silently plug into a host-reachable bridge.
func (s *Server) ensureNICNetworkProvisioned(ctx context.Context, networkName string) (bridge string, err error) {
	bridge = resolveBridge(ctx, s.db, networkName)
	nr, _ := corrosion.GetNetwork(ctx, s.db, networkName)
	if nr == nil || nr.Config == "" {
		return bridge, nil
	}
	var def compose.NetworkDef
	if json.Unmarshal([]byte(nr.Config), &def) != nil {
		return bridge, nil
	}
	def.Type = nr.Type
	if def.Interface == "" {
		def.Interface = networkName
	}
	localIP := getLocalIP()
	if _, perr := network.SafeProvision(ctx, s.db, networkName, def, localIP, s.hostName); perr != nil {
		slog.Warn("nic attach: failed to provision network locally", "network", networkName, "error", perr)
		return bridge, nil
	}
	if ferr := s.reconcileFirewallRequired(ctx); ferr != nil {
		return bridge, fmt.Errorf("apply firewall after provisioning network %q: %w", networkName, ferr)
	}
	return bridge, nil
}

// writeNICAttachRows commits the vm_nics row and, pre-latch, the legacy
// vm_interfaces row — in that order, so a legacy-write failure after the
// authoritative write lands is forward progress the caller must compensate
// precisely (via rb.nicRowWritten/legacyRowWritten), never a coarse all-or-nothing
// commit that could leak one side.
func (s *Server) writeNICAttachRows(ctx context.Context, rb *nicAttachRollback, vmName string, spec *pb.NetworkAttachment, model, mac, nicID, sgsJSON string, ordinal int) error {
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
		VMName: vmName, ID: nicID, NetworkName: spec.Name, Model: model, MAC: mac,
		Ordinal: ordinal, IP: spec.Ip, SecurityGroups: sgsJSON,
	}); err != nil {
		return fmt.Errorf("record nic row: %w", err)
	}
	rb.nicRowWritten = true
	if rb.dualWrite {
		if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
			VMName: vmName, NetworkName: spec.Name, Ordinal: ordinal, MAC: mac, IP: spec.Ip,
		}); err != nil {
			return fmt.Errorf("record legacy interface row: %w", err)
		}
		rb.legacyRowWritten = true
	}
	return nil
}

// executeNICAttach realizes the attach DAG under the lock: ensure the network is
// provisioned → journal the plan → (running) live attach then commit rows, or
// (stopped) commit rows then reconcile the inactive definition → verify
// both-state membership → CompleteVMOperation. Any failure routes to
// failNICAttach, which rolls back directionally.
func (s *Server) executeNICAttach(ctx context.Context, vm *corrosion.VMRecord, spec *pb.NetworkAttachment, mac, model, nicID, sgsJSON string, ordinal int, opID string, epoch, newGen int64, running, latched bool) (*pb.VM, error) {
	rb := &nicAttachRollback{vm: vm, opID: opID, epoch: epoch, newGen: newGen, mac: mac, nicID: nicID,
		networkName: spec.Name, running: running, dualWrite: !latched}

	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepReserved)

	bridge, perr := s.ensureNICNetworkProvisioned(ctx, spec.Name)
	if perr != nil {
		return s.failNICAttach(ctx, rb, codes.Internal, perr)
	}

	// Journal the plan BEFORE the irreversible live attach so a crash recovers.
	priorActive, _ := s.virt.DumpXML(vm.Name)
	priorInactive, _ := s.virt.DumpXMLInactive(vm.Name)
	if s.opJournal != nil {
		entry := opjournal.Entry{
			OperationID:    opID,
			OwnerEpoch:     epoch,
			SpecGeneration: newGen,
			ResourceID:     vm.Name,
			Kind:           "device_attach",
			Stage:          "planned",
			Artifacts: map[string]string{
				"mac":                    mac,
				"network_name":           spec.Name,
				"model":                  model,
				"prior_active_xml":       priorActive,
				"prior_inactive_xml":     priorInactive,
				"member_active_before":   strconv.FormatBool(nicMacInXML(priorActive, mac)),
				"member_inactive_before": strconv.FormatBool(nicMacInXML(priorInactive, mac)),
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			// Fail closed: without the durable plan we must not perform the
			// irreversible attach. No side effect yet → clean terminal failure.
			return s.failNICAttach(ctx, rb, codes.Unavailable, fmt.Errorf("journal attach plan: %w", err))
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepClaimed)

	if running {
		if err := s.virt.AttachNIC(vm.Name, bridge, model, mac); err != nil {
			return s.failNICAttach(ctx, rb, codes.Internal, fmt.Errorf("attach NIC: %w", err))
		}
		rb.attached = true
		if err := s.writeNICAttachRows(ctx, rb, vm.Name, spec, model, mac, nicID, sgsJSON, ordinal); err != nil {
			return s.failNICAttach(ctx, rb, codes.Internal, err)
		}
	} else {
		if err := s.writeNICAttachRows(ctx, rb, vm.Name, spec, model, mac, nicID, sgsJSON, ordinal); err != nil {
			return s.failNICAttach(ctx, rb, codes.Internal, err)
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			return s.failNICAttach(ctx, rb, codes.Internal, fmt.Errorf("reconcile definition: %w", err))
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepBound)

	// Verify terminal membership before completing (§8): on the running path the NIC
	// must be present in BOTH the live domain AND the persistent (inactive)
	// definition, because AttachNIC applies live+config.
	divergence, verr := s.verifyNICAttached(vm.Name, mac, running)
	if verr != nil {
		if running && divergence {
			return s.failNICAttach(ctx, rb, codes.Internal, fmt.Errorf("verify attach membership: %w", verr))
		}
		slog.Error("nic attach: membership unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", verr)
		return nil, status.Errorf(codes.Internal, "nic attach for %q could not be verified; left recoverable: %v", vm.Name, verr)
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceAttach, corrosion.OpStepAttached)

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		// The device is fully attached, but the barrier could not be cleared — the CAS
		// precondition no longer holds (ownership/generation moved underneath the op) or
		// the write failed. Do NOT remove the journal or report success; leave the
		// operation recovery-required.
		slog.Error("nic attach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "nic attach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("nic attach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("nic attached", "vm", vm.Name, "network", spec.Name, "mac", mac)
	s.recordVMEvent(ctx, vm.Name, "device.attached", "ok", "nic "+mac)
	s.publish("device.attached", vm.Name, "nic:"+mac)
	return s.vmToProto(ctx, vm.Name)
}

// failNICAttach compensates a failed attach by rolling BACK (§8): inverse
// live-detach the just-attached NIC, tombstone/soft-delete exactly the rows THIS
// execution wrote (nicRowWritten/legacyRowWritten — never more), and restore the
// prior inactive definition on the stopped path. If the rollback fully completes it
// records a terminal failure + clears the barrier; otherwise the operation is left
// NON-TERMINAL for recovery — never force-completed.
func (s *Server) failNICAttach(ctx context.Context, rb *nicAttachRollback, code codes.Code, cause error) (*pb.VM, error) {
	rolledBack := true

	if rb.attached {
		if err := s.virt.DetachNIC(rb.vm.Name, rb.mac); err != nil {
			slog.Error("nic attach rollback: inverse-detach failed", "vm", rb.vm.Name, "mac", rb.mac, "error", err)
			rolledBack = false
		}
	}
	if rb.nicRowWritten {
		if err := corrosion.TombstoneNIC(ctx, s.db, rb.vm.Name, rb.nicID); err != nil {
			slog.Error("nic attach rollback: tombstone nic row failed", "vm", rb.vm.Name, "mac", rb.mac, "error", err)
			rolledBack = false
		}
	}
	if rb.legacyRowWritten {
		if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, rb.vm.Name, rb.mac); err != nil {
			slog.Error("nic attach rollback: soft-delete legacy interface row failed", "vm", rb.vm.Name, "mac", rb.mac, "error", err)
			rolledBack = false
		}
	}
	if (rb.nicRowWritten || rb.legacyRowWritten) && !rb.running {
		// Restore the prior inactive definition: re-reconcile now that the rows are
		// gone drops the NIC we added from the definition.
		if err := s.reconcileDomainDefinition(ctx, rb.vm, nil); err != nil {
			slog.Error("nic attach rollback: re-reconcile to drop nic failed", "vm", rb.vm.Name, "error", err)
			rolledBack = false
		}
	}

	if !rolledBack {
		slog.Error("nic attach: rollback incomplete — operation left recoverable", "vm", rb.vm.Name, "op", rb.opID, "cause", cause)
		return nil, status.Errorf(code, "nic attach for %q failed and rollback is incomplete; left recoverable: %v", rb.vm.Name, cause)
	}

	s.appendOpStep(ctx, rb.opID, rb.epoch, corrosion.OpDeviceAttach, corrosion.OpStepRollbackCompleted)
	applied, ferr := s.db.FailVMOperation(ctx, rb.vm.Name, rb.opID, rb.epoch, rb.newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("nic attach: recording terminal failure failed — recovery will reconcile", "vm", rb.vm.Name, "op", rb.opID, "error", ferr)
	case !applied:
		slog.Error("nic attach: terminal-failure CAS did not apply — left recoverable", "vm", rb.vm.Name, "op", rb.opID)
	default:
		if s.opJournal != nil {
			_ = s.opJournal.Remove(rb.opID)
		}
	}
	s.recordVMEvent(ctx, rb.vm.Name, "device.attached", "error", "nic "+rb.mac)
	return nil, status.Error(code, cause.Error())
}

// verifyNICAttached asserts the NIC landed in the authoritative definition(s) after
// an attach, mirroring verifyDiskAttached. There is no DomainNICSources-style
// structured live accessor (unlike disks' DomainDiskSources), so the live check
// uses DumpXML directly — in production this genuinely differs from DumpXMLInactive
// for a running domain (real libvirt: DomainGetXMLDesc live vs DomainXMLInactive),
// so this is not a simplification, just NIC's natural live-membership signal.
func (s *Server) verifyNICAttached(vmName, mac string, running bool) (divergence bool, err error) {
	if running {
		live, rerr := s.virt.DumpXML(vmName)
		if rerr != nil {
			return false, fmt.Errorf("read live domain: %w", rerr)
		}
		if !nicMacInXML(live, mac) {
			return true, fmt.Errorf("nic %s absent from the live domain after attach", mac)
		}
		xml, rerr := s.virt.DumpXMLInactive(vmName)
		if rerr != nil {
			return false, fmt.Errorf("read inactive definition: %w", rerr)
		}
		if !nicMacInXML(xml, mac) {
			return true, fmt.Errorf("nic %s absent from the persistent definition after attach", mac)
		}
		return false, nil
	}
	xml, rerr := s.virt.DumpXMLInactive(vmName)
	if rerr != nil {
		return false, fmt.Errorf("read inactive definition: %w", rerr)
	}
	if !nicMacInXML(xml, mac) {
		return true, fmt.Errorf("nic %s absent from the inactive definition after reconcile", mac)
	}
	return false, nil
}

// ── DETACH ──────────────────────────────────────────────────────────────────

// detachNICEntry mirrors attachNICEntry for the detach path.
func (s *Server) detachNICEntry(ctx context.Context, req *pb.DetachDeviceRequest, vmRec *corrosion.VMRecord) (resp *pb.VM, retErr error) {
	if req.NicMac == "" {
		return nil, status.Error(codes.InvalidArgument, "nic_mac is required")
	}
	if !s.operationProtocolActive(ctx) {
		return nil, status.Error(codes.FailedPrecondition,
			"nic detach requires the operation_protocol_v1 capability to be active")
	}

	if opID, reqHash, ok := s.deviceOpFromPeer(ctx); ok {
		return s.detachNICOwner(ctx, req, vmRec.Name, opID, reqHash, "")
	}

	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		idemKey = uuid.NewString()
	}
	opID := corrosion.DeterministicOperationID("DetachDevice", principal, vmRec.Project, vmRec.Name, idemKey)
	reqHash := detachNICRequestHash(vmRec.Name, req.NicMac)

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

	resp, retErr = s.detachNICOwner(ctx, req, vmRec.Name, opID, reqHash, idemKey)
	return resp, retErr
}

// detachNICOwner is the at-most-once owner path for a NIC detach.
func (s *Server) detachNICOwner(ctx context.Context, req *pb.DetachDeviceRequest, vmName, opID, reqHash, idemKey string) (*pb.VM, error) {
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
			"stopped-VM NIC detach for %q is not available until hardware_v2 is active", vmName)
	}

	// A read failure must FAIL the operation before any mutation (fail-closed).
	existing, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list NICs for %q: %v", vmName, err)
	}
	found := false
	for _, n := range existing {
		if strings.EqualFold(n.MAC, req.NicMac) {
			found = true
			break
		}
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "NIC with MAC %q not found on VM %q", req.NicMac, vmName)
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
	applied, err := s.db.BeginVMOperation(ctx, op, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		if errors.Is(err, corrosion.ErrOperationHashConflict) {
			return nil, status.Errorf(codes.InvalidArgument, "idempotency key reused with a different NIC detach for %q", vmName)
		}
		return nil, status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot detach a NIC from %q: an operation is in progress", vmName)
	}
	newGen := vm.SpecGeneration + 1
	return s.executeNICDetach(ctx, vm, req.NicMac, opID, vm.OwnerEpoch, newGen, running, latched)
}

// executeNICDetach realizes the detach DAG under the lock: journal the plan →
// (running) live detach then tombstone rows, or (stopped) tombstone rows then
// reconcile → verify absence → CompleteVMOperation. Row writes are ordered
// vm_nics-first (authoritative), then the pre-latch legacy dual-write — so a
// legacy-write failure after the authoritative tombstone lands is forward progress
// (left recoverable), never reported as a clean no-op failure.
func (s *Server) executeNICDetach(ctx context.Context, vm *corrosion.VMRecord, mac, opID string, epoch, newGen int64, running, latched bool) (*pb.VM, error) {
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepReserved)

	nicID := corrosion.DeterministicNICID(vm.Name, mac)
	dualWrite := !latched

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
				"mac":                    mac,
				"nic_id":                 nicID,
				"prior_active_xml":       priorActive,
				"prior_inactive_xml":     priorInactive,
				"member_active_before":   strconv.FormatBool(nicMacInXML(priorActive, mac)),
				"member_inactive_before": strconv.FormatBool(nicMacInXML(priorInactive, mac)),
			},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.opJournal.Write(entry); err != nil {
			// No side effect yet → clean terminal failure (nothing to roll back).
			return s.failNICDetachClean(ctx, vm, opID, epoch, newGen, mac,
				codes.Unavailable, fmt.Errorf("journal detach plan: %w", err))
		}
	}

	if running {
		if err := s.virt.DetachNIC(vm.Name, mac); err != nil {
			// The irreversible step failed and nothing changed → clean terminal fail.
			return s.failNICDetachClean(ctx, vm, opID, epoch, newGen, mac,
				codes.Internal, fmt.Errorf("detach nic: %w", err))
		}
		if !s.retryNICRowTombstone(ctx, vm.Name, mac, nicID, dualWrite) {
			// Live-detached but the row bookkeeping would not commit → roll FORWARD:
			// leave NON-TERMINAL for recovery, never re-attach.
			slog.Error("nic detach: row tombstone failed after live detach — left recoverable", "vm", vm.Name, "op", opID)
			return nil, status.Errorf(codes.Internal, "nic detach for %q applied but bookkeeping incomplete; left recoverable", vm.Name)
		}
	} else {
		if err := corrosion.TombstoneNIC(ctx, s.db, vm.Name, nicID); err != nil {
			// Nothing applied to the domain yet → clean terminal fail.
			return s.failNICDetachClean(ctx, vm, opID, epoch, newGen, mac,
				codes.Internal, fmt.Errorf("tombstone nic row: %w", err))
		}
		if dualWrite {
			if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, vm.Name, mac); err != nil {
				// The authoritative row is already gone (forward progress via the
				// overlay) → roll FORWARD: leave NON-TERMINAL, never re-attach.
				slog.Error("nic detach: legacy interface soft-delete failed after nic tombstone — left recoverable", "vm", vm.Name, "op", opID, "error", err)
				return nil, status.Errorf(codes.Internal, "nic detach for %q applied but legacy bookkeeping incomplete; left recoverable: %v", vm.Name, err)
			}
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			slog.Error("nic detach: reconcile after row tombstone failed — left recoverable", "vm", vm.Name, "op", opID, "error", err)
			return nil, status.Errorf(codes.Internal, "nic detach for %q applied but definition not reconciled; left recoverable: %v", vm.Name, err)
		}
	}
	s.appendOpStep(ctx, opID, epoch, corrosion.OpDeviceDetach, corrosion.OpStepAttached)

	if err := s.verifyNICDetached(vm.Name, mac, running); err != nil {
		slog.Error("nic detach: absence unverifiable — left recoverable", "vm", vm.Name, "op", opID, "error", err)
		return nil, status.Errorf(codes.Internal, "nic detach for %q could not be verified; left recoverable: %v", vm.Name, err)
	}

	applied, cerr := s.db.CompleteVMOperation(ctx, vm.Name, opID, epoch, newGen)
	if cerr != nil || !applied {
		slog.Error("nic detach: completion could not be committed — left recoverable", "vm", vm.Name, "op", opID, "applied", applied, "error", cerr)
		return nil, status.Errorf(codes.Internal, "nic detach for %q completed but could not be committed; left recoverable: %v", vm.Name, cerr)
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(opID); err != nil {
			slog.Warn("nic detach: clear journal entry", "vm", vm.Name, "op", opID, "error", err)
		}
	}
	slog.Info("nic detached", "vm", vm.Name, "mac", mac)
	s.recordVMEvent(ctx, vm.Name, "device.detached", "ok", "nic "+mac)
	s.publish("device.detached", vm.Name, "nic:"+mac)
	return s.vmToProto(ctx, vm.Name)
}

// retryNICRowTombstone retries the row bookkeeping a bounded number of times (the
// forward-compensation retry after a successful live detach) — vm_nics first
// (authoritative), then the legacy dual-write when still pre-latch. Both statements
// are idempotent UPDATEs, so re-running an already-applied one is harmless.
func (s *Server) retryNICRowTombstone(ctx context.Context, vmName, mac, nicID string, dualWrite bool) bool {
	for attempt := 0; attempt < resizeApplyAttempts; attempt++ {
		if err := corrosion.TombstoneNIC(ctx, s.db, vmName, nicID); err != nil {
			continue
		}
		if dualWrite {
			if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, vmName, mac); err != nil {
				continue
			}
		}
		return true
	}
	return false
}

// failNICDetachClean records a terminal detach failure + clears the barrier when
// NOTHING was applied to the domain (the live/config detach never ran and no row
// was tombstoned), so the VM is unchanged and mutable again.
func (s *Server) failNICDetachClean(ctx context.Context, vm *corrosion.VMRecord, opID string, epoch, newGen int64, mac string, code codes.Code, cause error) (*pb.VM, error) {
	applied, ferr := s.db.FailVMOperation(ctx, vm.Name, opID, epoch, newGen, deviceFailureFacts(code, cause))
	switch {
	case ferr != nil:
		slog.Error("nic detach: recording terminal failure failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", ferr)
	case !applied:
		slog.Error("nic detach: terminal-failure CAS did not apply — left recoverable", "vm", vm.Name, "op", opID)
	default:
		if s.opJournal != nil {
			_ = s.opJournal.Remove(opID)
		}
	}
	s.recordVMEvent(ctx, vm.Name, "device.detached", "error", "nic "+mac)
	return nil, status.Error(code, cause.Error())
}

// verifyNICDetached asserts the NIC is GONE from the authoritative definition(s),
// mirroring verifyDiskDetached.
func (s *Server) verifyNICDetached(vmName, mac string, running bool) error {
	if running {
		live, err := s.virt.DumpXML(vmName)
		if err != nil {
			return fmt.Errorf("read live domain: %w", err)
		}
		if nicMacInXML(live, mac) {
			return fmt.Errorf("nic %s still present in the live domain after detach", mac)
		}
		xml, err := s.virt.DumpXMLInactive(vmName)
		if err != nil {
			return fmt.Errorf("read inactive definition: %w", err)
		}
		if nicMacInXML(xml, mac) {
			return fmt.Errorf("nic %s still present in the persistent definition after detach", mac)
		}
		return nil
	}
	xml, err := s.virt.DumpXMLInactive(vmName)
	if err != nil {
		return fmt.Errorf("read inactive definition: %w", err)
	}
	if nicMacInXML(xml, mac) {
		return fmt.Errorf("nic %s still present in the inactive definition after reconcile", mac)
	}
	return nil
}
