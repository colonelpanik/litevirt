package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// hardwareRecoveryInterval is the reconciler cadence for resuming device
// attach/detach operations that crashed with the mutation barrier held and the
// operation NON-TERMINAL. It matches the resource-update recovery cadence.
const hardwareRecoveryInterval = 60 * time.Second

// RecoverHardwareOperations resumes locally-owned VMs whose mutation barrier
// points at a NONTERMINAL device_attach / device_detach operation — a hot-plug
// that crashed after claiming the barrier but before reaching a clean terminal.
// It converges each such VM to a single consistent state (device fully present +
// completed, or fully rolled back) so a partial failure never wedges
// active_operation_id. It takes the VM lock per VM (serializing with any in-flight
// device op) and re-checks terminality under it, so it never races a live handler.
// Safe at startup and on a reconciler tick, and IDEMPOTENT: a converged/terminal
// op is a no-op. Resize/device-lease operations are recovered by their own paths.
func (s *Server) RecoverHardwareOperations(ctx context.Context) {
	if s.opJournal == nil {
		return // no host-local artifacts → nothing to re-drive
	}
	vms, err := corrosion.ListVMsWithActiveOperation(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("hardware op recovery: list wedged VMs failed", "error", err)
		return
	}
	for i := range vms {
		s.recoverOneHardwareOperation(ctx, vms[i].Name)
	}
}

// RunHardwareOperationRecovery periodically resumes wedged device operations so a
// partial failure converges without operator action (mirrors
// RunResourceOperationRecovery).
func (s *Server) RunHardwareOperationRecovery(ctx context.Context) {
	t := time.NewTicker(hardwareRecoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RecoverHardwareOperations(ctx)
		}
	}
}

// recoverOneHardwareOperation re-drives ONE VM's wedged device operation under the
// VM lock. It re-reads state under the lock (so a converged/terminal op is a no-op),
// filters to device_attach/device_detach, loads the host-local journal artifacts,
// and dispatches to the directional re-drive: attach → back, detach → forward.
func (s *Server) recoverOneHardwareOperation(ctx context.Context, name string) {
	unlock := s.lockVM(name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil || vm.HostName != s.hostName || vm.ActiveOperationID == "" {
		return
	}
	view, ok, err := corrosion.GetVMActiveOperation(ctx, s.db, name)
	if err != nil || !ok || view.Operation == nil {
		return
	}
	kind := corrosion.OperationKind(view.Operation.OperationKind)
	if kind != corrosion.OpDeviceAttach && kind != corrosion.OpDeviceDetach {
		return // resize / device-lease / restart are recovered by their own paths
	}
	if corrosion.IsOperationTerminal(view.State) {
		return // already converged (idempotent no-op)
	}
	if view.Faulted {
		slog.Error("hardware op recovery: operation has conflicting terminal states — manual recovery required",
			"vm", name, "op", view.ActiveOperationID)
		return
	}

	entry, found, err := s.opJournal.Read(view.ActiveOperationID)
	if err != nil {
		// Corrupt entry (ErrCorrupt) or read error → cannot safely re-drive; leave
		// recovery-required (host degraded for this mutation).
		slog.Error("hardware op recovery: journal read failed — left recoverable",
			"vm", name, "op", view.ActiveOperationID, "error", err)
		return
	}
	if !found {
		// No host-local artifacts (the durable plan is written BEFORE any irreversible
		// side effect, so a non-terminal op should have one). Without it we cannot
		// reconstruct target-dev / mac / created-file; leave recovery-required.
		slog.Warn("hardware op recovery: no journal entry for a wedged device op — left recoverable",
			"vm", name, "op", view.ActiveOperationID)
		return
	}
	// F1 takeover contract: the original owner rolls back external artifacts ONLY
	// while it is still the authorized owner at the entry's epoch. If ownership moved
	// on (a newer epoch), do NO external mutation here (RecoverDeviceLeases + the
	// resource coordinator handle a superseded owner's artifacts).
	if entry.OwnerEpoch != view.OwnerEpoch {
		slog.Warn("hardware op recovery: journal entry owner epoch superseded — skipping external re-drive",
			"vm", name, "op", view.ActiveOperationID, "entry_epoch", entry.OwnerEpoch, "current_epoch", view.OwnerEpoch)
		return
	}

	target := deviceOpTargetKind(entry.Artifacts)
	if target == "" {
		slog.Error("hardware op recovery: journal entry has no recognizable device artifacts — left recoverable",
			"vm", name, "op", view.ActiveOperationID)
		return
	}

	if kind == corrosion.OpDeviceAttach {
		s.recoverDeviceAttach(ctx, vm, view, entry, target)
		return
	}
	s.recoverDeviceDetach(ctx, vm, view, entry, target)
}

// deviceOpTargetKind classifies a device-op journal entry by its artifacts:
// concrete-address PCI carries pci_address; a NIC carries mac; a disk carries
// disk_name. (These are disjoint across the disk/NIC/PCI writers.)
func deviceOpTargetKind(art map[string]string) string {
	switch {
	case art["pci_address"] != "":
		return "pci"
	case art["mac"] != "":
		return "nic"
	case art["disk_name"] != "":
		return "disk"
	default:
		return ""
	}
}

// completeRecoveredOp finishes a device operation whose side effects are fully in
// place: it records the terminal happy-path 'attached' step (idempotent),
// CompleteVMOperation-clears the barrier, and clears the host-local journal entry.
// Caller holds the VM lock.
func (s *Server) completeRecoveredOp(ctx context.Context, vmName string, view *corrosion.VMOperationView, kind corrosion.OperationKind) {
	s.appendOpStep(ctx, view.ActiveOperationID, view.OwnerEpoch, kind, corrosion.OpStepAttached)
	if _, err := s.db.CompleteVMOperation(ctx, vmName, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration); err != nil {
		slog.Error("hardware op recovery: completing operation failed — will retry", "vm", vmName, "op", view.ActiveOperationID, "error", err)
		return
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(view.ActiveOperationID); err != nil {
			slog.Warn("hardware op recovery: clear journal entry", "vm", vmName, "op", view.ActiveOperationID, "error", err)
		}
	}
	slog.Info("hardware op recovery: converged", "vm", vmName, "op", view.ActiveOperationID, "kind", kind)
}

// ── ATTACH recovery (roll BACK; or COMPLETE when fully applied) ───────────────

// recoverDeviceAttach converges a wedged attach. Per §7.2 the DEFAULT is to roll
// BACK; the exception is an attach that recorded the terminal happy-path step
// (OpStepAttached, i.e. it verified membership) and only missed CompleteVMOperation
// — that is re-verified and COMPLETED. Compensation reuses the 5.2 failXAttach
// helpers with the rollback flags reconstructed from CURRENT observed state (so the
// undo is precise and idempotent).
func (s *Server) recoverDeviceAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry, target string) {
	switch target {
	case "disk":
		s.recoverDiskAttach(ctx, vm, view, entry)
	case "nic":
		s.recoverNICAttach(ctx, vm, view, entry)
	case "pci":
		s.recoverPCIAttach(ctx, vm, view, entry)
	}
}

func (s *Server) recoverDiskAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	art := entry.Artifacts
	targetDev := art["target_dev"]

	if view.State == corrosion.OpStepAttached {
		divergence, verr := s.verifyDiskAttached(vm.Name, targetDev, running)
		if verr == nil {
			s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceAttach)
			return
		}
		if !divergence {
			slog.Warn("hardware op recovery: disk attach membership unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", verr)
			return
		}
		// divergence → fall through to rollback
	}

	rb := attachRollback{
		vm: vm, opID: view.ActiveOperationID, epoch: view.OwnerEpoch, newGen: view.SpecGeneration,
		diskName: art["disk_name"], diskPath: art["file_created_by_operation"],
		targetDev: targetDev, running: running, journaled: true,
	}
	if running {
		if srcs, e := s.virt.DomainDiskSources(vm.Name); e == nil {
			_, rb.attached = srcs[targetDev]
		}
	}
	if disks, e := corrosion.ListDisks(ctx, s.db, vm.Name); e == nil {
		for _, d := range disks {
			if d.DiskName == rb.diskName {
				rb.rowWritten = true
				break
			}
		}
	}
	if rb.diskPath != "" {
		if _, e := os.Stat(rb.diskPath); e == nil {
			rb.fileCreated = true // exclusive-create guarantees a present file at this path is op-owned
		}
	}
	// failDeviceAttach rolls back directionally and, ONLY if the rollback completes,
	// records the terminal failure + clears the barrier; otherwise it leaves the op
	// NON-TERMINAL. Its returned error is the operation's reported failure (expected),
	// not a recovery fault — the resulting barrier state is the source of truth.
	_, _ = s.failDeviceAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

func (s *Server) recoverNICAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	latched := s.hardwareV2Latched(ctx)
	art := entry.Artifacts
	mac := art["mac"]

	if view.State == corrosion.OpStepAttached {
		divergence, verr := s.verifyNICAttached(vm.Name, mac, running)
		if verr == nil {
			s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceAttach)
			return
		}
		if !divergence {
			slog.Warn("hardware op recovery: nic attach membership unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", verr)
			return
		}
	}

	rb := &nicAttachRollback{
		vm: vm, opID: view.ActiveOperationID, epoch: view.OwnerEpoch, newGen: view.SpecGeneration,
		mac: mac, nicID: corrosion.DeterministicNICID(vm.Name, mac), networkName: art["network_name"],
		running: running, dualWrite: !latched,
	}
	if running {
		if live, e := s.virt.DumpXML(vm.Name); e == nil {
			rb.attached = nicMacInXML(live, mac)
		}
	}
	if nics, e := corrosion.MergedVMNICs(ctx, s.db, vm.Name); e == nil {
		present := false
		for _, n := range nics {
			if strings.EqualFold(n.MAC, mac) {
				present = true
				break
			}
		}
		rb.nicRowWritten = present
		rb.legacyRowWritten = present && !latched
	}
	_, _ = s.failNICAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

func (s *Server) recoverPCIAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	latched := s.hardwareV2Latched(ctx)
	art := entry.Artifacts
	deviceID := art["device_id"]
	normAddr := strings.ToLower(art["pci_address"])

	// Realized members (concrete host devices this attach bound) + intent presence.
	var members []ResolvedMember
	realizationsWritten := false
	if reals, e := corrosion.ListVMPCIRealizations(ctx, s.db, vm.Name); e == nil {
		for _, r := range reals {
			if r.DeviceID != deviceID {
				continue
			}
			members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: r.MemberID, Address: r.ResolvedAddress, Ordinal: r.Ordinal})
			realizationsWritten = true
		}
	}

	if view.State == corrosion.OpStepAttached {
		divergence, verr := s.verifyPCIAttached(vm.Name, deviceID, members, running)
		if verr == nil {
			s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceAttach)
			return
		}
		if !divergence {
			slog.Warn("hardware op recovery: pci attach membership unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", verr)
			return
		}
	}

	rb := &pciAttachRollback{
		vm: vm, opID: view.ActiveOperationID, epoch: view.OwnerEpoch, newGen: view.SpecGeneration,
		deviceID: deviceID, pciAddress: normAddr, members: members, origSpec: vm.Spec,
		running: running, dualWrite: !latched, realizationsWritten: realizationsWritten,
	}
	if intents, e := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name); e == nil {
		for _, in := range intents {
			if in.DeviceID == deviceID {
				rb.intentWritten = true
				break
			}
		}
	}
	if running {
		if live, e := s.virt.DumpXML(vm.Name); e == nil {
			for _, m := range members {
				if hostdevAliasInXML(live, pciMemberAlias(deviceID, m.MemberID)) {
					rb.attachedAddrs = append(rb.attachedAddrs, m.Address)
				}
			}
		}
		rb.acquired = realizationsWritten || len(rb.attachedAddrs) > 0
	}
	if rb.dualWrite {
		if os2, e := removePCIDeviceFromSpec(vm.Spec, normAddr); e == nil {
			rb.origSpec = os2 // restore the spec with the pre-latch dual-write device removed
		}
	}
	_, _ = s.failPCIAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

// ── DETACH recovery (roll FORWARD to completion; never re-attach) ─────────────

// recoverDeviceDetach finishes a wedged detach forward: it ensures the device is
// absent from the live domain AND the persistent definition, retries the row
// bookkeeping to completion, verifies absence, and completes. If any step cannot
// complete the op is left NON-TERMINAL for a later retry — it is NEVER re-attached.
func (s *Server) recoverDeviceDetach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry, target string) {
	switch target {
	case "disk":
		s.recoverDiskDetach(ctx, vm, view, entry)
	case "nic":
		s.recoverNICDetach(ctx, vm, view, entry)
	case "pci":
		s.recoverPCIDetach(ctx, vm, view, entry)
	}
}

func (s *Server) recoverDiskDetach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	art := entry.Artifacts
	targetDev := art["target_dev"]
	diskName := art["disk_name"]

	if running {
		if srcs, e := s.virt.DomainDiskSources(vm.Name); e == nil {
			if _, present := srcs[targetDev]; present {
				if e := s.virt.DetachDisk(vm.Name, targetDev); e != nil {
					slog.Error("hardware op recovery: disk detach live-detach failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", e)
					return
				}
			}
		}
		if !s.retrySoftDeleteDisk(ctx, vm.Name, diskName) {
			slog.Error("hardware op recovery: disk detach row soft-delete failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID)
			return
		}
	} else {
		if err := corrosion.SoftDeleteDisk(ctx, s.db, vm.Name, diskName); err != nil {
			slog.Error("hardware op recovery: disk detach row soft-delete failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			slog.Error("hardware op recovery: disk detach reconcile failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
	}
	if err := s.verifyDiskDetached(vm.Name, targetDev, running); err != nil {
		slog.Error("hardware op recovery: disk detach absence unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
		return
	}
	s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceDetach)
}

func (s *Server) recoverNICDetach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	latched := s.hardwareV2Latched(ctx)
	art := entry.Artifacts
	mac := art["mac"]
	nicID := art["nic_id"]
	if nicID == "" {
		nicID = corrosion.DeterministicNICID(vm.Name, mac)
	}
	dualWrite := !latched

	if running {
		if live, e := s.virt.DumpXML(vm.Name); e == nil && nicMacInXML(live, mac) {
			if e := s.virt.DetachNIC(vm.Name, mac); e != nil {
				slog.Error("hardware op recovery: nic detach live-detach failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", e)
				return
			}
		}
		if !s.retryNICRowTombstone(ctx, vm.Name, mac, nicID, dualWrite) {
			slog.Error("hardware op recovery: nic detach row tombstone failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID)
			return
		}
	} else {
		if err := corrosion.TombstoneNIC(ctx, s.db, vm.Name, nicID); err != nil {
			slog.Error("hardware op recovery: nic detach tombstone failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
		if dualWrite {
			if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, vm.Name, mac); err != nil {
				slog.Error("hardware op recovery: nic detach legacy soft-delete failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
				return
			}
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			slog.Error("hardware op recovery: nic detach reconcile failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
	}
	if err := s.verifyNICDetached(vm.Name, mac, running); err != nil {
		slog.Error("hardware op recovery: nic detach absence unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
		return
	}
	s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceDetach)
}

func (s *Server) recoverPCIDetach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	running := vm.State == "running"
	art := entry.Artifacts
	deviceID := art["device_id"]

	var memberAddrs, memberAliases []string
	if reals, e := corrosion.ListVMPCIRealizations(ctx, s.db, vm.Name); e == nil {
		for _, r := range reals {
			if r.DeviceID != deviceID {
				continue
			}
			memberAddrs = append(memberAddrs, r.ResolvedAddress)
			memberAliases = append(memberAliases, r.XMLAlias)
		}
	}

	if running {
		if live, e := s.virt.DumpXML(vm.Name); e == nil {
			for i, addr := range memberAddrs {
				if hostdevAliasInXML(live, memberAliases[i]) {
					if e := s.virt.DetachHostdev(vm.Name, addr); e != nil {
						slog.Error("hardware op recovery: pci detach live-detach failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", e)
						return
					}
				}
			}
		}
		s.releaseDeviceLeases(ctx, vm.Name, memberAddrs)
		if !s.retryPCIRowTombstone(ctx, vm.Name, deviceID) {
			slog.Error("hardware op recovery: pci detach row tombstone failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID)
			return
		}
	} else {
		if err := corrosion.TombstonePCIRealizations(ctx, s.db, vm.Name, deviceID); err != nil {
			slog.Error("hardware op recovery: pci detach tombstone realizations failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
		if err := corrosion.TombstonePCIIntent(ctx, s.db, vm.Name, deviceID); err != nil {
			slog.Error("hardware op recovery: pci detach tombstone intent failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
		if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
			slog.Error("hardware op recovery: pci detach reconcile failed — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
			return
		}
	}
	if err := s.verifyPCIDetached(vm.Name, memberAliases, running); err != nil {
		slog.Error("hardware op recovery: pci detach absence unverifiable — left recoverable", "vm", vm.Name, "op", view.ActiveOperationID, "error", err)
		return
	}
	s.completeRecoveredOp(ctx, vm.Name, view, corrosion.OpDeviceDetach)
}

// errRecoveredIncompleteAttach is the stable cause recorded on the terminal
// 'failed' step when crash recovery rolls back an attach that never reached a
// clean terminal.
var errRecoveredIncompleteAttach = fmt.Errorf("device attach did not complete before a crash; rolled back by recovery")
