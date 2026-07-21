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
	applied, err := s.db.CompleteVMOperation(ctx, vmName, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration)
	if err != nil {
		slog.Error("hardware op recovery: completing operation failed — will retry", "vm", vmName, "op", view.ActiveOperationID, "error", err)
		return
	}
	if !applied {
		// The CAS precondition no longer holds (ownership/generation moved underneath
		// the wedged op) — do NOT remove the journal; leave it recovery-required for a
		// later pass (or the new owner's own recovery).
		slog.Warn("hardware op recovery: completion CAS did not apply — left recoverable", "vm", vmName, "op", view.ActiveOperationID)
		return
	}
	if s.opJournal != nil {
		if err := s.opJournal.Remove(view.ActiveOperationID); err != nil {
			slog.Warn("hardware op recovery: clear journal entry", "vm", vmName, "op", view.ActiveOperationID, "error", err)
		}
	}
	slog.Info("hardware op recovery: converged", "vm", vmName, "op", view.ActiveOperationID, "kind", kind)
}

// recoveryDisp is the 3-way classification of a wedged VM's LIVE libvirt domain
// that crash recovery keys its compensation on.
type recoveryDisp int

const (
	// dispDefer: state indeterminate OR active-but-not-running (paused /
	// pm-suspended / crashed / stopping / unknown). Perform NO compensation this
	// pass; leave the op recovery-required and retry once the state is definite.
	dispDefer recoveryDisp = iota
	// dispRunning: the domain is live → drive the running compensation path.
	dispRunning
	// dispShutoff: the domain is POSITIVELY shut off → the stopped compensation
	// path (delete op-owned backing files, tombstone desired-state rows) is safe.
	dispShutoff
)

// recoveryDomainDisposition classifies the VM's LIVE libvirt domain for crash
// recovery. It deliberately consults the LIVE domain, NOT the replicated vm.State:
// after a HOST REBOOT (the primary recovery trigger) a VM that was "running"
// pre-crash still reads vm.State=="running" while its domain is shut off, and
// driving the running rollback there would issue a LIVE-flagged libvirt call (e.g.
// DetachDisk LIVE|CONFIG) that a shut-off domain rejects — stranding a half-applied
// device in the persistent definition.
//
// It classifies via DomainStateReason rather than DomainState because the coarse
// state COLLAPSES paused, shut-off, and pm-suspended all to "stopped". The stopped
// compensation path is DESTRUCTIVE (it deletes op-owned backing files and tombstones
// desired-state rows), and a filesystem delete affects a paused / pm-suspended guest
// — which is still ACTIVE with its disks attached — regardless of not issuing a live
// libvirt call. So the destructive path is taken ONLY for a genuine shut-off; a
// paused / pm-suspended (or indeterminate / crashed / stopping) domain DEFERS.
//
// Mapping: real libvirt coarse-"stopped" ⟺ {Paused, Shutoff, Pmsuspended}; the
// reasons "paused"/"pmsuspended" pick out the two still-active cases, so
// State=="stopped" with any OTHER reason ⟺ a genuine DomainShutoff (a "stopped" with
// an unmapped/"unknown" reason is an unmapped shut-off sub-reason → still shut off).
func (s *Server) recoveryDomainDisposition(vmName string) recoveryDisp {
	st, err := s.virt.DomainStateReason(vmName)
	if err != nil {
		slog.Warn("hardware op recovery: live domain state indeterminate", "vm", vmName, "error", err)
		return dispDefer
	}
	if st.State == "running" {
		return dispRunning
	}
	if st.State == "stopped" && st.Reason != "paused" && st.Reason != "pmsuspended" {
		return dispShutoff
	}
	slog.Warn("hardware op recovery: domain not definitively running or shut off; leaving recoverable",
		"vm", vmName, "state", st.State, "reason", st.Reason)
	return dispDefer
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

// sameFile reports whether two paths resolve to the SAME inode (os.Link'd twins). Any
// stat error → false: a missing or unreadable side cannot prove this op co-owns the
// final path, so recovery fails closed (does not delete).
func sameFile(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

func (s *Server) recoverDiskAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving disk attach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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

	// Prove this op published the FINAL file before letting rollback delete it. The mere
	// PRESENCE of "file_created_by_operation" (the INTENDED final path, journaled at the
	// claimed stage BEFORE the os.Link) is NOT proof — a crash after that journal but
	// before the link, plus a FOREIGN file appearing at the final path, must NOT delete
	// the foreign file. Ownership is proven iff:
	//   - the durable "published" stage is present (op linked final; the proof survives
	//     temp removal); OR
	//   - the claimed stage recorded "creating_temp" AND both temp & final exist and are
	//     the SAME inode (os.SameFile) — the op linked final but crashed before the
	//     published stage (the temp is removed only AFTER that stage, so its presence as
	//     final's inode-twin is the crash-window proof).
	// Otherwise fileCreated=false: never published, or a foreign/different-inode file
	// sits at final → recovery must not delete it.
	finalPath := art["file_created_by_operation"]
	tempPath := art["creating_temp"]
	fileCreated := art["published"] == "true" ||
		(tempPath != "" && finalPath != "" && sameFile(tempPath, finalPath))
	rb := attachRollback{
		vm: vm, opID: view.ActiveOperationID, epoch: view.OwnerEpoch, newGen: view.SpecGeneration,
		diskName: art["disk_name"], diskPath: finalPath,
		// The op-specific staging temp of a crashed op. ALWAYS safe to delete — unique to
		// this op → never a foreign file; failDeviceAttach removes it, tolerating ErrNotExist.
		tempPath:  tempPath,
		targetDev: targetDev, running: running, journaled: true,
		fileCreated: fileCreated,
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
	// failDeviceAttach rolls back directionally and, ONLY if the rollback completes,
	// records the terminal failure + clears the barrier; otherwise it leaves the op
	// NON-TERMINAL. Its returned error is the operation's reported failure (expected),
	// not a recovery fault — the resulting barrier state is the source of truth.
	_, _ = s.failDeviceAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

func (s *Server) recoverNICAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving nic attach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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
		for _, n := range nics {
			if strings.EqualFold(n.MAC, mac) {
				rb.nicRowWritten = true
				break
			}
		}
	}
	// Tombstone the legacy vm_interfaces row on its ACTUAL presence, not a latched
	// flag reconstructed at recovery time: a latch flip between crash and recovery
	// must never strand a written legacy row un-tombstoned.
	if legacy, e := corrosion.GetVMNICsRaw(ctx, s.db, "vm_interfaces", vm.Name); e == nil {
		for _, r := range legacy {
			if r.DeletedAt == "" && strings.EqualFold(r.MAC, mac) {
				rb.legacyRowWritten = true
				break
			}
		}
	}
	_, _ = s.failNICAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

func (s *Server) recoverPCIAttach(ctx context.Context, vm *corrosion.VMRecord, view *corrosion.VMOperationView, entry *opjournal.Entry) {
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving pci attach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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

	// Claimed-window fallback: a crash AFTER acquireDeviceLeases (vfio bind +
	// AssignPCIDevice + beginDeviceLease) but BEFORE any vm_pci_realizations row was
	// written leaves realizations empty even though the devices are vfio-bound and
	// owner-assigned to this VM. RecoverDeviceLeases already ran and CLEARED the
	// device_lease journal entry WITHOUT releasing (the VM row exists), so this op's
	// OWN device_attach entry is the sole authority for the addresses to release —
	// there is no double-release (device_lease is a distinct journal Kind). Reconstruct
	// them from its member_addresses artifact, confirmed against host_pci_devices
	// ownership so a STOPPED reserve — which resolves the same addresses into the
	// journal but never acquires a lease — is never wrongly released.
	leaseHeld := realizationsWritten
	if !realizationsWritten {
		if owned := s.pciAddrsOwnedByVM(ctx, vm.Name, splitCSVNonEmpty(art["member_addresses"])); len(owned) > 0 {
			for i, addr := range owned {
				members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", i), Address: addr})
			}
			leaseHeld = true
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
	}
	// Release the lease on rollback whenever it was acquired — realizations written,
	// the claimed-window journal fallback confirmed ownership, or a live hostdev is
	// present — REGARDLESS of whether the domain is running NOW: a host reboot flips a
	// claimed-window attach onto the stopped path, but its bound + owner-assigned
	// devices still leak (and block re-attach via exclusivity) unless released here.
	rb.acquired = leaseHeld || len(rb.attachedAddrs) > 0
	// The reconstructed members ARE the release set: realizations / the owner-confirmed
	// claimed-window fallback establish EXACTLY the devices this incomplete attach holds
	// and must release on rollback. failPCIAttach releases rb.acquireClaimed (scoped to
	// what THIS op took, FIX-9c), so hand it the reconstructed addresses — recovery cannot
	// observe the pre-op ownership, so it releases what the durable evidence says it owns.
	for _, m := range members {
		rb.acquireClaimed = append(rb.acquireClaimed, m.Address)
	}
	if rb.dualWrite {
		if os2, e := removePCIDeviceFromSpec(vm.Spec, normAddr); e == nil {
			rb.origSpec = os2 // restore the spec with the pre-latch dual-write device removed
		}
	}
	_, _ = s.failPCIAttach(ctx, rb, codes.Internal, errRecoveredIncompleteAttach)
}

// pciAddrsOwnedByVM returns the subset of addrs currently owner-assigned to vmName
// in host_pci_devices — the durable ground truth that acquireDeviceLeases ran (it
// AssignPCIDevice's each member BEFORE the vfio bind, and the assignment survives a
// reboot). Used by the claimed-window fallback to release EXACTLY the leases this VM
// holds, never a device a stopped reserve merely resolved or one another VM has since
// claimed.
func (s *Server) pciAddrsOwnedByVM(ctx context.Context, vmName string, addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil
	}
	owned := make(map[string]bool, len(devs))
	for _, d := range devs {
		if d.VMName == vmName {
			owned[d.Address] = true
		}
	}
	var out []string
	for _, a := range addrs {
		if owned[a] {
			out = append(out, a)
		}
	}
	return out
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
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving disk detach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving nic detach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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
	disp := s.recoveryDomainDisposition(vm.Name)
	if disp == dispDefer {
		slog.Warn("hardware op recovery: domain not definitely running/shutoff; leaving pci detach recoverable, will retry", "vm", vm.Name, "op", view.ActiveOperationID)
		return
	}
	running := disp == dispRunning
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
