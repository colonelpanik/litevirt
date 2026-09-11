package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// The destruction half of `lv cutover`, driven entirely from the journaled
// manifest.
//
// It cannot be driven from the database instead: the replacement transition
// DISPLACES the replaced VM's parent row and every child row whose key the
// replacement claims, and the name those rows were recorded under now belongs to
// the replacement. Reading it back would free the wrong VM's disks. The manifest,
// taken before the transition and committed with the step that authorizes this,
// is the only surviving description of what to free.

// operatorStopDetail is the sticky marker StopVM records. It is the one thing
// that overrides a cutover's journaled running intent: an operator's decision,
// as opposed to a reconciler's observation of a domain that is shut off because
// the handoff has not run yet.
const operatorStopDetail = "operator-stop"

// SetCutoverCrashHook installs a TEST-ONLY seam that fires at each of cutover's
// crash boundaries and, by returning an error, makes the handler abandon the
// operation exactly there.
//
// The stages are the boundaries between phases that cannot be one commit:
// "before-commit" (the transition), "mid-cleanup" (part of the destruction done),
// "before-runtime" (destruction recorded, the handoff not started) and
// "after-commit" (nothing after the transition has run).
//
// A process that dies mid-cutover cannot be arranged from a test any other way,
// and the guarantees at those three boundaries (an uncommitted operation destroys
// nothing; a committed one is finished by a restart; the replacement's resources
// survive every retry) are the whole reason the journal exists. Production never
// calls this.
func (s *Server) SetCutoverCrashHook(h func(stage string) error) { s.cutoverCrashHook = h }

func (s *Server) fireCutoverCrashHook(stage string) error {
	if h := s.cutoverCrashHook; h != nil {
		return h(stage)
	}
	return nil
}

// finishVMReplaceCleanup frees what the manifest lists and records completion —
// in that order, and only in that order. The completion step is what stops a
// restart from retrying, so writing it while a volume is still there would
// strand exactly what the journal exists to free.
//
// Every step is idempotent, because this runs again after any interruption: a
// volume already gone, firmware state already wiped, and an ISO already removed
// are all successes. The shared-path check is retained — a volume another VM
// still references is skipped, not freed.
func (s *Server) finishVMReplaceCleanup(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	if !cl.CleanupDone {
		if err := s.freeReplacedVMResources(ctx, cl); err != nil {
			return err
		}
		if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
			corrosion.OpStepConfigApplied); err != nil {
			return err
		}
	}
	if !cl.RuntimeDone {
		if hErr := s.fireCutoverCrashHook("before-runtime"); hErr != nil {
			return hErr
		}
		if err := s.finishVMReplaceRuntime(ctx, cl); err != nil {
			return err
		}
		if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
			corrosion.OpStepRedefined); err != nil {
			return err
		}
	}
	return corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
		corrosion.OpStepCompleted)
}

// freeReplacedVMResources is the destruction phase. It must run exactly once:
// after it, the runtime handoff moves the REPLACEMENT's firmware onto the
// contested name, and a second pass of this name-keyed wipe would destroy that
// instead.
func (s *Server) freeReplacedVMResources(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	m := cl.Manifest
	if m.HostName == s.hostName {
		// EVERY live reference protects the volume — no name is exempt. The
		// contested name now belongs to the replacement, and the temporary name is
		// free and reusable, so exempting either would exempt whatever VM happens
		// to hold that name when a delayed cleanup finally runs. A VM created after
		// the crash can legitimately reference the volume.
		//
		// There is deliberately no images.DeleteVMDisks default-dir sweep. That
		// globs "<name>-*.qcow2", which matches the replacement's own flat-named
		// disks ("<name>-next-*.qcow2") — the sweep would delete the disks the
		// cutover exists to keep. The manifest is authoritative and its records are
		// driver-dispatched, so a volume outside the default pool is freed where it
		// actually lives.
		if err := s.deleteCapturedVMDiskVolumes(ctx, m.Disks); err != nil {
			return fmt.Errorf("free the replaced VM's volumes: %w", err)
		}
		if hErr := s.fireCutoverCrashHook("mid-cleanup"); hErr != nil {
			return hErr
		}
		// The replaced VM's UUID-keyed swtpm tree and name-keyed NVRAM, so the
		// cutover does not orphan them (G1).
		lv.WipeFirmwareState(s.dataDir, m.ReplacedVM, m.FirmwareUUID)
		for _, p := range m.Paths {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", p, err)
			}
		}
	}
	return nil
}

// finishVMReplaceRuntime is the runtime-handoff phase: the replacement's libvirt
// domain and its name-keyed firmware still answer to the temporary name after the
// transition commits, and moving them is the other half of a cutover.
//
// Three things make this harder than "rename the domain":
//
//   - The temporary name is FREE the moment the transition commits, so acting on
//     it by name alone can consume a VM that reused it. Every step checks the
//     recorded domain UUID first, including the already-done shortcut.
//   - Undefining destroys the only copy of the definition, so it is journaled
//     first. A transient redefine failure would otherwise leave neither name
//     defined and nothing left to redefine from.
//   - The desired runtime state is read from the DATABASE now, not from the
//     manifest's pre-transition snapshot. An operator stop acknowledged between
//     capture and handoff must not be undone by replaying a stale "running".
//
// For a Secure-Boot/vTPM VM a failure is HARD: the reconciler cannot heal a
// firmware VM (a fresh redefine would mint new firmware), so it is reported and
// leaves the phase unrecorded for the next attempt. For a plain VM the reconciler
// rebuilds from the row, so a failure is logged and the phase still completes.
func (s *Server) finishVMReplaceRuntime(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	m := cl.Manifest
	if m.HostName != s.hostName {
		return nil
	}
	// The authoritative desired state, and the proof this operation still owns the
	// name. A different incarnation there means someone else's cutover or recreate
	// has taken over; touching libvirt for it would be acting on another VM.
	desired, err := corrosion.GetVM(ctx, s.db, m.ReplacedVM)
	if err != nil {
		return err
	}
	if desired == nil || desired.CreatedAt != m.ReplacementIncarnation {
		slog.Warn("cutover: skipping the runtime handoff — the name no longer holds this incarnation",
			"vm", m.ReplacedVM, "operation", cl.OperationID)
		return nil
	}

	// No recorded identity means there was no local domain to move when the
	// manifest was taken, so there is nothing for this phase to do. It is NOT a
	// licence to act by name: the temporary name is reusable, and a name match
	// alone would let a delayed recovery consume whatever VM now holds it.
	if m.ReplacementUUID == "" {
		return nil
	}
	firmware := usesFirmwareState(m.ReplacementSpec)
	// EVERY failure here is returned, so the phase stays unrecorded and a restart
	// retries it. The older behaviour tolerated a plain VM's failure on the grounds
	// that the reconciler rebuilds from the row — but that predates the journal,
	// and swallowing it now records the handoff as done: a redefine that failed
	// leaves neither name defined with the operation closed, and a start that
	// failed leaves a VM the operator asked to be running shut off for good. The
	// reconciler is still a backstop; it is no longer the only one.
	failed := func(step string, e error) error {
		slog.Error("cutover: runtime handoff step failed",
			"step", step, "vm", m.ReplacedVM, "error", e, "firmware_vm", firmware)
		s.recordVMEvent(ctx, m.ReplacedVM, "vm.cutover", "error", step+" failed: "+e.Error())
		// A firmware VM cannot be healed by a fresh redefine (it would mint new
		// firmware), so the failure is surfaced on its row for an operator to see —
		// in the DETAIL, keeping the state itself untouched. Writing state=error
		// here is what made a failed start unrecoverable: the next attempt reads the
		// row for the desired runtime state, sees "error", concludes the VM was not
		// asked to run, and completes the operation with it shut off. Operation
		// failure and running intent are different facts and cannot share a column.
		if firmware {
			if werr := corrosion.UpdateVMState(ctx, s.db, m.ReplacedVM, desired.State,
				"cutover "+step+" failed: "+e.Error()); werr != nil {
				s.noteStateWriteFail(corrosion.OpVMState, werr)
			}
		}
		return fmt.Errorf("%s: %w", step, e)
	}

	// 1. The definition, durably, before anything undefines it.
	alreadyAtTarget, _, atErr := s.domainOwnership(m.ReplacedVM, m.ReplacementUUID)
	if atErr != nil {
		return failed("read the domain at the contested name", atErr)
	}
	handoff := cl.Handoff
	if handoff.XML == "" {
		xml, derr := s.virt.DumpXML(m.Replacement)
		switch {
		case derr == nil && s.domainIdentityMatches(xml, m.ReplacementUUID):
			handoff = corrosion.VMReplaceHandoff{XML: xml, UUID: m.ReplacementUUID}
			if rErr := corrosion.RecordVMReplaceHandoff(ctx, s.db, cl.OperationID, cl.OwnerEpoch, handoff); rErr != nil {
				return rErr
			}
		case alreadyAtTarget:
			// Already redefined by an earlier attempt; only the runtime state may
			// still be owed, which the tail of this function settles.
		case derr == nil:
			// A DIFFERENT VM answers to the temporary name. Never undefine it.
			slog.Warn("cutover: the temporary name holds a different VM — leaving it alone",
				"name", m.Replacement, "want_uuid", m.ReplacementUUID)
			return nil
		default:
			return failed("dump the replacement's XML", derr)
		}
	}

	// Whether the temporary name is still OURS. A foreign domain there means some
	// other VM has taken the freed name: neither its definition nor its firmware
	// may be touched.
	//
	// A read that FAILED is neither answer. Treating it as "not foreign" is what
	// let a transient libvirt error authorize moving an unrelated VM's firmware, so
	// only a verified not-found counts as absence and anything else aborts the
	// phase for the next attempt.
	ownsTemporary, foreignAtTemporary, idErr := s.domainOwnership(m.Replacement, m.ReplacementUUID)
	if idErr != nil {
		return failed("read the domain at the replacement's name", idErr)
	}

	// 2. Undefine — only ever the domain this operation recorded.
	if handoff.XML != "" && ownsTemporary {
		// KEEP NVRAM/vTPM: the recorded XML carries the stable <uuid>, so the
		// UUID-keyed swtpm follows automatically and only the name-keyed vars file
		// moves. The undefine MUST precede that rename or the file is pulled out
		// from under a still-defined domain, leaving a dangling <nvram> path (G1).
		if e := s.virt.UndefineDomainPreservingState(m.Replacement); e != nil {
			return failed("undefine the replacement's domain", e)
		}
	}

	// 3. Redefine under the contested name, from the recorded definition.
	targetIsOurs, _, tErr := s.domainOwnership(m.ReplacedVM, m.ReplacementUUID)
	if tErr != nil {
		return failed("read the domain at the contested name", tErr)
	}
	if handoff.XML != "" && !targetIsOurs {
		oldNvram := lv.NvramPath(s.dataDir, m.Replacement)
		newNvram := lv.NvramPath(s.dataDir, m.ReplacedVM)
		// The destination definition, derived UNCONDITIONALLY — not as a side effect
		// of this attempt performing the rename. A retry after a failed redefine
		// finds the file already moved, skips the rename, and would otherwise define
		// the VM pointing at a vars file that is no longer there.
		xml := strings.ReplaceAll(
			replaceDomainName(handoff.XML, m.Replacement, m.ReplacedVM), oldNvram, newNvram)
		// The firmware moves only while the temporary name is still ours. It is a
		// name-keyed path, so a VM that took the freed name owns the file at it now,
		// and moving it would hand that VM's firmware to the contested name.
		if !foreignAtTemporary {
			if _, e := os.Stat(oldNvram); e == nil {
				if e := os.Rename(oldNvram, newNvram); e != nil {
					return failed("nvram rename", e)
				}
			}
		}
		if e := s.virt.DefineDomain(xml); e != nil {
			return failed("redefine", e)
		}
	}

	// 4. The runtime state the DATABASE currently asks for — never the manifest's
	// snapshot. A domain merely existing is not the finished state: a start that
	// failed on an earlier attempt leaves it defined and shut off, and recording
	// the phase then would strand a VM the operator asked to be running.
	// The intent comes from the MANIFEST, captured before the teardown, not from
	// the row. The row's state is observational: a reconciler pass that finds the
	// domain shut off — which is exactly what an unfinished handoff looks like —
	// syncs it to "stopped", and reading that back would erase the very start this
	// phase owes. Only an explicit operator stop overrides the manifest, because
	// that is a decision rather than an observation.
	wantRunning := m.ReplacementState == "running"
	if desired.StateDetail == operatorStopDetail {
		wantRunning = false
	}
	if !wantRunning {
		return nil
	}
	state, sErr := s.virt.DomainState(m.ReplacedVM)
	if sErr != nil {
		return failed("read the domain state", sErr)
	}
	if state == "running" {
		return nil
	}
	if e := s.virt.StartDomain(m.ReplacedVM); e != nil {
		return failed("start", e)
	}
	return nil
}

// domainIdentityMatches reports whether libvirt XML carries the expected UUID. An
// empty expectation matches nothing: a manifest without a recorded UUID cannot
// authorize acting on a reusable name.
func (s *Server) domainIdentityMatches(xml, want string) bool {
	return want != "" && domainUUIDFromXML(xml) == want
}

// domainOwnership reports whether the domain at name is the expected one (ours),
// whether some OTHER domain answers to that name (foreign), or an error.
//
// Three-valued on purpose. A failed read is not "absent" and not "not foreign":
// collapsing it into either lets a transient libvirt error authorize acting on a
// name whose real occupant is unknown, which for a reusable name means acting on
// another VM. Only a verified not-found is absence (false, false, nil).
func (s *Server) domainOwnership(name, want string) (ours, foreign bool, err error) {
	xml, dErr := s.virt.DumpXML(name)
	switch {
	case dErr == nil:
		if s.domainIdentityMatches(xml, want) {
			return true, false, nil
		}
		return false, true, nil
	case lv.IsNotFound(dErr):
		return false, false, nil
	default:
		return false, false, dErr
	}
}

// domainUUIDFromXML extracts <uuid>…</uuid> from a domain definition.
func domainUUIDFromXML(xml string) string {
	const open, close = "<uuid>", "</uuid>"
	i := strings.Index(xml, open)
	if i < 0 {
		return ""
	}
	rest := xml[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// lockedFinishVMReplace takes the lifecycle locks the phases require, in name
// order, and finishes what is owed. Recovery has to serialize with StopVM/StartVM
// exactly as the handler does: a resumed handoff reads the desired runtime state
// and then acts on it, and a lifecycle call landing between those is how a VM the
// operator just stopped gets started again.
func (s *Server) lockedFinishVMReplace(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	for _, n := range sortedPair(cl.Manifest.ReplacedVM, cl.Manifest.Replacement) {
		unlock := s.lockVM(n)
		defer unlock()
	}
	// RELOAD under the locks. The snapshot that got us here was taken before them,
	// so another caller holding them may have finished phases in the meantime —
	// and repeating the destruction phase after the handoff has moved the
	// replacement's firmware onto the contested name would wipe it.
	fresh, err := corrosion.ListVMReplaceCleanups(ctx, s.db, s.hostName)
	if err != nil {
		return err
	}
	for _, f := range fresh {
		if f.OperationID == cl.OperationID {
			return s.finishVMReplaceCleanup(ctx, f)
		}
	}
	return nil // finished by whoever held the locks first
}

// ResumeVMReplaceCleanups finishes the destruction for every cutover on this host
// whose transition COMMITTED and whose cleanup was never recorded as done — the
// work a daemon that died mid-cutover left behind.
//
// It never re-runs a replacement and never reconstructs the replaced VM's
// resources from the reused name: a planned-only operation is skipped precisely
// because its transition did not land, and a committed one is driven from its
// manifest. Called at startup, and safe to call at any time.
func (s *Server) ResumeVMReplaceCleanups(ctx context.Context) error {
	pending, err := corrosion.ListVMReplaceCleanups(ctx, s.db, s.hostName)
	if err != nil {
		return err
	}
	var firstErr error
	for _, cl := range pending {
		slog.Info("cutover: resuming a committed cleanup left by an interrupted attempt",
			"replaced_vm", cl.Manifest.ReplacedVM, "operation", cl.OperationID,
			"disks", len(cl.Manifest.Disks))
		if cErr := s.lockedFinishVMReplace(ctx, cl); cErr != nil {
			slog.Error("cutover: resumed cleanup failed — it stays journaled for the next attempt",
				"replaced_vm", cl.Manifest.ReplacedVM, "operation", cl.OperationID, "error", cErr)
			if firstErr == nil {
				firstErr = cErr
			}
		}
	}
	return firstErr
}
