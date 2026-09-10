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
		if err := s.finishVMReplaceRuntime(ctx, cl.Manifest); err != nil {
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
// A restart cannot re-derive its inputs from the database — the replacement's row
// is tombstoned under its temporary name and the contested name now holds the
// transitioned record — so they come from the manifest. It is idempotent: a
// domain already defined under the new name, with no domain left under the
// temporary one, is the finished state and does nothing.
//
// For a Secure-Boot/vTPM VM a failure here is HARD: the reconciler cannot heal a
// firmware VM (a fresh redefine would mint new firmware), so it is reported and
// leaves the phase unrecorded for the next attempt. For a plain VM the reconciler
// rebuilds from the row, so a failure is logged and the phase still completes.
func (s *Server) finishVMReplaceRuntime(ctx context.Context, m corrosion.VMReplaceManifest) error {
	if m.HostName != s.hostName {
		return nil
	}
	firmware := usesFirmwareState(m.ReplacementSpec)
	failed := func(step string, e error) error {
		slog.Error("cutover: runtime handoff step failed",
			"step", step, "vm", m.ReplacedVM, "error", e, "firmware_vm", firmware)
		s.recordVMEvent(ctx, m.ReplacedVM, "vm.cutover", "error", step+" failed: "+e.Error())
		if firmware {
			if werr := corrosion.UpdateVMState(ctx, s.db, m.ReplacedVM, "error",
				"cutover "+step+" failed: "+e.Error()); werr != nil {
				s.noteStateWriteFail(corrosion.OpVMState, werr)
			}
			return fmt.Errorf("%s: %w", step, e)
		}
		return nil // plain VM — the reconciler rebuilds it from its row
	}

	// Libvirt has no rename: dump, undefine, redefine. A domain already at the new
	// name means this phase has run.
	xml, derr := s.virt.DumpXML(m.Replacement)
	if derr != nil {
		if _, atNew := s.virt.DumpXML(m.ReplacedVM); atNew == nil {
			return nil // already handed over
		}
		return failed("dump XML", derr)
	}
	// KEEP NVRAM/vTPM — the dumped XML retains the stable <uuid> so the UUID-keyed
	// swtpm follows it automatically; only the name-keyed NVRAM file moves. The
	// undefine MUST succeed before that rename, or the vars file is pulled out from
	// under a still-defined domain, leaving a dangling <nvram> path (G1).
	if e := s.virt.UndefineDomainPreservingState(m.Replacement); e != nil {
		if err := failed("undefine the replacement's domain", e); err != nil {
			return err
		}
	}
	xml = replaceDomainName(xml, m.Replacement, m.ReplacedVM)
	oldNvram := lv.NvramPath(s.dataDir, m.Replacement)
	newNvram := lv.NvramPath(s.dataDir, m.ReplacedVM)
	if _, e := os.Stat(oldNvram); e == nil {
		if e := os.Rename(oldNvram, newNvram); e == nil {
			xml = strings.ReplaceAll(xml, oldNvram, newNvram)
		} else if err := failed("nvram rename", e); err != nil {
			return err
		}
	}
	if e := s.virt.DefineDomain(xml); e != nil {
		if err := failed("redefine", e); err != nil {
			return err
		}
	} else if m.ReplacementState == "running" {
		if e := s.virt.StartDomain(m.ReplacedVM); e != nil {
			if err := failed("start", e); err != nil {
				return err
			}
		}
	}
	return nil
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
		if cErr := s.finishVMReplaceCleanup(ctx, cl); cErr != nil {
			slog.Error("cutover: resumed cleanup failed — it stays journaled for the next attempt",
				"replaced_vm", cl.Manifest.ReplacedVM, "operation", cl.OperationID, "error", cErr)
			if firstErr == nil {
				firstErr = cErr
			}
		}
	}
	return firstErr
}
