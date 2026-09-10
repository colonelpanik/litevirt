package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

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
// crash boundaries — "before-commit", "after-commit", "mid-cleanup" — and, by
// returning an error, makes the handler abandon the operation exactly there.
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
	m := cl.Manifest
	if m.HostName == s.hostName {
		// Owner = the replacement's FORMER name, which owns no live row now.
		// Passing the contested name would make diskPathReferencedByOtherVM read
		// the replacement's own rows as this VM's and free a path they share;
		// passing a name that owns nothing makes every live reference count as
		// another VM's, which is the conservative direction.
		//
		// There is deliberately no images.DeleteVMDisks default-dir sweep. That
		// globs "<name>-*.qcow2", which matches the replacement's own flat-named
		// disks ("<name>-next-*.qcow2") — the sweep would delete the disks the
		// cutover exists to keep. The manifest is authoritative and its records are
		// driver-dispatched, so a volume outside the default pool is freed where it
		// actually lives.
		if err := s.deleteRecordedVMDiskVolumeRecords(ctx, m.Replacement, m.Disks); err != nil {
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
	return corrosion.CompleteVMReplace(ctx, s.db, cl.OperationID, cl.OwnerEpoch)
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
