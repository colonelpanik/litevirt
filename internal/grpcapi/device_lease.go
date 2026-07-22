package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// deviceLeaseKind marks host-local journal entries that record a PCI allocation's
// claimed/bound devices (distinct from operation entries, which the startup
// operation-recovery barrier handles).
const deviceLeaseKind = "device_lease"

// deviceLeaseStageBound marks a device lease whose allocation completed the vfio bind
// (and, for a running attach, the guest attach loop). Restart recovery treats a bound
// lease on an EXISTING VM as a finished allocation and clears it WITHOUT releasing — the
// ownership + realization rows are the durable record by then, so reclaiming would tear
// live devices out of a successfully-completed VM. This is the initial stage every caller
// EXCEPT the legacy running-attach uses.
const deviceLeaseStageBound = "bound"

// deviceLeaseStageInProgress marks a legacy running-attach lease at BEGIN — the devices
// are already owned + vfio-bound, but the guest attach loop has not finished, and this
// path is UNJOURNALED (the lease is its ONLY crash anchor). A crash in that window leaves
// the devices owned + bound with the VM already existing; a bound lease would be
// misread as a completed allocation and cleared, leaking the devices. So this stage is a
// reclaim trigger: restart recovery treats it EXACTLY like rollback_incomplete.
const deviceLeaseStageInProgress = "in_progress"

// deviceLeaseStageRollbackIncomplete marks a device lease whose owning operation's
// rollback could not complete, leaving the recorded device(s) still owned + bound.
// It is the signal that distinguishes such a lease from a completed allocation
// (Stage "bound"): restart recovery reclaims a rollback_incomplete lease's members
// instead of clearing it, so the leaked owned+bound devices are never silently lost.
const deviceLeaseStageRollbackIncomplete = "rollback_incomplete"

func deviceLeaseOpID(vmName string) string { return "devlease:" + vmName }

// clearDeviceLease removes any lingering durable PCI device lease for vmName. Called
// after a VM's devices have been released on delete so a deleted VM's devlease:<vm> entry
// can never linger and later drive RecoverDeviceLeases to unbind a BDF the VM's address
// has since been legitimately reclaimed for. Tolerant of a missing entry / absent journal
// (opJournal.Remove is a no-op for a not-found entry).
func (s *Server) clearDeviceLease(vmName string) {
	if s.opJournal == nil {
		return
	}
	if err := s.opJournal.Remove(deviceLeaseOpID(vmName)); err != nil {
		slog.Warn("device lease: clear on delete", "vm", vmName, "error", err)
	}
}

// beginDeviceLease durably records the devices an allocation has claimed for
// vmName, BEFORE the irreversible vfio bind, so a crash before the VM row is
// finalized can be rolled back at startup (RecoverDeviceLeases). It is gated by
// the operation_protocol capability being active (config flag AND latch): when
// inactive it is a no-op and only the in-memory scoped rollback applies. Returns
// a finish func the caller defers to clear the lease once the VM row is durable.
//
// It is FAIL-CLOSED: the durable pre-bind crash anchor is a precondition of binding,
// so a journal write error returns a non-nil error and the caller MUST NOT bind — a
// crash after a bind with no recovery record is exactly the owned+bound leak this
// lease exists to prevent. The gated no-op case returns (func(){}, nil): pre-latch no
// lease is EXPECTED, so it is not an error.
//
// stage is the INITIAL durable stage: deviceLeaseStageBound for every caller whose
// completion produces its own durable record (CreateVM, start, journaled attach), and
// deviceLeaseStageInProgress ONLY for the unjournaled legacy running-attach, whose lease
// is its sole crash anchor and whose VM already exists — so a mid-attach crash must be
// reclaimed by recovery, not misread as a completed allocation and cleared.
func (s *Server) beginDeviceLease(ctx context.Context, vmName string, addrs []string, stage string) (func(), error) {
	if s.opJournal == nil || len(addrs) == 0 || !s.operationProtocolActive(ctx) {
		return func() {}, nil
	}
	entry := opjournal.Entry{
		OperationID: deviceLeaseOpID(vmName),
		ResourceID:  vmName,
		Kind:        deviceLeaseKind,
		Stage:       stage,
		Artifacts:   map[string]string{"addresses": strings.Join(addrs, ",")},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.opJournal.Write(entry); err != nil {
		return nil, fmt.Errorf("device lease: durable journal write for %q: %w", vmName, err)
	}
	return func() {
		if err := s.opJournal.Remove(deviceLeaseOpID(vmName)); err != nil {
			slog.Warn("device lease: clear journal entry", "vm", vmName, "error", err)
		}
	}, nil
}

// completeDeviceLease durably records that a successful allocation's lease reached a SAFE
// outcome, and REPORTS whether it did. It transitions the lease to Stage bound (recovery
// clears a bound lease WITHOUT reclamation) then best-effort removes it. Only needed by the
// legacy attach (its lease is in_progress, a reclaim trigger); the other callers' leases are
// already bound. No-op (nil) when no lease exists (pre-latch / already gone).
//
// The two journal ops (the bound-transition Write and the Remove) are NOT independent: ONE
// persistent filesystem fault — ENOSPC, a read-only remount, a journal-dir I/O error —
// naturally fails BOTH. A "safe outcome" is either state startup recovery treats
// non-destructively: (i) the lease is durably bound (recovery clears it, no reclaim), OR
// (ii) the lease is durably removed (recovery has nothing). It returns nil iff at least one
// was established (boundPersisted || removed); only when NEITHER did does the surviving
// in_progress lease become a reclaim trigger for the just-attached device — so the caller
// MUST NOT acknowledge success, and completeDeviceLease returns an error to force that.
func (s *Server) completeDeviceLease(vmName string) error {
	if s.opJournal == nil {
		return nil
	}
	opID := deviceLeaseOpID(vmName)
	existing, found, err := s.opJournal.Read(opID)
	if err == nil && !found {
		return nil // no lease (pre-latch / already gone) — nothing to complete
	}
	// boundPersisted: the lease is durably in Stage bound (already bound, or the transition
	// Write succeeded). removed: the best-effort Remove succeeded. Either is a safe outcome.
	var boundPersisted, removed bool
	if err == nil && existing.Stage == deviceLeaseStageBound {
		boundPersisted = true // already bound (a prior partial completion persisted the transition)
	} else if err == nil {
		// A cleanly-read, not-yet-bound lease: durably transition it to bound FIRST (recovery
		// clears a bound lease WITHOUT reclamation). A Write error leaves it un-persisted.
		existing.Stage = deviceLeaseStageBound
		if werr := s.opJournal.Write(*existing); werr != nil {
			slog.Error("device lease: mark completed failed — falling back to removal", "vm", vmName, "error", werr)
		} else {
			boundPersisted = true
		}
	}
	// FIX-33: on a READ error we cannot transition (existing is nil), so we must NOT
	// early-return — the surviving in_progress entry is a reclaim trigger. Fall straight
	// through to the removal: clearing the entry leaves recovery nothing to reclaim (the
	// ownership row + live domain XML are the durable record of the successful attach).
	if rerr := s.opJournal.Remove(opID); rerr != nil {
		slog.Warn("device lease: remove after completion (best-effort; recovery clears a bound entry)", "vm", vmName, "error", rerr)
	} else {
		removed = true
	}
	// NEITHER safe outcome persisted (the bound-transition Write AND the Remove both failed —
	// the single-root-cause degraded-journal fault): the in_progress lease survives and
	// recovery would reclaim the just-attached device. Report it so the caller does not ACK.
	if !boundPersisted && !removed {
		return fmt.Errorf("device lease: could not durably record completion for %q (journal degraded)", vmName)
	}
	return nil
}

// markDeviceLeaseRollbackIncomplete rewrites vmName's durable device lease to Stage
// rollback_incomplete when a legacy running-attach rollback could not complete, leaving
// the recorded device(s) still owned + bound. It overwrites the existing in_progress entry
// in place (same OperationID), REFINING the recovery record: rollback_incomplete records
// the exact left-owned+bound addrs (the members whose rollback failed), whereas the initial
// in_progress lease covers the whole attach.
//
// This mark is a REFINEMENT, NOT the safety net. The legacy attach's INITIAL lease is
// already Stage in_progress — itself a reclaim trigger (recovery reclaims in_progress
// exactly like rollback_incomplete) — so a failed or best-effort mark write no longer
// risks a leak: recovery still reclaims the members off the unrefined in_progress lease.
// A write error is therefore only logged (Warn); the in-memory return still leaves the
// device(s) owned + bound so the safety invariant holds regardless. A no-op when the
// operation journal is absent (pre-latch: no lease exists).
func (s *Server) markDeviceLeaseRollbackIncomplete(vmName string, addrs []string) {
	if s.opJournal == nil {
		return
	}
	// Only OVERWRITE an EXISTING lease — never CREATE one. Pre-latch (operation protocol
	// inactive), beginDeviceLease is a no-op, so no lease was ever written; opJournal is still
	// wired unconditionally at startup, so opJournal!=nil && no-lease is a normal reachable
	// state. Fabricating a rollback_incomplete anchor here would make restart recovery
	// (RecoverDeviceLeases) reclaim — guest-detach + unbind + release — a device that a
	// subsequent successful attach retry has since made live, ripping working passthrough out
	// of a running VM (a recovery pass acting over a NON-leak). The device left owned+bound by
	// an incomplete rollback still converges via operator retry/detach; we simply never invent
	// an anchor that did not already exist.
	existing, found, err := s.opJournal.Read(deviceLeaseOpID(vmName))
	if err != nil || !found {
		return
	}
	existing.Stage = deviceLeaseStageRollbackIncomplete
	existing.Artifacts = map[string]string{"addresses": strings.Join(addrs, ",")}
	if werr := s.opJournal.Write(*existing); werr != nil {
		slog.Warn("device lease: mark rollback_incomplete failed (device left owned+bound; recovery anchor best-effort)",
			"vm", vmName, "error", werr)
	}
}

// RecoverDeviceLeases rolls back device leases a crash orphaned. For each durable
// device_lease journal entry:
//   - the VM no longer exists (its allocation never finalized) → the recorded devices
//     are unbound + owner-scoped-released, then the entry is removed;
//   - the VM exists and the lease is Stage in_progress or rollback_incomplete → a legacy
//     running-attach crashed mid-flight (in_progress: the initial stage, so the crash hit
//     during the bind or guest-attach loop) or its rollback could not complete
//     (rollback_incomplete: the refined stage), leaving this attach's members owned +
//     bound. They are membership-aware-reclaimed (guest-detach FIRST, then unbind +
//     owner-release), then the entry removed — but the guest-detach is chosen by the
//     LIVE-domain DISPOSITION: a running domain gets a LIVE detach, a POSITIVELY shut-off
//     domain a CONFIG-only detach (a live-flagged detach a shut-off domain rejects would
//     wedge the lease), and an indeterminate / paused / pm-suspended domain DEFERS (the
//     entry is retained, reclaimed nothing, retried next pass);
//   - the VM exists with any other stage (Stage "bound" — a completed allocation whose
//     finish() didn't run before the crash) → the entry is just cleared, WITHOUT releasing.
//
// Runs at daemon startup, before serving. Best-effort — a transient error leaves the
// entry for next time.
func (s *Server) RecoverDeviceLeases(ctx context.Context) {
	if s.opJournal == nil {
		return
	}
	entries, corrupt, err := s.opJournal.List()
	if err != nil {
		slog.Error("device-lease recovery: list journal", "error", err)
		return
	}
	if len(corrupt) > 0 {
		slog.Error("device-lease recovery: CORRUPT journal entries — host degraded for affected mutations", "files", corrupt)
	}
	for _, e := range entries {
		if e.Kind != deviceLeaseKind {
			continue // operation entries are handled by the operation-recovery barrier
		}
		addrs := splitCSVNonEmpty(e.Artifacts["addresses"])
		vm, err := corrosion.GetVM(ctx, s.db, e.ResourceID)
		if err != nil {
			slog.Warn("device-lease recovery: lookup vm", "vm", e.ResourceID, "error", err)
			continue
		}
		if vm == nil {
			// Orphaned: the VM was never finalized — roll back the leaked devices via the
			// durable-lease-authorized reclaimLeasedDevices primitive (reclaimNoDomain: the VM
			// row is gone, so there is no domain to membership-detach from). The lease is
			// the proof these leaked BDFs were this dead VM's, so the primitive may reclaim an
			// UNOWNED addr — which the normal unbindAndReleaseOwnership must never do. The
			// primitive fails closed on the ownership read, SKIPS any BDF a DIFFERENT live VM
			// has since legitimately reclaimed (never unbinds another VM's passthrough), and is
			// strict all-or-nothing: on its error RETAIN the entry so a later pass retries,
			// rather than removing it over a device still bound to vfio-pci.
			slog.Warn("device-lease recovery: rolling back orphaned lease", "vm", e.ResourceID, "devices", addrs)
			if rerr := s.reclaimLeasedDevices(ctx, e.ResourceID, addrs, reclaimNoDomain); rerr != nil {
				slog.Error("device-lease recovery: reclaim incomplete — retaining lease for retry", "vm", e.ResourceID, "error", rerr)
				continue // do NOT remove the entry; a later pass retries
			}
		} else if e.Stage == deviceLeaseStageInProgress || e.Stage == deviceLeaseStageRollbackIncomplete {
			// The VM exists but a legacy running-attach crashed mid-flight (in_progress: the
			// initial stage — the crash hit during the vfio bind or the guest-attach loop) or
			// its rollback could not complete (rollback_incomplete: the refined stage), leaving
			// this attach's members owned + bound. The reclaim membership-detaches each
			// still-in-guest member FIRST, then unbind + owner-scoped-release — but WHICH detach
			// depends on the LIVE-domain DISPOSITION, not merely "the vm row exists". After a
			// host reboot the vm row still says the VM exists while its domain is SHUT OFF: a
			// live-flagged detach then fails and wedges the lease forever, so a shut-off domain
			// must be CONFIG-detached (persistent definition) instead. An indeterminate / paused
			// / pm-suspended domain DEFERS — reclaiming it could tear a device out of a
			// still-active or unknown-state guest — so the entry is RETAINED for a later pass.
			// Fail closed → RETAIN the entry on any error; a BDF a DIFFERENT live VM has since
			// reclaimed is skipped.
			var mode reclaimGuestMode
			switch disp := s.recoveryDomainDisposition(e.ResourceID); disp {
			case dispRunning:
				mode = reclaimLive
			case dispShutoff:
				mode = reclaimConfig
			default: // dispDefer: indeterminate / paused / pm-suspended → retain, retry next pass
				slog.Warn("device-lease recovery: domain not definitively running or shut off — deferring reclaim, retaining lease",
					"vm", e.ResourceID, "stage", e.Stage, "devices", addrs)
				continue // do NOT reclaim and do NOT clear; a later pass retries once the state is definite
			}
			slog.Warn("device-lease recovery: reclaiming in-progress/rollback-incomplete lease", "vm", e.ResourceID, "stage", e.Stage, "devices", addrs)
			if rerr := s.reclaimLeasedDevices(ctx, e.ResourceID, addrs, mode); rerr != nil {
				slog.Error("device-lease recovery: reclaim incomplete — retaining lease for retry", "vm", e.ResourceID, "error", rerr)
				continue // do NOT remove the entry; a later pass retries
			}
		} else {
			// A completed allocation (finish() didn't run before the crash): the ownership +
			// realization rows are the durable record now — clear the lease WITHOUT releasing.
			slog.Info("device-lease recovery: allocation completed, clearing lease", "vm", e.ResourceID)
		}
		if err := s.opJournal.Remove(e.OperationID); err != nil {
			slog.Warn("device-lease recovery: remove entry", "vm", e.ResourceID, "error", err)
		}
	}
}

func splitCSVNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
