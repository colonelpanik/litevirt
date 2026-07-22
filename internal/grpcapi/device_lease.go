package grpcapi

import (
	"context"
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
func (s *Server) beginDeviceLease(ctx context.Context, vmName string, addrs []string) func() {
	if s.opJournal == nil || len(addrs) == 0 || !s.operationProtocolActive(ctx) {
		return func() {}
	}
	entry := opjournal.Entry{
		OperationID: deviceLeaseOpID(vmName),
		ResourceID:  vmName,
		Kind:        deviceLeaseKind,
		Stage:       "bound",
		Artifacts:   map[string]string{"addresses": strings.Join(addrs, ",")},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.opJournal.Write(entry); err != nil {
		slog.Warn("device lease: durable journal write failed (in-memory rollback still applies)",
			"vm", vmName, "error", err)
		return func() {}
	}
	return func() {
		if err := s.opJournal.Remove(deviceLeaseOpID(vmName)); err != nil {
			slog.Warn("device lease: clear journal entry", "vm", vmName, "error", err)
		}
	}
}

// markDeviceLeaseRollbackIncomplete rewrites vmName's durable device lease to Stage
// rollback_incomplete when a legacy running-attach rollback could not complete, leaving
// the recorded device(s) still owned + bound. It overwrites the existing "bound" entry
// in place (same OperationID), so restart recovery can distinguish this real leak from a
// completed allocation and reclaim the members instead of silently clearing the entry.
// A write error is only logged (Warn): the in-memory return still leaves the device(s)
// owned + bound so the safety invariant holds — only the durable recovery anchor is
// best-effort. A no-op when the operation journal is absent (pre-latch: no lease exists).
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
//   - the VM exists and the lease is Stage rollback_incomplete → a legacy-attach
//     rollback left this attach's members owned + bound, so they are membership-aware-
//     reclaimed (guest-detach FIRST, then unbind + owner-release), then the entry removed;
//   - the VM exists with any other stage (a completed allocation whose finish() didn't
//     run before the crash) → the entry is just cleared, WITHOUT releasing.
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
			// durable-lease-authorized reclaimLeasedDevices primitive (vmExists=false: the VM
			// row is gone, so there is no live guest to membership-detach from). The lease is
			// the proof these leaked BDFs were this dead VM's, so the primitive may reclaim an
			// UNOWNED addr — which the normal unbindAndReleaseOwnership must never do. The
			// primitive fails closed on the ownership read, SKIPS any BDF a DIFFERENT live VM
			// has since legitimately reclaimed (never unbinds another VM's passthrough), and is
			// strict all-or-nothing: on its error RETAIN the entry so a later pass retries,
			// rather than removing it over a device still bound to vfio-pci.
			slog.Warn("device-lease recovery: rolling back orphaned lease", "vm", e.ResourceID, "devices", addrs)
			if rerr := s.reclaimLeasedDevices(ctx, e.ResourceID, addrs, false); rerr != nil {
				slog.Error("device-lease recovery: reclaim incomplete — retaining lease for retry", "vm", e.ResourceID, "error", rerr)
				continue // do NOT remove the entry; a later pass retries
			}
		} else if e.Stage == deviceLeaseStageRollbackIncomplete {
			// The VM exists but a legacy-attach rollback left this attach's members owned +
			// bound (the retained recovery anchor). Reclaim them via the durable-lease-
			// authorized primitive with vmExists=true: it membership-detaches each still-in-
			// guest member FIRST, then unbind + owner-scoped-release. Fail closed → RETAIN the
			// entry on any error (never remove it over a device still bound to vfio-pci); a
			// later pass retries. A BDF a DIFFERENT live VM has since reclaimed is skipped.
			slog.Warn("device-lease recovery: reclaiming rollback-incomplete lease", "vm", e.ResourceID, "devices", addrs)
			if rerr := s.reclaimLeasedDevices(ctx, e.ResourceID, addrs, true); rerr != nil {
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
