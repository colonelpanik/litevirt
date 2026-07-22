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

// RecoverDeviceLeases rolls back device leases a crash orphaned. For each durable
// device_lease journal entry: if the VM no longer exists (its allocation never
// finalized), the recorded devices are unbound + owner-scoped-released, then the
// entry is removed; if the VM exists (allocation completed but finish() didn't
// run before the crash), the entry is just cleared. Runs at daemon startup,
// before serving. Best-effort — a transient error leaves the entry for next time.
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
		} else {
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
