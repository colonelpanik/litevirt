package grpcapi

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// diskStem strips a disk path's file extension. litevirt names a data disk
// <dir>/<vm>-<disk>.qcow2, and libvirt names its external-snapshot overlays
// <dir>/<vm>-<disk>.<snapname> (same dir + stem, only the extension swapped),
// so the stem is the disk's stable identity across snapshot operations.
func diskStem(p string) string {
	return strings.TrimSuffix(p, filepath.Ext(p))
}

// reconcileDiskPaths syncs the recorded vm_disks.path to the live domain's
// active disk sources. A snapshot create/revert/delete cuts the domain over to
// an overlay (<disk>.<snapname>), and libvirt consolidates the chain on delete,
// leaving the active disk named after a (possibly deleted) snapshot. Without
// reconciliation the recorded path diverges from reality and backup, migration,
// and restart-from-record all use a stale or absent path (the observed bug:
// "no disk with source …qcow2 in domain" + a leaked overlay on VM delete).
//
// Best-effort and must run on the VM's host (where s.virt is the right libvirt).
// A failure only leaves the path stale — the prior behaviour — and never
// touches disk contents. Matching is by filename stem so it holds whether the
// extension is .qcow2 (canonical) or .<snapname> (overlay).
func (s *Server) reconcileDiskPaths(ctx context.Context, vmName string) {
	if s.virt == nil || s.db == nil {
		return
	}
	live, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		slog.Warn("snapshot: read live disk sources for reconcile failed", "vm", vmName, "error", err)
		return
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return
	}
	liveByStem := make(map[string]string, len(live))
	for _, src := range live {
		liveByStem[diskStem(src)] = src
	}
	for _, d := range disks {
		src, ok := liveByStem[diskStem(d.Path)]
		if !ok || src == d.Path {
			continue
		}
		if err := corrosion.UpdateVMDiskPath(ctx, s.db, vmName, d.DiskName, src); err != nil {
			slog.Warn("snapshot: reconcile disk path failed", "vm", vmName, "disk", d.DiskName, "error", err)
			continue
		}
		slog.Info("snapshot: reconciled disk path to live source",
			"vm", vmName, "disk", d.DiskName, "from", d.Path, "to", src)
	}
}
