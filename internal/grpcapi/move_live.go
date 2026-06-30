package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// LiveMover is the boundary the live-motion orchestrator calls into.
// Production = a thin shim around internal/libvirt.Client; tests use
// a fake to exercise the orchestration logic without a real qemu.
//
// The orchestrator's job:
//
//  1. Pre-create the destination file at the right size (qemu-img
//     will receive writes via the mirror, but the file must exist).
//  2. Start the block-copy job.
//  3. Poll until cur >= end (mirror in sync).
//  4. Repoint the PERSISTENT domain config to the destination, then commit the DB
//     placement — BOTH before the pivot.
//  5. Pivot. The pivot is the irreversible commit (the guest writes to the
//     destination once it lands), so persistent config + DB are moved first and are
//     never rolled back to the source after a *successful* pivot. This ordering is
//     deliberate — do NOT "simplify" it back to pivot-then-update: that would lose
//     acknowledged post-pivot writes on a failure, or boot a restarted guest from the
//     stale source. See liveMoveVolume for the rollback/auto-pivot handling.
type LiveMover interface {
	StartBlockCopy(domain, disk, destXML string, flags uint32) error
	BlockJobStatus(domain, disk string) (LiveMoverStatus, error)
	PivotBlockCopy(domain, disk string) error
	CancelBlockCopy(domain, disk string) error
}

// LiveMoverStatus mirrors libvirt.BlockJobStatus at the gRPC layer
// boundary — keeps internal/grpcapi from importing internal/libvirt
// at the test surface.
type LiveMoverStatus struct {
	Found bool
	Cur   uint64
	End   uint64
}

// LiveMoverPollInterval controls how often the orchestrator checks
// in-flight progress. 250ms keeps emit-progress chunks frequent
// enough for a responsive UI without hammering libvirt.
var LiveMoverPollInterval = 250 * time.Millisecond

// LiveMoverPivotTimeout caps the wait for "mirror caught up". A
// healthy mirror reaches steady state in seconds for small disks;
// we abort after this so a stalled mirror doesn't block forever.
var LiveMoverPivotTimeout = 30 * time.Minute

// liveMoveVolume drives the BlockCopy → poll → pivot dance for a
// running VM. Called from moveOneVolume when vm.State == "running".
// Progress frames go through send (the caller owns the transport).
func (s *Server) liveMoveVolume(
	ctx context.Context,
	vm *corrosion.VMRecord,
	src *corrosion.DiskRecord,
	destPath string,
	targetPool string,
	dstPool StoragePoolRef,
	deleteSource bool,
	send func(*pb.MoveVolumeProgress) error,
) error {
	if s.liveMover == nil {
		return status.Error(codes.Unimplemented,
			"live storage motion requires a wired LiveMover (running VM); "+
				"set --skip-live-mover to convert via stop+offline+start")
	}
	if !isFileBasedDriver(src.StorageType) || !isFileBasedDriver(dstPool.Driver) {
		return status.Error(codes.Unimplemented,
			"live storage motion supported only between file-based pools today")
	}

	// Preflight BEFORE touching destPath: if the guest already runs on destPath — a
	// prior partial move pivoted but its DB catch-up didn't land — preallocating or
	// mirroring would CLOBBER the live disk. Catch up persistent + DB instead.
	if s.virt != nil {
		liveSrc, lerr := s.movedDiskLiveSource(vm, src, destPath)
		if lerr != nil {
			return status.Errorf(codes.Internal, "inspect active disk source: %v", lerr)
		}
		if liveSrc == destPath {
			return s.liveCatchUpAtDest(ctx, vm, src, destPath, targetPool, dstPool, deleteSource, send)
		}
	}

	// 1. Pre-create the destination. REUSE_EXT (below) makes libvirt open the
	// destination as an existing qcow2 and mirror into it, so it must be a
	// VALID qcow2 of the source's virtual size — a raw/truncated file fails
	// blockdev-add with "Image is not in qcow2 format".
	if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
		return status.Errorf(codes.Internal, "mkdir destination: %v", err)
	}
	virtualSize := src.SizeBytes
	if info, ierr := qcow2.Info(src.Path); ierr == nil && info.VirtualSize > 0 {
		virtualSize = int64(info.VirtualSize)
	}
	if err := preallocate(destPath, virtualSize); err != nil {
		return status.Errorf(codes.Internal, "preallocate destination: %v", err)
	}

	if err := send(&pb.MoveVolumeProgress{
		Phase:  pb.MoveVolumeProgress_MIRROR,
		Status: fmt.Sprintf("starting blockdev-mirror %s → %s", src.Path, destPath),
	}); err != nil {
		_ = os.Remove(destPath) // best-effort: don't leak the just-preallocated dest
		return err
	}

	// 2. Kick off the mirror.
	destXML := buildDiskXML(destPath)
	// flags = VIR_DOMAIN_BLOCK_COPY_REUSE_EXT (0x2) | _TRANSIENT_JOB (0x4).
	// These MUST match libvirt's DomainBlockCopyFlags values.
	//
	// TRANSIENT_JOB is REQUIRED, not optional: our domains are persistent
	// (DomainDefineXML), and libvirt refuses block-copy on a persistent domain
	// without it ("Requested operation is not valid: domain is not transient").
	//
	// KNOWN LIMITATION: on libvirt 10.0.0 + AppArmor this trips a virt-aa-helper
	// bug — it can't parse a transient block-copy job's <mirror> element
	// ("unknown mirror job type ''"), so the destination's security label fails
	// to apply and the mirror aborts mid-copy with "Error in input stream".
	// There is no flag that avoids both (dropping TRANSIENT_JOB makes libvirt
	// reject the copy outright), so the live path can't be fixed here for that
	// libvirt build — relax AppArmor for qemu, or use an offline stop→convert→
	// start move (MoveVolume on a stopped VM).
	const flagReuseExt = 0x2
	const flagTransientJob = 0x4
	if err := s.liveMover.StartBlockCopy(vm.Name, src.Path, destXML, flagReuseExt|flagTransientJob); err != nil {
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "start block copy: %v", err)
	}

	// 3. Poll progress.
	deadline := time.Now().Add(LiveMoverPivotTimeout)
	for {
		select {
		case <-ctx.Done():
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Error(codes.DeadlineExceeded, "mirror did not reach steady state in time")
		}
		st, err := s.liveMover.BlockJobStatus(vm.Name, src.Path)
		if err != nil {
			// A transient libvirtd hiccup mid-mirror must not orphan the
			// block-copy job (it pins the disk → "block job already active" on
			// the next op) or leak the preallocated dest. Cancel + clean up,
			// like the ctx-cancel and deadline branches (bug-sweep #5).
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal, "block job status: %v", err)
		}
		if !st.Found {
			// The job ended on its own — usually because libvirt
			// already pivoted (TRANSIENT_JOB completes when synced).
			break
		}
		var pct float32
		if st.End > 0 {
			pct = float32(st.Cur) * 100 / float32(st.End)
		}
		_ = send(&pb.MoveVolumeProgress{
			Phase:       pb.MoveVolumeProgress_MIRROR,
			CopyPct:     pct,
			BytesCopied: int64(st.Cur),
		})
		if st.Cur >= st.End && st.End > 0 {
			// Caught up — drop out of the polling loop.
			break
		}
		time.Sleep(LiveMoverPollInterval)
	}

	// 4. Cutover. The PIVOT is the irreversible commit — once it lands the guest
	// writes to dest — so we move the PERSISTENT config and the DB to dest BEFORE
	// pivoting, and never roll them back to src after a *successful* pivot. That
	// keeps the invariant: srcPath is never the durable restart path post-pivot, and
	// no acknowledged post-pivot write is lost.
	commit := func() error {
		return corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, destPath, dstPool.Driver, targetPool)
	}
	done := func() error {
		if deleteSource {
			s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		}
		return send(&pb.MoveVolumeProgress{
			Phase:       pb.MoveVolumeProgress_DONE,
			Status:      "live move complete",
			BytesCopied: src.SizeBytes,
			CopyPct:     100,
		})
	}

	// No libvirt backend (libvirt-less test context): there is no persistent config
	// to keep in sync, so fall back to pivot → commit → delete.
	if s.virt == nil {
		if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal, "pivot: %v", err)
		}
		if err := commit(); err != nil {
			return liveMovePlacementErr(err)
		}
		return done()
	}

	// After the mirror job ends, the ACTIVE disk source is the truth — libvirt may
	// end a job for reasons other than a clean pivot, so we reason from the inspected
	// source, not from job state.
	liveSrc, lerr := s.movedDiskLiveSource(vm, src, destPath)
	if lerr != nil {
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "inspect active disk source: %v", lerr)
	}

	switch liveSrc {
	case destPath:
		// Auto-pivoted during this mirror — the guest is on dest. Catch up forward-only.
		return s.liveCatchUpAtDest(ctx, vm, src, destPath, targetPool, dstPool, deleteSource, send)
	case src.Path:
		// Not pivoted yet — the safe ordering below.
	default:
		// Can't prove which path is live — abort WITHOUT destructive cleanup (don't
		// remove dst or src, don't roll back); the operator inspects.
		return status.Errorf(codes.Internal,
			"live move: active disk source %q is neither old %q nor new %q — aborting without cleanup", liveSrc, src.Path, destPath)
	}

	// Still on src. Redefine persistent → commit DB → pivot, rolling back on failure.
	cs, origXML, rerr := s.redefineMovedDiskSource(vm, src, destPath)
	if rerr != nil {
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "redefine persistent config (cutover aborted): %v", rerr)
	}
	if err := commit(); err != nil {
		// Roll persistent back; only remove the dest when it's no longer referenced
		// (rollbackCutover keeps it for the already-at-dst / rollback-failed cases).
		safe := s.rollbackCutover(cs, vm.Name, origXML)
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		if safe {
			_ = os.Remove(destPath)
		}
		return liveMovePlacementErr(err)
	}

	// Persistent + DB are now at dest. A dropped progress stream must NOT abort before
	// the pivot — that would strand the guest on src while durable state points at dest.
	// Send best-effort, then complete the cutover.
	_ = send(&pb.MoveVolumeProgress{Phase: pb.MoveVolumeProgress_CUTOVER, Status: "pivoting to destination"})
	if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
		// Pivot did not occur (guest still on src). Roll DB back to src, roll persistent
		// back (only the redefined case can; already-at-dst keeps dest), keep the source,
		// and remove the dest only if persistent no longer references it.
		if dbErr := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, src.HostName, src.Path, src.StorageType, src.StorageVolume); dbErr != nil {
			slog.Error("live move: pivot failed and DB rollback to src also failed — DB records dest but guest is on src; operator must reconcile",
				"vm", vm.Name, "disk", src.DiskName, "pivot_error", err, "db_rollback_error", dbErr)
		}
		safe := s.rollbackCutover(cs, vm.Name, origXML)
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		if safe {
			_ = os.Remove(destPath)
		}
		return status.Errorf(codes.Internal, "pivot: %v", err)
	}

	// Pivot succeeded: live=dest, persistent=dest, DB=dest all agree.
	return done()
}

// liveMovePlacementErr maps the strict UpdateDiskPlacement error to a deliberate gRPC
// code: a vanished/soft-deleted disk row → Aborted (concurrent change), else Internal.
func liveMovePlacementErr(err error) error {
	if errors.Is(err, corrosion.ErrNoRowsAffected) {
		return status.Error(codes.Aborted, "disk record changed during live move; aborted")
	}
	return status.Errorf(codes.Internal, "update disk placement: %v", err)
}

// liveCatchUpAtDest completes a live move whose guest ALREADY runs on destPath (a
// prior move pivoted — possibly auto-pivoted — without committing the DB). It is
// FORWARD-ONLY: it ensures the persistent config points at destPath, commits the DB,
// and NEVER touches destPath (the live disk) or rolls back to src. On a commit failure
// it keeps dest and surfaces a reconcile error. No block-copy job runs here.
func (s *Server) liveCatchUpAtDest(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, destPath, targetPool string, dstPool StoragePoolRef, deleteSource bool, send func(*pb.MoveVolumeProgress) error) error {
	if _, _, rerr := s.redefineMovedDiskSource(vm, src, destPath); rerr != nil {
		return status.Errorf(codes.Internal, "redefine persistent config (guest already on dest): %v", rerr)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, destPath, dstPool.Driver, targetPool); err != nil {
		slog.Error("live move: guest already on the new path but DB catch-up commit failed — leaving persistent at dest (a restart follows the post-pivot path); operator must reconcile the disk row",
			"vm", vm.Name, "disk", src.DiskName, "dest", destPath, "error", err)
		return liveMovePlacementErr(err)
	}
	if deleteSource {
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
	}
	return send(&pb.MoveVolumeProgress{
		Phase:       pb.MoveVolumeProgress_DONE,
		Status:      "live move complete (guest already on destination)",
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
	})
}

// movedDiskLiveSource returns the moved disk's CURRENT active <source file>. A row
// with a recorded target dev reads that dev; a legacy row without one resolves by
// matching either the old or new path among the live sources (returns "" when
// neither is present, so the caller treats it as indeterminate).
func (s *Server) movedDiskLiveSource(vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath string) (string, error) {
	srcs, err := s.virt.DomainDiskSources(vm.Name)
	if err != nil {
		return "", err
	}
	if src.TargetDev != "" {
		return srcs[src.TargetDev], nil
	}
	for _, v := range srcs {
		if v == src.Path || v == dstPath {
			return v, nil
		}
	}
	return "", nil
}

// preallocate creates an empty file of size bytes — `qemu-img create`
// would also work, but the truncate path is simpler and adequate for
// REUSE_EXT (libvirt fills in the qcow2 header).
// preallocate creates the destination as an empty qcow2 of the given virtual
// size. The live mirror uses REUSE_EXT, so the destination must already be a
// valid qcow2 (a raw/truncated file fails blockdev-add with "Image is not in
// qcow2 format").
func preallocate(path string, virtualSize int64) error {
	if virtualSize <= 0 {
		return fmt.Errorf("destination virtual size must be > 0")
	}
	return qcow2.Create(path, uint64(virtualSize), nil)
}

// buildDiskXML produces the small <disk> snippet libvirt's BlockCopy
// accepts as the destination. Format is qcow2 by convention since
// the rest of the file-based path uses it.
func buildDiskXML(destPath string) string {
	return fmt.Sprintf(
		`<disk type="file" device="disk"><driver name="qemu" type="qcow2"/><source file="%s"/></disk>`,
		destPath,
	)
}
