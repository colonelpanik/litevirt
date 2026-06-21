package grpcapi

import (
	"context"
	"fmt"
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
//  4. Pivot atomically.
//  5. Update DB to point the disk record at the new path.
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

	// 4. Pivot atomically.
	if err := send(&pb.MoveVolumeProgress{
		Phase: pb.MoveVolumeProgress_CUTOVER, Status: "pivoting to destination",
	}); err != nil {
		return err
	}
	if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
		// At this point the mirror is in sync but the pivot failed.
		// Best we can do is cancel and surface the error; the VM
		// continues using the original disk so no data loss. Remove the
		// now-orphaned destination so a failed pivot doesn't strand a file.
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "pivot: %v", err)
	}

	// 5. DB updates — point the disk at the new path.
	if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, vm.Name, src.DiskName, vm.HostName, destPath); err != nil {
		return status.Errorf(codes.Internal, "update disk path: %v", err)
	}
	if err := corrosion.UpdateDiskStorage(ctx, s.db, vm.Name, src.DiskName, dstPool.Driver, targetPool); err != nil {
		return status.Errorf(codes.Internal, "update disk storage: %v", err)
	}

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
