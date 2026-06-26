package grpcapi

import (
	"fmt"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// ReplicateVolume copies a VM disk into a target pool without cutting
// the VM over. The source remains the VM's authoritative disk; the
// target receives a point-in-time copy suitable for off-site DR.
//
// first cut:
//   - File-based source AND target only (local, nfs, dir, btrfs).
//   - Crash-consistent: we don't quiesce the guest. For application
//     consistency the operator should snapshot the VM first
//     (snapshot + replicate is the common pattern).
//   - Full copy every call. Incremental sync arrives with the
//     scheduler in
//
// Block backends (ceph, zfs, iscsi, lvm-thin) return Unimplemented;
// each will eventually reach for native send/receive primitives
// (rbd export-diff | rbd import-diff, zfs send | zfs recv) which
// out-perform a raw byte stream by several orders of magnitude.
func (s *Server) ReplicateVolume(req *pb.ReplicateVolumeRequest, stream grpc.ServerStreamingServer[pb.ReplicateVolumeProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.DiskName == "" || req.TargetPool == "" {
		return status.Error(codes.InvalidArgument, "vm_name, disk_name, target_pool required")
	}

	unlock := s.lockVM(req.VmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.replicate", "operator"); err != nil {
		return err
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q lives on %q; run ReplicateVolume on that host", req.VmName, vm.HostName)
	}

	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	var src *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == req.DiskName {
			src = &disks[i]
			break
		}
	}
	if src == nil {
		return status.Errorf(codes.NotFound, "vm %q has no disk %q", req.VmName, req.DiskName)
	}

	dstPool, ok := s.resolvePool(ctx, req.TargetPool)
	if !ok {
		return status.Errorf(codes.NotFound, "target pool %q not configured on this host", req.TargetPool)
	}

	// prefer native send/recv when the source driver
	// implements Replicator. Skipped for cross-driver replication
	// since e.g. zfs send / btrfs receive aren't compatible.
	if src.StorageType == dstPool.Driver {
		srcDrv, _ := storage.New(s.dataDir, storage.Config{
			Driver:  src.StorageType,
			Source:  src.StorageVolume,
			Options: dstPool.Options,
		})
		if rep := storage.AsReplicator(srcDrv); rep != nil {
			progress := func(phase pb.ReplicateVolumeProgress_Phase, statusText string) error {
				return stream.Send(&pb.ReplicateVolumeProgress{
					Phase:      phase,
					Status:     statusText,
					BytesTotal: src.SizeBytes,
				})
			}
			if err := progress(pb.ReplicateVolumeProgress_SNAPSHOT,
				fmt.Sprintf("native %s send/recv", src.StorageType)); err != nil {
				return err
			}
			if err := rep.Replicate(ctx, storage.ReplicateOptions{
				SrcRef: src.Path, DstRef: req.TargetPool,
			}); err != nil {
				return status.Errorf(codes.Internal, "native replicate: %v", err)
			}
			s.recordVMEvent(ctx, req.VmName, "disk.replicated", "ok",
				fmt.Sprintf("%s → %s", req.DiskName, req.TargetPool))
			return stream.Send(&pb.ReplicateVolumeProgress{
				Phase:      pb.ReplicateVolumeProgress_DONE,
				Status:     "native replication complete",
				TargetPath: req.TargetPool,
				BytesTotal: src.SizeBytes,
			})
		}
	}

	if !isFileBasedDriver(src.StorageType) {
		return status.Errorf(codes.Unimplemented,
			"source pool driver %q: replication not yet implemented", src.StorageType)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return status.Errorf(codes.Unimplemented,
			"target pool driver %q: replication not yet implemented", dstPool.Driver)
	}

	drv, err := storage.New(s.dataDir, storage.Config{
		Driver:  dstPool.Driver,
		Source:  dstPool.Source,
		Target:  dstPool.Target,
		Options: dstPool.Options,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "construct target driver: %v", err)
	}
	if err := drv.Prepare(ctx); err != nil {
		return status.Errorf(codes.FailedPrecondition, "prepare target pool: %v", err)
	}

	dstDir, err := fileBasedPoolDir(s.dataDir, dstPool)
	if err != nil {
		return status.Errorf(codes.Internal, "resolve target dir: %v", err)
	}
	// target_path: empty → the auto-derived "<vm>-<disk>.qcow2" under the pool
	// dir; a bare filename is contained under the pool dir; a custom absolute
	// path is admin-only (same policy as restore destinations).
	var dstPath string
	if req.TargetPath == "" {
		dstPath = filepath.Join(dstDir, fmt.Sprintf("%s-%s.qcow2", req.VmName, req.DiskName))
	} else {
		dstPath, err = s.resolveRestoreTarget(ctx, req.TargetPath, dstDir)
		if err != nil {
			return err
		}
	}
	if dstPath == src.Path {
		return status.Error(codes.FailedPrecondition, "source and destination resolve to the same path")
	}
	if err := refuseSymlinkTarget(dstPath); err != nil {
		return err
	}

	send := func(p *pb.ReplicateVolumeProgress) error {
		p.BytesTotal = src.SizeBytes
		return stream.Send(p)
	}

	if err := send(&pb.ReplicateVolumeProgress{
		Phase:  pb.ReplicateVolumeProgress_SNAPSHOT,
		Status: "skipping in-guest quiesce; copy is crash-consistent",
	}); err != nil {
		return err
	}

	// Reuse the qemu-img convert helper; the only difference vs MoveVolume
	// is that we don't update the VM's disk record afterwards.
	emit := func(p *pb.MoveVolumeProgress) error {
		return send(&pb.ReplicateVolumeProgress{
			Phase:       pb.ReplicateVolumeProgress_COPY,
			CopyPct:     p.CopyPct,
			BytesCopied: p.BytesCopied,
		})
	}
	if err := convertQcow2(ctx, src.Path, dstPath, emit); err != nil {
		return status.Errorf(codes.Internal, "qemu-img convert: %v", err)
	}

	s.recordVMEvent(ctx, req.VmName, "disk.replicated", "ok",
		fmt.Sprintf("%s → %s", req.DiskName, req.TargetPool))
	return send(&pb.ReplicateVolumeProgress{
		Phase:       pb.ReplicateVolumeProgress_DONE,
		Status:      "replication complete",
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
		TargetPath:  dstPath,
	})
}
