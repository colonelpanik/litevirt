package grpcapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// MoveVolume copies a single VM disk from its current pool to target_pool
// on the same host, then updates the libvirt source so qemu reads from
// the new path. Cross-host moves use MigrateVM(with_storage=true).
//
// scope: file-based pools only (local, nfs, dir, btrfs).
// Block backends (ceph, zfs, iscsi, lvm-thin) require backend-specific
// copy primitives — they return Unimplemented until the corresponding
// driver Mover lands.
//
// Live (running-VM) cutover is wired: a running VM routes to liveMoveVolume
// (libvirt block-copy → pivot, see move_live.go); a stopped VM does an offline
// copy. Only the block-backend gap above remains.
func (s *Server) MoveVolume(req *pb.MoveVolumeRequest, stream grpc.ServerStreamingServer[pb.MoveVolumeProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.DiskName == "" || req.TargetPool == "" {
		return status.Error(codes.InvalidArgument, "vm_name, disk_name, target_pool required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.move", "operator"); err != nil {
		return err
	}
	// MoveVolume runs on the host owning the VM (it touches local disk files).
	// If we're not that host, forward to the owner and relay its progress, so
	// any daemon — e.g. the one serving the UI/CLI — can drive the move.
	if vm.HostName != s.hostName {
		client, conn, perr := s.peerClient(ctx, vm.HostName)
		if perr != nil {
			return status.Errorf(codes.FailedPrecondition, "reach host %q owning vm %q: %v", vm.HostName, req.VmName, perr)
		}
		defer conn.Close()
		rs, perr := client.MoveVolume(ctx, req)
		if perr != nil {
			return perr
		}
		for {
			frame, rerr := rs.Recv()
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			if rerr != nil {
				return rerr
			}
			if serr := stream.Send(frame); serr != nil {
				return serr
			}
		}
	}

	unlock := s.lockVM(req.VmName)
	defer unlock()

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
	if src.StorageVolume == req.TargetPool {
		// Idempotent no-op: the disk is already where the caller asked for it
		// (e.g. re-running a move that already completed). Emit a terminal
		// success frame instead of FailedPrecondition so the UI/CLI shows
		// "done", not "failed", for a move whose desired end-state already holds.
		return stream.Send(&pb.MoveVolumeProgress{
			Phase:      pb.MoveVolumeProgress_DONE,
			Status:     fmt.Sprintf("disk %q is already in pool %q — nothing to do", req.DiskName, req.TargetPool),
			CopyPct:    100,
			BytesTotal: src.SizeBytes,
		})
	}

	return s.moveOneVolume(ctx, vm, src, req.TargetPool, req.DeleteSource, stream.Send)
}

// moveOneVolume performs a single disk's pool-to-pool motion for a VM the
// daemon owns locally. It is the shared core behind the MoveVolume RPC and
// the MigrateStackVolumes orchestrator (which calls it directly for local
// VMs and via a peer MoveVolume RPC for remote ones). Progress frames are
// delivered through send; the caller owns the transport — a raw gRPC
// stream.Send for MoveVolume, a translating closure for MigrateStackVolumes.
//
// Precondition: vm.HostName == s.hostName — it touches local disk files.
func (s *Server) moveOneVolume(
	ctx context.Context,
	vm *corrosion.VMRecord,
	src *corrosion.DiskRecord,
	targetPool string,
	deleteSource bool,
	send func(*pb.MoveVolumeProgress) error,
) error {
	dstPool, ok := s.lookupStoragePool(targetPool)
	if !ok {
		return status.Errorf(codes.NotFound, "target pool %q not configured on host %q", targetPool, s.hostName)
	}
	if !isFileBasedDriver(src.StorageType) {
		return status.Errorf(codes.Unimplemented,
			"source pool driver %q: storage motion not yet implemented", src.StorageType)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return status.Errorf(codes.Unimplemented,
			"target pool driver %q: storage motion not yet implemented", dstPool.Driver)
	}

	// Resolve the destination directory. We piggyback on the storage
	// driver's Prepare to ensure it's mounted/ready, then derive a
	// per-VM filename.
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
	dstPath := filepath.Join(dstDir, fmt.Sprintf("%s-%s.qcow2", vm.Name, src.DiskName))
	if dstPath == src.Path {
		return status.Error(codes.FailedPrecondition, "source and destination resolve to the same path")
	}

	// Every frame carries the disk's total size for the caller's bar.
	totalBytes := src.SizeBytes
	emit := func(p *pb.MoveVolumeProgress) error {
		p.BytesTotal = totalBytes
		return send(p)
	}

	// running VMs go through libvirt blockdev-mirror so
	// the disk swap is online. Stopped VMs use the simpler offline
	// qemu-img convert path below — still atomic at the DB layer.
	if vm.State == "running" {
		if err := s.liveMoveVolume(ctx, vm, src, dstPath, targetPool, dstPool, deleteSource, emit); err != nil {
			return err
		}
		s.syncStackComposeForMovedDisk(ctx, vm, src.DiskName, targetPool)
		s.recordVMEvent(ctx, vm.Name, "disk.moved", "ok",
			fmt.Sprintf("%s: %s → %s", src.DiskName, poolLabel(src.StorageVolume), targetPool))
		return nil
	}

	if err := emit(&pb.MoveVolumeProgress{
		Phase:  pb.MoveVolumeProgress_COPY,
		Status: fmt.Sprintf("copying %s → %s", src.Path, dstPath),
	}); err != nil {
		return err
	}

	if err := convertQcow2(ctx, src.Path, dstPath, emit); err != nil {
		// Best-effort cleanup of partial output.
		_ = os.Remove(dstPath)
		return status.Errorf(codes.Internal, "qemu-img convert: %v", err)
	}

	// Update DB: point the disk record at the new path/pool.
	if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, vm.Name, src.DiskName, vm.HostName, dstPath); err != nil {
		return status.Errorf(codes.Internal, "update disk record: %v", err)
	}
	if err := corrosion.UpdateDiskStorage(ctx, s.db, vm.Name, src.DiskName, dstPool.Driver, targetPool); err != nil {
		return status.Errorf(codes.Internal, "update disk storage pool: %v", err)
	}
	// Point the persistent libvirt domain at the new path. The live path gets
	// this from the blockdev-mirror pivot; the offline (stopped-VM) path must
	// rewrite the inactive domain's <source file>, or the VM fails to start
	// with "Cannot access storage file" at the moved-away (and deleted) path.
	if s.virt != nil {
		if xml, derr := s.virt.DumpXML(vm.Name); derr != nil {
			slog.Warn("move: dump domain xml for redefine — VM may not start until redefined",
				"vm", vm.Name, "error", derr)
		} else if updated := strings.ReplaceAll(xml, src.Path, dstPath); updated != xml {
			if derr := s.virt.DefineDomain(updated); derr != nil {
				slog.Warn("move: redefine domain with new disk path",
					"vm", vm.Name, "old", src.Path, "new", dstPath, "error", derr)
			}
		}
	}
	s.syncStackComposeForMovedDisk(ctx, vm, src.DiskName, targetPool)

	if err := emit(&pb.MoveVolumeProgress{
		Phase: pb.MoveVolumeProgress_CUTOVER, Status: "disk record updated",
	}); err != nil {
		return err
	}

	if deleteSource {
		s.deleteSourceIfUnreferenced(ctx, vm, src, emit)
	}

	s.recordVMEvent(ctx, vm.Name, "disk.moved", "ok",
		fmt.Sprintf("%s: %s → %s", src.DiskName, poolLabel(src.StorageVolume), targetPool))
	return emit(&pb.MoveVolumeProgress{
		Phase:       pb.MoveVolumeProgress_DONE,
		Status:      "move complete",
		BytesCopied: totalBytes,
		CopyPct:     100,
	})
}

// deleteSourceIfUnreferenced removes the moved disk's old file after a
// successful cutover — but ONLY if no other disk still references that exact
// path, either as its own file or as a backing image. This guards against the
// destructive case the bare os.Remove had: the source being a shared disk or a
// base image other overlays depend on. Best-effort: a skipped, failed, or
// unverifiable delete is reported via send and logged, never fatal — the move
// itself already succeeded and the disk is live on the new pool.
// pathStillReferenced reports whether the disk file at `path` is still needed by
// something OTHER than (excludeVM, excludeDisk): another VM's disk at that path,
// a disk using it as a backing_image, OR a linked clone whose backing_disk
// points at it (which DisksReferencingPath does NOT check). Returns a
// human-readable reason for logging. On a query error it returns referenced=true
// so callers keep the file rather than risk deleting one still in use.
//
// Shared by the storage-motion delete path and the post-migration source-disk
// cleanup — both must never os.Remove a file that backs a linked clone or
// another VM (the bug-sweep found migrate deleting a clone's backing chain).
func (s *Server) pathStillReferenced(ctx context.Context, path, excludeVM, excludeDisk string) (bool, string, error) {
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return true, "usage check failed: " + err.Error(), err
	}
	for _, d := range refs {
		if d.VMName == excludeVM && d.DiskName == excludeDisk {
			continue // the disk being moved/migrated (record repointed)
		}
		rel := "disk file"
		if d.BackingImage == path {
			rel = "backing image"
		}
		return true, fmt.Sprintf("%s/%s (as %s)", d.VMName, d.DiskName, rel), nil
	}
	clones, err := corrosion.LinkedCloneNames(ctx, s.db, path)
	if err != nil {
		return true, "linked-clone check failed: " + err.Error(), err
	}
	for _, c := range clones {
		if c != excludeVM {
			return true, "linked clone " + c, nil
		}
	}
	return false, "", nil
}

func (s *Server) deleteSourceIfUnreferenced(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, send func(*pb.MoveVolumeProgress) error) {
	referenced, reason, err := s.pathStillReferenced(ctx, src.Path, vm.Name, src.DiskName)
	if err != nil {
		// Couldn't verify — keep the source rather than risk deleting a
		// file still in use. The operator can remove it manually.
		slog.Warn("move: source-usage check failed; keeping source disk", "path", src.Path, "error", err)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source kept (usage check failed): " + err.Error(),
		})
		return
	}
	if referenced {
		slog.Warn("move: source disk still referenced — NOT deleting", "path", src.Path, "referenced_by", reason)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source NOT deleted — still referenced by " + reason,
		})
		return
	}
	if err := os.Remove(src.Path); err != nil {
		slog.Warn("move: delete source after move", "path", src.Path, "error", err)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source remove failed: " + err.Error(),
		})
		return
	}
	_ = send(&pb.MoveVolumeProgress{
		Phase:  pb.MoveVolumeProgress_CLEANUP,
		Status: "source removed: " + src.Path,
	})
}

// deleteRecordedVMDiskVolumes frees every disk a VM owns at its RECORDED
// location, dispatched through that disk's storage driver. This is what makes
// VM deletion honour non-default pools: a disk relocated by MoveVolume, or one
// living on a ceph/zfs/lvm-thin/iscsi/nfs/dir backend, is actually released
// instead of orphaned. (The default-dir glob in Store.DeleteVMDisks only ever
// saw <dataDir>/disks/<vm>-*.qcow2, so anything elsewhere leaked.)
//
// It mirrors MoveVolume's driver resolution and reuses the same shared-disk
// guard as deleteSourceIfUnreferenced, so a disk path still referenced by
// another VM (shared volume / backing image) is never removed. Best-effort:
// every failure is logged, never fatal — VM teardown must still complete.
//
// Callers MUST invoke this BEFORE tombstoning the VM's corrosion records, since
// it reads vm_disks. The glob-based Store.DeleteVMDisks remains as the fallback
// for default-dir / cloud-init debris not represented in vm_disks.
func (s *Server) deleteRecordedVMDiskVolumes(ctx context.Context, vmName string) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("delete: list disks for volume cleanup — falling back to default-dir glob only",
			"vm", vmName, "error", err)
		return
	}
	for i := range disks {
		d := &disks[i]
		if d.Path == "" {
			continue
		}
		if s.diskPathReferencedByOtherVM(ctx, vmName, d) {
			continue
		}
		if err := s.deleteDiskAtRecordedLocation(ctx, d); err != nil {
			slog.Warn("delete: free disk volume",
				"vm", vmName, "disk", d.DiskName, "path", d.Path,
				"storage_type", d.StorageType, "pool", poolLabel(d.StorageVolume), "error", err)
		}
	}
}

// deleteDiskAtRecordedLocation resolves the storage driver for a disk's pool
// and asks it to delete the disk at its recorded path. For file-based pools
// (local/dir/nfs/btrfs) the driver does os.Remove; for block/object backends
// it runs the backend primitive (ceph rbd rm, zfs destroy, lvremove). When the
// disk names a configured pool we use that pool's full config (Source/Options
// matter for ceph); otherwise we fall back to the recorded StorageType, and to
// "local" when even that is blank (legacy rows).
func (s *Server) deleteDiskAtRecordedLocation(ctx context.Context, d *corrosion.DiskRecord) error {
	cfg := storage.Config{Driver: d.StorageType}
	if pool, ok := s.lookupStoragePool(d.StorageVolume); ok {
		cfg = storage.Config{Driver: pool.Driver, Source: pool.Source, Target: pool.Target, Options: pool.Options}
	}
	if cfg.Driver == "" {
		cfg.Driver = "local"
	}
	drv, err := storage.New(s.dataDir, cfg)
	if err != nil {
		return fmt.Errorf("construct %s driver: %w", cfg.Driver, err)
	}
	return drv.DeleteDisk(ctx, d.Path)
}

// diskPathReferencedByOtherVM reports whether a disk's path is still in use by a
// VM other than vmName — as either a disk file or another disk's backing image.
// If so (or if the check itself fails) the caller must keep the file: deleting a
// shared volume or a base image other overlays depend on would be destructive.
func (s *Server) diskPathReferencedByOtherVM(ctx context.Context, vmName string, d *corrosion.DiskRecord) bool {
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, d.Path)
	if err != nil {
		slog.Warn("delete: shared-disk check failed; keeping disk to avoid removing a shared volume",
			"vm", vmName, "disk", d.DiskName, "path", d.Path, "error", err)
		return true
	}
	for _, r := range refs {
		if r.VMName == vmName {
			continue // our own record(s) for this VM
		}
		rel := "disk file"
		if r.BackingImage == d.Path {
			rel = "backing image"
		}
		slog.Warn("delete: disk path still referenced by another VM — NOT deleting",
			"vm", vmName, "path", d.Path,
			"referenced_by_vm", r.VMName, "referenced_by_disk", r.DiskName, "as", rel)
		return true
	}
	return false
}

// syncStackComposeForMovedDisk keeps a stack's stored compose YAML in sync with
// a disk's new pool after a move, so `lv stack export` / the UI Export reflect
// the change and a re-deploy is idempotent (rather than reverting the disk).
// No-op for VMs not in a stack. Best-effort: failures are logged, not fatal —
// the disk move itself already succeeded.
func (s *Server) syncStackComposeForMovedDisk(ctx context.Context, vm *corrosion.VMRecord, diskName, pool string) {
	if vm.StackName == "" {
		return
	}
	st, err := corrosion.GetStack(ctx, s.db, vm.StackName)
	if err != nil || st == nil || st.ComposeYAML == "" {
		return
	}
	f, perr := compose.ParseBytes([]byte(st.ComposeYAML))
	if perr != nil {
		slog.Warn("move: parse stack compose for sync", "stack", st.Name, "error", perr)
		return
	}
	def, vmKey := compose.FindVMDef(f, vm.Name)
	if def == nil || vmKey == "" {
		return
	}
	if def.EffectiveReplicas() > 1 {
		// Per-replica pool placement can't be expressed in a shared compose def;
		// leave the YAML alone rather than rewriting every replica's pool.
		slog.Info("move: stack VM is replicated — compose YAML not patched (per-replica pool not expressible)",
			"stack", st.Name, "vm", vm.Name)
		return
	}
	updated, changed, perr := compose.PatchDiskStorage(st.ComposeYAML, vmKey, diskName, pool)
	if perr != nil {
		slog.Warn("move: patch stack compose yaml", "stack", st.Name, "vm", vm.Name, "error", perr)
		return
	}
	if !changed {
		return
	}
	st.ComposeYAML = updated
	st.ComposeHash = fmt.Sprintf("%x", sha256.Sum256([]byte(updated)))
	if err := corrosion.UpsertStack(ctx, s.db, *st); err != nil {
		slog.Warn("move: upsert stack after compose patch", "stack", st.Name, "error", err)
		return
	}
	slog.Info("move: synced stack compose YAML with disk pool change",
		"stack", st.Name, "vm", vm.Name, "disk", diskName, "pool", pool)
}

// poolLabel renders a storage-pool name for display, mapping the unnamed
// default pool ("") to "default".
func poolLabel(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

// isFileBasedDriver reports whether a storage driver returns plain file
// paths (rather than block devices or rbd:// identifiers). Only those
// can be moved with qemu-img convert today.
func isFileBasedDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "nfs", "dir", "btrfs":
		return true
	}
	return false
}

// fileBasedPoolDir resolves the on-disk directory used by a file-based
// driver. NFS pools are mounted at <dataDir>/mounts/<safe-source> by
// default; local/dir use the explicit Target or <dataDir>/disks.
func fileBasedPoolDir(dataDir string, p StoragePoolRef) (string, error) {
	switch strings.ToLower(p.Driver) {
	case "", "local":
		if p.Target != "" {
			return p.Target, nil
		}
		return filepath.Join(dataDir, "disks"), nil
	case "dir":
		if p.Target == "" {
			return "", errors.New("dir pool missing Target")
		}
		return p.Target, nil
	case "nfs":
		if p.Target != "" {
			return p.Target, nil
		}
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(p.Source)
		return filepath.Join(dataDir, "mounts", safe), nil
	case "btrfs":
		// btrfs CreateDisk would create a per-VM subvolume — for motion
		// we land the qcow2 directly in Source; subvolume management
		// is the operator's call.
		return p.Source, nil
	}
	return "", fmt.Errorf("driver %q: not a file-based pool", p.Driver)
}

// convertQcow2 invokes qemu-img convert -p (progress on stdout). We parse
// "(NN.NN/100%)" lines and forward them as progress chunks. If qemu-img
// is missing we fall back to a simple file copy.
// qemuImgAvailable reports whether qemu-img is on PATH. Callers that would
// otherwise fall back to a verbatim byte copy must NOT do so for a raw source
// (the copy would land raw bytes in a qcow2-declared file) — see promote.
func qemuImgAvailable() bool {
	_, err := exec.LookPath("qemu-img")
	return err == nil
}

func convertQcow2(ctx context.Context, src, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		return copyFileWithProgress(ctx, src, dst, emit)
	}
	// -U (force-share) lets us read a source image a running VM holds open —
	// required for crash-consistent replication/move of a live disk; harmless
	// for an offline (stopped) source.
	cmd := exec.CommandContext(ctx, "qemu-img", "convert", "-U", "-p", "-O", "qcow2", src, dst)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 256)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 {
			pct := parseQemuImgProgress(string(buf[:n]))
			if pct >= 0 {
				_ = emit(&pb.MoveVolumeProgress{
					Phase:   pb.MoveVolumeProgress_COPY,
					CopyPct: pct,
				})
			}
		}
		if rerr != nil {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// parseQemuImgProgress extracts "    (12.34/100%)" → 12.34. Returns -1
// when no progress token is present.
func parseQemuImgProgress(s string) float32 {
	i := strings.LastIndex(s, "(")
	j := strings.LastIndex(s, "/100%")
	if i < 0 || j < 0 || j <= i {
		return -1
	}
	var pct float32
	_, err := fmt.Sscanf(s[i+1:j], "%f", &pct)
	if err != nil {
		return -1
	}
	return pct
}

// copyFileWithProgress is the fallback when qemu-img is unavailable
// (e.g. test environments). Less efficient than qemu-img convert
// because it doesn't drop sparse holes, but functionally correct.
func copyFileWithProgress(ctx context.Context, src, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	total := st.Size()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 1<<20)
	var copied int64
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			copied += int64(n)
			if time.Since(last) > 250*time.Millisecond {
				last = time.Now()
				pct := float32(0)
				if total > 0 {
					pct = float32(copied) * 100 / float32(total)
				}
				_ = emit(&pb.MoveVolumeProgress{
					Phase:       pb.MoveVolumeProgress_COPY,
					CopyPct:     pct,
					BytesCopied: copied,
				})
			}
		}
		if rerr == io.EOF {
			// Flush to stable storage before reporting the copy complete — a
			// crash here must not leave a truncated disk that looks done (F7).
			if err := out.Sync(); err != nil {
				return fmt.Errorf("sync destination: %w", err)
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// _ touches the context import used only when qemu-img is present.
var _ context.Context
