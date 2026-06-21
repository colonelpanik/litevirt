package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// BackupSnapshot streams a VM disk into a host-local backup repo.
// only the daemon-you-call-with-LV_HOST does work; if
// the VM lives on a different host, FailedPrecondition tells the
// operator which host to retry against. Cross-host disk streaming
// is a follow-up (would need a peer streaming primitive).
func (s *Server) BackupSnapshot(req *pb.BackupSnapshotRequest, stream grpc.ServerStreamingServer[pb.BackupSnapshotProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.RepoPath == "" {
		return status.Error(codes.InvalidArgument, "vm_name and repo_path required")
	}
	unlock := s.lockVM(req.VmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "backup.create", "operator"); err != nil {
		return err
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q lives on host %q; re-run against that daemon (set LV_HOST)",
			req.VmName, vm.HostName)
	}

	disk, err := pickDisk(ctx, s.db, req.VmName, req.DiskName)
	if err != nil {
		return err
	}

	repo, err := pbsstore.Open(req.RepoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo %q: %v", req.RepoPath, err)
	}

	timestamp := req.Timestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Snoop the running bytes_read off the COPY frames so the DONE frame
	// reports the total — the at-a-glance proof of how much read I/O the
	// dirty bitmap / allocation map saved.
	var lastBytesRead int64
	send := func(p *pb.BackupSnapshotProgress) error {
		if p.BytesRead > lastBytesRead {
			lastBytesRead = p.BytesRead
		}
		return stream.Send(p)
	}
	statusMsg := fmt.Sprintf("backing up %s/%s → %s", req.VmName, disk.DiskName, req.RepoPath)
	if err := send(&pb.BackupSnapshotProgress{
		Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
		Status: statusMsg,
	}); err != nil {
		return err
	}

	s.recordVMEvent(ctx, req.VmName, "backup.started", "ok", "manual → "+req.RepoPath)
	manifest, err := s.pushBackup(ctx, repo, disk, req, timestamp, send, vm.Spec)
	if err != nil {
		s.recordVMEvent(ctx, req.VmName, "backup.failed", "error", err.Error())
		s.notify(ctx, notify.Notification{
			Kind: "backup.failed", Severity: notify.SevError, Subject: req.VmName, Detail: err.Error(),
		})
		return err
	}
	s.recordBackupUsage(ctx, req.VmName, disk.DiskName, req.RepoPath, manifest.TotalSize)
	s.recordVMEvent(ctx, req.VmName, "backup.succeeded", "ok",
		fmt.Sprintf("manual → %s @ %s", req.RepoPath, manifest.Timestamp))
	return send(&pb.BackupSnapshotProgress{
		Phase:          pb.BackupSnapshotProgress_DONE,
		ManifestTs:     manifest.Timestamp,
		ChunksTotal:    int32(len(manifest.Chunks)),
		BytesProcessed: manifest.TotalSize,
		BytesRead:      lastBytesRead,
		Status:         fmt.Sprintf("snapshot stored at %s", manifest.Timestamp),
	})
}

// pushBackup dispatches on req.Incremental:
//
//   - full (incremental=false OR no parent manifest available):
//     PushFile reads the whole disk, dedup happens via the chunk
//     store's content addressing.
//   - incremental + parent + bitmap: PushIncremental reuses the
//     parent's chunk refs for clean regions and only reads dirty
//     bytes off disk.
//   - incremental + parent + NO bitmap: PushIncremental with the
//     AlwaysDirty bitmap. Manifest chain integrity is preserved and
//     the chunk store still dedups, but no read I/O is saved. The
//     status message tells the operator why.
//
// Returning the resolved manifest lets the caller emit the DONE
// progress frame with chunk counts the operator expects.
func (s *Server) pushBackup(
	ctx context.Context,
	repo *pbsstore.Repo,
	disk *corrosion.DiskRecord,
	req *pb.BackupSnapshotRequest,
	timestamp string,
	send func(*pb.BackupSnapshotProgress) error,
	vmSpecJSON string,
) (*pbsstore.Manifest, error) {
	progress := func(p pbsstore.PushProgress) {
		_ = send(&pb.BackupSnapshotProgress{
			Phase:          pb.BackupSnapshotProgress_COPY,
			BytesProcessed: p.BytesProcessed,
			BytesNew:       p.BytesNew,
			BytesRead:      p.BytesRead,
			ChunksTotal:    int32(p.ChunksTotal),
			ChunksDeduped:  int32(p.ChunksDeduped),
		})
	}
	opts := pbsstore.PushOptions{
		VMName: req.VmName, DiskName: disk.DiskName,
		Timestamp: timestamp, Progress: progress,
	}
	// Embed the VM spec on the root-disk manifest so a live restore can
	// auto-define the domain without the source cluster (the spec already
	// enumerates every disk, so capturing it once avoids duplication).
	if disk.DiskName == "root" {
		opts.VMSpecJSON = vmSpecJSON
		if s.virt != nil {
			if xml, err := s.virt.DumpXML(req.VmName); err == nil {
				opts.DomainXML = xml
			}
		}
	}

	// Legacy fallback: no guest-content backup engine wired (e.g. no
	// libvirt). Back up the qcow2 container file. Correct for a full
	// backup; an incremental degrades to a full container backup.
	if s.backupSource == nil {
		if err := containerBackupUnsupported(disk); err != nil {
			return nil, err
		}
		m, err := pbsstore.PushFile(ctx, repo, disk.Path, opts)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "push: %v", err)
		}
		return m, nil
	}

	// Resolve the parent manifest + the checkpoint it established, so an
	// incremental can diff against it.
	var parent *pbsstore.Manifest
	var parentCP string
	if req.Incremental {
		p, ok, err := repo.LatestManifestFor(req.VmName, disk.DiskName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "lookup parent manifest: %v", err)
		}
		if ok {
			parent = p
			parentCP = p.BitmapName
		} else {
			_ = send(&pb.BackupSnapshotProgress{
				Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
				Status: "no parent manifest in repo — first incremental is a full backup",
			})
		}
	}

	newCP := checkpointName(disk.DiskName, timestamp)
	opts.BitmapName = newCP

	// Open a pull-mode backup session reading GUEST content over NBD.
	// Incremental iff we have a parent checkpoint to diff against.
	incrCP := ""
	if parent != nil && parentCP != "" {
		incrCP = parentCP
	}
	// Application-consistent backup (#2): freeze guest filesystems via the
	// qemu-guest-agent so the point-in-time the pull-mode session establishes is
	// app-consistent. Thaw as soon as BeginBackup returns (the NBD export then
	// holds a stable snapshot) so the guest is frozen only for that brief window.
	// A freeze failure never fails the backup — we log and proceed crash-consistent.
	froze := false
	if s.backupQuiesceWanted(req.Quiesce, vmSpecJSON) {
		if ferr := s.virt.FreezeGuest(req.VmName); ferr != nil {
			_ = send(&pb.BackupSnapshotProgress{
				Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
				Status: fmt.Sprintf("guest quiesce unavailable (%v) — proceeding crash-consistent", ferr),
			})
		} else {
			froze = true
			_ = send(&pb.BackupSnapshotProgress{
				Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
				Status: "guest filesystems frozen (application-consistent)",
			})
		}
	}
	session, err := s.backupSource.BeginBackup(req.VmName, disk.Path, incrCP, newCP)
	if froze {
		if terr := s.virt.ThawGuest(req.VmName); terr != nil {
			slog.Warn("backup: fs-thaw failed after begin", "vm", req.VmName, "error", terr)
		}
	}
	if err != nil {
		// Can't open a guest-content session (stopped VM, parent
		// checkpoint gone, old libvirt). Fall back to a full container
		// backup so the operator still gets a correct backup.
		// A container PushFile can only stand in for guest-content backup on
		// file-based pools; for a block/object backend (e.g. a stopped ceph
		// VM) there is no openable container, so surface that instead of
		// failing obscurely in os.Open / silently raw-reading a block device.
		if guardErr := containerBackupUnsupported(disk); guardErr != nil {
			return nil, guardErr
		}
		_ = send(&pb.BackupSnapshotProgress{
			Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
			Status: fmt.Sprintf("guest-content backup unavailable (%v) — full container backup", err),
		})
		opts.BitmapName = ""
		m, perr := pbsstore.PushFile(ctx, repo, disk.Path, opts)
		if perr != nil {
			return nil, status.Errorf(codes.Internal, "push: %v", perr)
		}
		return m, nil
	}
	defer session.Close()

	extents, err := session.ChangedExtents()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "enumerate changed regions: %v", err)
	}

	// Full session → parent=nil (sparse full); incremental → inherit clean
	// regions from the parent.
	var inheritFrom *pbsstore.Manifest
	mode := "full"
	if session.Incremental() {
		inheritFrom = parent
		mode = "incremental"
	} else if req.Incremental {
		mode = "incremental→full (no usable parent checkpoint)"
	}
	_ = send(&pb.BackupSnapshotProgress{
		Phase:  pb.BackupSnapshotProgress_SNAPSHOT,
		Status: fmt.Sprintf("%s guest-content backup: %d changed extent(s)", mode, len(extents)),
	})

	m, err := pbsstore.PushFromSource(ctx, repo, session, session.Size(), extents, inheritFrom, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "push: %v", err)
	}

	// Prune checkpoints no surviving manifest references.
	if err := s.backupSource.GCCheckpoints(req.VmName, disk.DiskName, keepBitmapNames(repo, req.VmName, disk.DiskName)); err != nil {
		_ = send(&pb.BackupSnapshotProgress{
			Phase: pb.BackupSnapshotProgress_SNAPSHOT, Status: fmt.Sprintf("checkpoint GC warning: %v", err),
		})
	}
	return m, nil
}

// backupQuiesceWanted reports whether to attempt an in-guest filesystem freeze
// for this backup (#2). "off" disables it; "auto"/"" freeze only when the VM
// advertises a guest agent and a libvirt backend is wired. The freeze itself is
// still best-effort — a failure downgrades to crash-consistent.
func (s *Server) backupQuiesceWanted(quiesce, vmSpecJSON string) bool {
	if quiesce == "off" || s.virt == nil || vmSpecJSON == "" {
		return false
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vmSpecJSON), &spec); err != nil {
		return false
	}
	return spec.GuestAgent
}

// recordBackupUsage best-effort updates the per-VM backup-size index
// (vm_backups) that the tenancy backup_gib quota sums. Never fatal: a backup
// that already succeeded must not be reported as failed because the usage-index
// write did.
func (s *Server) recordBackupUsage(ctx context.Context, vm, disk, repo string, totalBytes int64) {
	if err := corrosion.UpsertVMBackup(ctx, s.db, vm, disk, repo, totalBytes); err != nil {
		slog.Warn("backup: update vm_backups usage index",
			"vm", vm, "disk", disk, "repo", repo, "error", err)
	}
}

// containerBackupUnsupported reports whether a disk can be backed up by reading
// its path as a container file (the PushFile fallback). That only works for
// file-based pools (local/dir/nfs/btrfs); for block/object backends
// (ceph/zfs/lvm-thin/iscsi) the recorded path is not an openable qcow2, so a
// container backup is impossible (ceph) or semantically wrong (raw block read).
// Such disks must be backed up with the VM running, via the guest-content (NBD)
// path. Returns a clear, actionable error otherwise.
func containerBackupUnsupported(disk *corrosion.DiskRecord) error {
	if isFileBasedDriver(disk.StorageType) {
		return nil
	}
	return status.Errorf(codes.Unimplemented,
		"disk %q is on %q storage: container-file backup is not supported — back it up with the VM running so the guest-content (NBD) path is used",
		disk.DiskName, disk.StorageType)
}

// keepBitmapNames is the GC keep-set: every checkpoint name still
// referenced by a surviving manifest for (vm, disk).
func keepBitmapNames(repo *pbsstore.Repo, vm, disk string) []string {
	ms, err := repo.ListManifests()
	if err != nil {
		return nil
	}
	var keep []string
	for i := range ms {
		m := &ms[i]
		if m.VMName == vm && m.DiskName == disk && m.BitmapName != "" {
			keep = append(keep, m.BitmapName)
		}
	}
	return keep
}

// RestoreFromBackup streams a manifest's chunks back into a target
// disk path. Same single-host model as BackupSnapshot.
func (s *Server) RestoreFromBackup(req *pb.RestoreFromBackupRequest, stream grpc.ServerStreamingServer[pb.RestoreFromBackupProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.RepoPath == "" || req.VmName == "" || req.DiskName == "" || req.Timestamp == "" || req.TargetPath == "" {
		return status.Error(codes.InvalidArgument,
			"repo_path, vm_name, disk_name, timestamp, target_path all required")
	}
	// Restore may target a VM that no longer exists (disaster recovery),
	// so fall back to the default-project path when the record is gone.
	rbacPath := vmRBACPathFor("", req.VmName)
	if vm, gerr := corrosion.GetVM(ctx, s.db, req.VmName); gerr == nil && vm != nil {
		rbacPath = vmRBACPath(vm)
	}
	if err := s.RequirePerm(ctx, rbacPath, "backup.restore", "operator"); err != nil {
		return err
	}
	repo, err := pbsstore.Open(req.RepoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo: %v", err)
	}
	manifest, err := repo.GetManifest(req.VmName, req.Timestamp, req.DiskName)
	if err != nil {
		return status.Errorf(codes.NotFound, "manifest: %v", err)
	}

	send := func(p *pb.RestoreFromBackupProgress) error { return stream.Send(p) }
	if err := send(&pb.RestoreFromBackupProgress{
		Phase:       pb.RestoreFromBackupProgress_RESTORE,
		ChunksTotal: int32(len(manifest.Chunks)),
		Status:      fmt.Sprintf("restoring %s@%s → %s", req.VmName, req.Timestamp, req.TargetPath),
	}); err != nil {
		return err
	}

	if err := pbsstore.RestoreToFile(ctx, repo, manifest, req.TargetPath, pbsstore.RestoreOptions{
		Progress: func(p pbsstore.RestoreProgress) {
			_ = send(&pb.RestoreFromBackupProgress{
				Phase:        pb.RestoreFromBackupProgress_RESTORE,
				BytesWritten: p.BytesWritten,
				ChunksDone:   int32(p.ChunksDone),
				ChunksTotal:  int32(p.ChunksTotal),
			})
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "restore: %v", err)
	}
	s.recordVMEvent(ctx, req.VmName, "backup.restored", "ok",
		fmt.Sprintf("%s @ %s → %s", req.DiskName, req.Timestamp, req.TargetPath))
	return send(&pb.RestoreFromBackupProgress{
		Phase:        pb.RestoreFromBackupProgress_DONE,
		BytesWritten: manifest.TotalSize,
		ChunksDone:   int32(len(manifest.Chunks)),
		ChunksTotal:  int32(len(manifest.Chunks)),
		Status:       "restore complete",
	})
}

// pickDisk resolves disk_name (empty → first / "root") to the
// matching DiskRecord on the VM.
func pickDisk(ctx context.Context, db *corrosion.Client, vm, want string) (*corrosion.DiskRecord, error) {
	disks, err := corrosion.GetVMDisks(ctx, db, vm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	if len(disks) == 0 {
		return nil, status.Errorf(codes.NotFound, "vm %q has no disks", vm)
	}
	if want == "" {
		// Prefer "root", fall back to the first disk.
		for i := range disks {
			if disks[i].DiskName == "root" {
				return &disks[i], nil
			}
		}
		return &disks[0], nil
	}
	for i := range disks {
		if disks[i].DiskName == want {
			return &disks[i], nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "vm %q has no disk %q", vm, want)
}
