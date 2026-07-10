package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/storage"
)

// errCheckpointCommit marks a failure to durably record the NEW replication
// checkpoint anchor after a transfer. It is distinct from a transfer failure: the
// parent anchor (DB row + libvirt bitmap) is left intact, so RunReplication must
// NOT reset the chain and fall back to a full copy (that would erase the retryable
// parent). The next run retries from the preserved parent.
var errCheckpointCommit = errors.New("replication checkpoint commit failed")

// RunReplication is the scheduler's replication dispatch (scheduler.Replication
// Runner). It replicates the VM's disk to the schedule's target pool, keeping
// the newest keep_replicas point-in-time copies. Crash-consistent (no guest
// quiesce) — same semantics as ReplicateVolume; it's a fast-recovery layer, not
// a backup replacement.
//
// Target model: an explicit target_host or a shared pool (nfs/ceph/iscsi) makes
// the replica usable cluster-wide; for a non-shared pool a cross-host target is
// rejected with guidance (true cross-host transport of local-only storage is a
// planned follow-up).
func (s *Server) RunReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error {
	if sched.TargetPool == "" {
		return fmt.Errorf("replication schedule for %q missing target_pool", sched.VMName)
	}
	vm, err := corrosion.GetVM(ctx, s.db, sched.VMName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q not found", sched.VMName)
	}
	if vm.HostName != s.hostName {
		return nil // not ours; the owning host's scheduler handles it
	}
	unlock := s.lockVM(sched.VMName)
	defer unlock()

	disks, err := corrosion.GetVMDisks(ctx, s.db, sched.VMName)
	if err != nil {
		return fmt.Errorf("list disks: %w", err)
	}
	src := pickReplicaSource(disks)
	if src == nil {
		return fmt.Errorf("vm %q has no disks to replicate", sched.VMName)
	}
	if !isFileBasedDriver(src.StorageType) {
		return fmt.Errorf("replication supports file-based disks only (disk %q is %q)", src.DiskName, src.StorageType)
	}

	// Resolve where the replica lands per the target model: explicit host, or a
	// shared pool (usable cluster-wide so write locally), otherwise a healthy
	// peer that has the pool — falling back to a same-host copy only if the pool
	// is local-only and no peer has it.
	poolLocal, haveLocal := s.resolvePool(ctx, sched.TargetPool)
	shared := haveLocal && isSharedDriver(poolLocal.Driver)
	targetHost := sched.TargetHost
	switch {
	case shared:
		targetHost = s.hostName
	case targetHost == s.hostName:
		// explicit same-host
	case targetHost != "":
		// explicit peer → cross-host below
	default:
		peers, _ := corrosion.HostsWithPool(ctx, s.db, sched.TargetPool, s.hostName)
		switch {
		case len(peers) > 0:
			targetHost = peers[0]
		case haveLocal:
			targetHost = s.hostName
		default:
			return fmt.Errorf("no active host has pool %q (and it isn't local); set target_host or use a shared pool", sched.TargetPool)
		}
	}

	// Project isolation (day-2): the VM's project may replicate only into a pool
	// that is global or its own — enforced at RUN time (against the resolved target
	// host) so a schedule created before v37, or any path, can't copy data into
	// another project's pool. Promotion runs through this path too.
	if err := s.admitVMPoolUse(ctx, vm, targetHost, sched.TargetPool); err != nil {
		return fmt.Errorf("replication target pool admission: %w", err)
	}

	ts := runAt.UTC().Format("20060102-150405")

	// Incremental path (opt-in): transfer only dirty extents into a raw replica
	// via the libvirt backup session. Falls back to the full qcow2 copy below
	// when the session can't open (stopped VM / old libvirt) or the transfer
	// fails — resetting the chain so the next run re-bases cleanly.
	if sched.Incremental && s.backupSource != nil {
		err := s.replicateIncremental(ctx, sched, vm, src, targetHost, ts)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, errCheckpointCommit):
			// The transfer succeeded but the new anchor couldn't be recorded. The
			// parent anchor (DB row + bitmap) is intact — do NOT reset the chain or
			// fall back (that would erase the retryable parent). Retry next run.
			slog.Error("incremental replication: checkpoint commit failed; parent anchor preserved for retry",
				"vm", sched.VMName, "pool", sched.TargetPool, "error", err)
			return err
		default:
			// Genuine transfer/session failure: reset the chain so the next run
			// re-bases cleanly, then fall through to the full qcow2 copy.
			if rerr := corrosion.SetReplicationCheckpoint(ctx, s.db, sched.VMName, sched.Repo, ""); rerr != nil {
				slog.Error("incremental replication: chain reset write failed",
					"vm", sched.VMName, "pool", sched.TargetPool, "error", rerr)
			}
			slog.Warn("incremental replication fell back to full copy",
				"vm", sched.VMName, "pool", sched.TargetPool, "error", err)
		}
	}

	if targetHost == s.hostName {
		return s.replicateLocal(ctx, sched, src, ts)
	}
	return s.replicateCrossHost(ctx, sched, src, targetHost, ts)
}

// replicateLocal writes the replica into a file-based pool on this host (the
// shared-storage / same-host path), then prunes locally.
func (s *Server) replicateLocal(ctx context.Context, sched corrosion.BackupScheduleRecord, src *corrosion.DiskRecord, ts string) error {
	dstPool, ok := s.resolvePool(ctx, sched.TargetPool)
	if !ok {
		return fmt.Errorf("target pool %q not configured on host %q", sched.TargetPool, s.hostName)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return fmt.Errorf("target pool %q driver %q is not file-based", sched.TargetPool, dstPool.Driver)
	}
	drv, err := storage.New(s.dataDir, storage.Config{
		Driver: dstPool.Driver, Source: dstPool.Source, Target: dstPool.Target, Options: dstPool.Options,
	})
	if err != nil {
		return fmt.Errorf("construct target driver: %w", err)
	}
	if err := drv.Prepare(ctx); err != nil {
		return fmt.Errorf("prepare target pool: %w", err)
	}
	dstDir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: dstPool.Driver, Source: dstPool.Source, Target: dstPool.Target})
	if err != nil {
		return fmt.Errorf("resolve target dir: %w", err)
	}
	dstPath := filepath.Join(dstDir, fmt.Sprintf("%s-%s-%s.qcow2", sched.VMName, src.DiskName, ts))
	if dstPath == src.Path {
		return fmt.Errorf("source and destination resolve to the same path")
	}
	noop := func(*pb.MoveVolumeProgress) error { return nil }
	if err := convertQcow2(ctx, src.Path, dstPath, noop); err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s: %v", src.DiskName, sched.TargetPool, err))
		s.notify(ctx, notify.Notification{
			Kind: "replication.failed", Severity: notify.SevError, Subject: sched.VMName,
			Detail: fmt.Sprintf("%s → %s: %v", src.DiskName, sched.TargetPool, err),
		})
		return fmt.Errorf("replicate %s: %w", src.DiskName, err)
	}
	pruned := pruneReplicas(dstDir, sched.VMName, src.DiskName, sched.KeepReplicas)
	detail := fmt.Sprintf("%s → %s (%s)", src.DiskName, sched.TargetPool, ts)
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	return nil
}

// replicateCrossHost replicates to a local scratch file, streams it to the
// target host's pool via UploadStoragePoolContent, removes the scratch, then
// prunes old replicas on the peer.
func (s *Server) replicateCrossHost(ctx context.Context, sched corrosion.BackupScheduleRecord, src *corrosion.DiskRecord, targetHost, ts string) error {
	fname := fmt.Sprintf("%s-%s-%s.qcow2", sched.VMName, src.DiskName, ts)
	scratchDir := filepath.Join(s.dataDir, "replicate-scratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return fmt.Errorf("scratch dir: %w", err)
	}
	scratch := filepath.Join(scratchDir, fname)
	defer os.Remove(scratch)

	noop := func(*pb.MoveVolumeProgress) error { return nil }
	if err := convertQcow2(ctx, src.Path, scratch, noop); err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s@%s: local copy: %v", src.DiskName, sched.TargetPool, targetHost, err))
		return fmt.Errorf("local scratch replicate: %w", err)
	}

	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		return fmt.Errorf("reach target host %q: %w", targetHost, err)
	}
	defer conn.Close()

	if err := streamFileToPool(ctx, client, scratch, sched.TargetPool, targetHost, fname); err != nil {
		s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "error", fmt.Sprintf("%s → %s@%s: upload: %v", src.DiskName, sched.TargetPool, targetHost, err))
		return fmt.Errorf("stream to %q: %w", targetHost, err)
	}

	pruned := pruneReplicasRemote(ctx, client, sched.TargetPool, targetHost, sched.VMName, src.DiskName, sched.KeepReplicas)
	detail := fmt.Sprintf("%s → %s@%s (%s)", src.DiskName, sched.TargetPool, targetHost, ts)
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	return nil
}

// streamFileToPool uploads a local file into a peer's pool via the
// client-streaming UploadStoragePoolContent RPC.
func streamFileToPool(ctx context.Context, client pb.LiteVirtClient, path, pool, host, filename string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	up, err := client.UploadStoragePoolContent(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(&pb.UploadStoragePoolContentRequest{PoolName: pool, Host: host, Filename: filename}); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := up.Send(&pb.UploadStoragePoolContentRequest{Chunk: buf[:n]}); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	_, err = up.CloseAndRecv()
	return err
}

// pruneReplicasRemote keeps the newest keepN replicas of <vm>-<disk>-*.qcow2 in
// a peer's pool, deleting older ones via DeleteStoragePoolContent. Returns the
// count deleted (best-effort; errors are logged by the caller's event).
func pruneReplicasRemote(ctx context.Context, client pb.LiteVirtClient, pool, host, vmName, diskName string, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	resp, err := client.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host})
	if err != nil {
		return 0
	}
	var names []string
	for _, c := range resp.GetContents() {
		if isReplicaOf(c.GetName(), vmName, diskName) {
			names = append(names, c.GetName())
		}
	}
	if len(names) <= keepN {
		return 0
	}
	sort.Strings(names)
	deleted := 0
	for _, n := range names[:len(names)-keepN] {
		if _, err := client.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: pool, Host: host, Filename: n}); err == nil {
			deleted++
		}
	}
	return deleted
}

// replicateIncremental transfers only the disk's dirty extents into a new raw
// replica, forked from the previous one. It opens a libvirt backup session
// (pull-mode NBD) to read guest-visible changed extents since the schedule's
// last checkpoint; a session that opens non-incrementally (no parent, or parent
// gone) produces a full raw push. On success it advances the schedule's
// checkpoint chain and prunes old replicas. Returns an error to let the caller
// fall back to a full qcow2 copy.
func (s *Server) replicateIncremental(ctx context.Context, sched corrosion.BackupScheduleRecord, vm *corrosion.VMRecord, src *corrosion.DiskRecord, targetHost, ts string) error {
	base := s.newestRawReplica(ctx, sched.TargetPool, targetHost, sched.VMName, src.DiskName)
	// Read the anchor from the per-VM replication_checkpoints table keyed by the
	// REAL vm (sched.VMName), NOT sched.LastCheckpoint — for fan-out scopes the
	// schedule row's vm_name is a sentinel, so sched.LastCheckpoint is always
	// empty and incremental silently degraded to full copies (bug-sweep #6).
	parentCP, _ := corrosion.GetReplicationCheckpoint(ctx, s.db, sched.VMName, sched.Repo)
	incrCP := ""
	if base != "" && parentCP != "" {
		incrCP = parentCP // both a base file and its checkpoint → real incremental
	} else {
		base = "" // can't fork safely → full push
	}

	newCP := replCheckpointName(src.DiskName, ts)
	session, err := s.backupSource.BeginBackup(sched.VMName, src.Path, incrCP, newCP)
	if err != nil {
		return fmt.Errorf("begin backup session: %w", err)
	}
	defer session.Close()
	// BeginBackup creates newCP durably (independent of the backup job). If the
	// transfer below fails, newCP would never be recorded and never cleaned up —
	// an unbounded checkpoint/bitmap leak on a flaky link (bug-sweep #7). Delete
	// it on any failure; the parent anchor (incrCP) is preserved for a retry.
	committed := false
	defer func() {
		if !committed {
			_ = s.backupSource.DeleteCheckpoint(sched.VMName, newCP)
		}
	}()
	if !session.Incremental() {
		base = "" // session decided full (e.g. parent checkpoint vanished)
	}
	extents, err := session.ChangedExtents()
	if err != nil {
		return fmt.Errorf("changed extents: %w", err)
	}
	totalSize := session.Size()
	newName := fmt.Sprintf("%s-%s-%s.raw", sched.VMName, src.DiskName, ts)

	if targetHost == s.hostName {
		if err := s.applyIncrementLocal(ctx, sched.TargetPool, newName, base, totalSize, session, extents); err != nil {
			return err
		}
	} else {
		if err := s.applyIncrementRemote(ctx, targetHost, sched.TargetPool, newName, base, totalSize, session, extents); err != nil {
			return err
		}
	}

	// Advance the chain: record the new anchor, then drop the old one. On failure
	// this returns errCheckpointCommit and leaves the parent anchor intact.
	if err := s.advanceReplicationCheckpoint(ctx, sched.VMName, sched.Repo, parentCP, newCP); err != nil {
		return err
	}
	committed = true // newCP is now the recorded anchor — keep it

	pruned := s.pruneReplicasAnywhere(ctx, sched.TargetPool, targetHost, sched.VMName, src.DiskName, sched.KeepReplicas)
	mode := "full"
	if base != "" {
		mode = "incremental"
	}
	detail := fmt.Sprintf("%s → %s@%s (%s, %s, %d extent(s))", src.DiskName, sched.TargetPool, targetHost, ts, mode, len(extents))
	if pruned > 0 {
		detail += fmt.Sprintf(", pruned %d old", pruned)
	}
	s.recordVMEvent(ctx, sched.VMName, "disk.replicated", "ok", detail)
	return nil
}

// advanceReplicationCheckpoint commits the checkpoint chain forward. It records
// newCP as the schedule's anchor FIRST — checked — and only after that write lands
// does it drop the superseded parent bitmap. If the anchor write fails it returns
// errCheckpointCommit WITHOUT touching the parent, so the caller preserves a fully
// retryable state (parent bitmap + parent DB anchor both intact) and the just-
// created newCP is cleaned up by replicateIncremental's deferred rollback.
func (s *Server) advanceReplicationCheckpoint(ctx context.Context, vmName, repo, parentCP, newCP string) error {
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, vmName, repo, newCP); err != nil {
		return fmt.Errorf("%w: record %q for %s/%s: %v", errCheckpointCommit, newCP, vmName, repo, err)
	}
	// Anchor is durable; the parent is now superseded. Dropping its bitmap is
	// best-effort — a failure only leaks a bitmap, it can't break the chain.
	if parentCP != "" && parentCP != newCP {
		if err := s.backupSource.DeleteCheckpoint(vmName, parentCP); err != nil {
			slog.Warn("replication: dropping superseded parent checkpoint failed (bitmap leak; not fatal)",
				"vm", vmName, "parent", parentCP, "error", err)
		}
	}
	return nil
}

// newestRawReplica returns the newest <vm>-<disk>-*.raw file in the target pool
// on host, or "" if none. Used as the fork base for an incremental push. Uses
// poolContentNames (RBAC-free), since the scheduler runs unauthenticated.
func (s *Server) newestRawReplica(ctx context.Context, pool, host, vmName, diskName string) string {
	prefix := fmt.Sprintf("%s-%s-", vmName, diskName)
	best := ""
	for _, n := range s.poolContentNames(ctx, pool, host) {
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".raw") && n > best {
			best = n
		}
	}
	return best
}

// applyIncrementLocal writes the new raw replica into a same-host pool.
func (s *Server) applyIncrementLocal(ctx context.Context, pool, newName, base string, totalSize int64, r io.ReaderAt, extents [][2]int64) error {
	poolRef, ok := s.resolvePool(ctx, pool)
	if !ok {
		return fmt.Errorf("pool %q not on host %q", pool, s.hostName)
	}
	dir, err := fileBasedPoolDir(s.dataDir, poolRef)
	if err != nil {
		return err
	}
	apply := func(f *os.File) error {
		return forEachExtentChunk(r, extents, totalSize, func(off int64, data []byte) error {
			_, werr := f.WriteAt(data, off)
			return werr
		})
	}
	_, err = forkRawAndApply(dir, newName, base, totalSize, apply)
	return err
}

// applyIncrementRemote streams the new raw replica to a peer's pool via
// PushReplicaIncrement (dirty extents only; the peer forks from base).
func (s *Server) applyIncrementRemote(ctx context.Context, host, pool, newName, base string, totalSize int64, r io.ReaderAt, extents [][2]int64) error {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return fmt.Errorf("reach host %q: %w", host, err)
	}
	defer conn.Close()
	up, err := client.PushReplicaIncrement(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(&pb.PushReplicaIncrementRequest{
		PoolName: pool, Host: host, Filename: newName, Base: base, TotalSize: totalSize,
	}); err != nil {
		return err
	}
	if err := forEachExtentChunk(r, extents, totalSize, func(off int64, data []byte) error {
		return up.Send(&pb.PushReplicaIncrementRequest{Offset: off, Data: data})
	}); err != nil {
		return err
	}
	_, err = up.CloseAndRecv()
	return err
}

// pruneReplicasAnywhere prunes old replicas in the target pool, local or remote.
func (s *Server) pruneReplicasAnywhere(ctx context.Context, pool, host, vmName, diskName string, keepN int) int {
	if host == s.hostName {
		if poolRef, ok := s.resolvePool(ctx, pool); ok {
			if dir, err := fileBasedPoolDir(s.dataDir, poolRef); err == nil {
				return pruneReplicas(dir, vmName, diskName, keepN)
			}
		}
		return 0
	}
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return 0
	}
	defer conn.Close()
	return pruneReplicasRemote(ctx, client, pool, host, vmName, diskName, keepN)
}

// forEachExtentChunk reads each extent from r in ≤1 MiB pieces and hands each
// (offset,data) to fn — the sink is either a local WriteAt or a gRPC Send. A
// reusable buffer is safe: both sinks consume the bytes synchronously.
func forEachExtentChunk(r io.ReaderAt, extents [][2]int64, totalSize int64, fn func(off int64, data []byte) error) error {
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for _, e := range extents {
		off, length := e[0], e[1]
		if off < 0 || length <= 0 {
			continue
		}
		if off+length > totalSize {
			length = totalSize - off
		}
		end := off + length
		for pos := off; pos < end; {
			n := int64(chunk)
			if end-pos < n {
				n = end - pos
			}
			got, rerr := readFullAt(r, buf[:n], pos)
			if got > 0 {
				if err := fn(pos, buf[:got]); err != nil {
					return err
				}
			}
			if rerr != nil {
				return rerr
			}
			pos += int64(got)
		}
	}
	return nil
}

// readFullAt fills p from r at off, looping over short reads. A short read that
// ends in io.EOF before filling p is a real error for our bounded extents.
func readFullAt(r io.ReaderAt, p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.ReadAt(p[total:], off+int64(total))
		total += n
		if err != nil {
			if err == io.EOF && total == len(p) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

// pickReplicaSource chooses the disk to replicate: the root disk if present,
// else the first disk.
func pickReplicaSource(disks []corrosion.DiskRecord) *corrosion.DiskRecord {
	for i := range disks {
		if disks[i].DiskName == "root" {
			return &disks[i]
		}
	}
	if len(disks) > 0 {
		return &disks[0]
	}
	return nil
}

// isSharedDriver reports whether a pool driver is reachable from multiple hosts
// (so a replica written by the source is usable by a peer on failover).
func isSharedDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "nfs", "ceph", "iscsi":
		return true
	}
	return false
}

// pruneReplicas keeps the newest keepN timestamped replicas of <vm>-<disk>-*.qcow2
// in dir, deleting older ones. keepN <= 0 keeps all. Returns the count deleted.
func pruneReplicas(dir, vmName, diskName string, keepN int) int {
	if keepN <= 0 {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isReplicaOf(e.Name(), vmName, diskName) {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keepN {
		return 0
	}
	sort.Strings(names) // timestamped suffix sorts oldest→newest
	deleted := 0
	for _, n := range names[:len(names)-keepN] {
		if os.Remove(filepath.Join(dir, n)) == nil {
			deleted++
		}
	}
	return deleted
}
