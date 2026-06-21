package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// BackupRunnerForScheduler returns a scheduler.SnapshotRunner that
// drives BackupSnapshot's underlying primitives (lockVM + pbsstore.PushFile
// + retention) without going through gRPC. The repos map provides the
// logical-name → on-disk-path resolution that the daemon config carries
// in `backup_repos:`. Schedules referencing an unconfigured repo are
// surfaced as a per-row error so the rest of the suite keeps running.
func BackupRunnerForScheduler(s *Server, repos map[string]string) scheduler.SnapshotRunner {
	return &backupRunner{server: s, repos: repos}
}

type backupRunner struct {
	server *Server
	repos  map[string]string
}

// resolveRepoPath maps a logical repo name to its on-disk path. Daemon config
// `backup_repos:` wins; otherwise it falls back to a cluster-wide repo
// registered at runtime (e.g. a compose `backup-repos:` block). Returns ""
// when the name is unknown anywhere.
func (r *backupRunner) resolveRepoPath(ctx context.Context, name string) string {
	if p, ok := r.repos[name]; ok {
		return p
	}
	if r.server != nil && r.server.db != nil {
		if p, err := corrosion.GetBackupRepoPath(ctx, r.server.db, name); err == nil {
			return p
		}
	}
	return ""
}

// RunBackup wraps the actual backup with per-VM event emission. The scheduler
// invokes this once per VM — including each expanded VM of a fan-out
// (pool/cluster/project) schedule — so a single VM's failure inside a fan-out
// is attributed to THAT vm in vm_events (the old code only recorded one
// last_run on the scope row, losing per-VM failures).
func (r *backupRunner) RunBackup(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error {
	// A schedule referencing an unconfigured repo is a config issue (already
	// surfaced via backup_schedules.last_run_err) and fires every cron tick —
	// don't spam vm_events with it.
	if r.resolveRepoPath(ctx, sched.Repo) == "" {
		return r.runBackupInner(ctx, sched, runAt)
	}
	r.server.recordVMEvent(ctx, sched.VMName, "backup.started", "ok", "scheduled → "+sched.Repo)
	err := r.runBackupInner(ctx, sched, runAt)
	if err != nil {
		r.server.recordVMEvent(ctx, sched.VMName, "backup.failed", "error", err.Error())
	} else {
		r.server.recordVMEvent(ctx, sched.VMName, "backup.succeeded", "ok", "scheduled → "+sched.Repo)
	}
	return err
}

func (r *backupRunner) runBackupInner(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error {
	repoPath := r.resolveRepoPath(ctx, sched.Repo)
	if repoPath == "" {
		return fmt.Errorf("%w: repo=%q", scheduler.ErrNoRepoConfigured, sched.Repo)
	}

	// Ownership is enforced by the scheduler — it only fires schedules
	// whose VM is owned by this host. We still re-fetch the VM here to
	// guard against a mid-tick migration.
	vm, err := corrosion.GetVM(ctx, r.server.db, sched.VMName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q not found", sched.VMName)
	}
	if vm.HostName != r.server.hostName {
		return fmt.Errorf("vm %q migrated mid-tick (now on %q)", sched.VMName, vm.HostName)
	}

	unlock := r.server.lockVM(sched.VMName)
	defer unlock()

	disk, derr := pickDisk(ctx, r.server.db, sched.VMName, "")
	if derr != nil {
		return fmt.Errorf("pick disk: %v", derr)
	}
	repo, oerr := pbsstore.Open(repoPath)
	if oerr != nil {
		return fmt.Errorf("open repo %q: %v", repoPath, oerr)
	}
	timestamp := runAt.UTC().Format(time.RFC3339)
	// Route through the same engine the interactive BackupSnapshot uses, rather
	// than reading disk.Path directly: for a RUNNING VM that means a consistent
	// guest-content (pull-mode NBD) backup that is storage-agnostic — a raw
	// PushFile here read a live qcow2 (inconsistent) and could not handle a disk
	// on a non-file backend at all. Schedules don't carry an incremental flag
	// yet, so this is a full backup; pushBackup still falls back to a container
	// PushFile for stopped / no-libvirt VMs on file-based pools.
	noProgress := func(*pb.BackupSnapshotProgress) error { return nil }
	m, perr := r.server.pushBackup(ctx, repo, disk, &pb.BackupSnapshotRequest{
		VmName:    sched.VMName,
		DiskName:  disk.DiskName,
		RepoPath:  repoPath,
		Timestamp: timestamp,
	}, timestamp, noProgress, vm.Spec)
	if perr != nil {
		return fmt.Errorf("push: %v", perr)
	}
	r.server.recordBackupUsage(ctx, sched.VMName, disk.DiskName, repoPath, m.TotalSize)

	// Retention runs after a successful push so a failed push doesn't
	// drop older recovery points.
	if hasRetention(sched) {
		policy := pbsstore.RetentionPolicy{
			KeepLast:    sched.KeepLast,
			KeepDaily:   sched.KeepDaily,
			KeepWeekly:  sched.KeepWeekly,
			KeepMonthly: sched.KeepMonthly,
			KeepYearly:  sched.KeepYearly,
		}
		plan, perr := pbsstore.PlanPrune(repo, policy)
		if perr != nil {
			slog.Warn("snapshot runner: plan prune", "vm", sched.VMName, "error", perr)
			return nil // backup succeeded; pruning is best-effort
		}
		if err := pbsstore.ApplyPrune(repo, plan); err != nil {
			slog.Warn("snapshot runner: apply prune", "vm", sched.VMName, "error", err)
		}
	}
	return nil
}

func hasRetention(s corrosion.BackupScheduleRecord) bool {
	return s.KeepLast > 0 || s.KeepDaily > 0 || s.KeepWeekly > 0 || s.KeepMonthly > 0 || s.KeepYearly > 0
}
