// Snapshot/backup scheduler.
//
// Each daemon runs its own scheduler. Per tick (default 60 s), it
// pulls every non-deleted backup_schedules row whose VM is hosted
// locally and whose cron expression matches the current minute, then
// invokes the SnapshotRunner. There is no cluster-wide leader gate:
// a VM is owned by exactly one host at a time, so each backup_schedules
// row has exactly one candidate executor and double-firing is
// impossible by construction. The `same-minute` dedup guard prevents
// a fast-poll within a minute from re-firing the same row.
//
// Why not leader-gated: in the original design the leader iterated
// all schedules and skipped non-local VMs (returning nil). That
// silently dropped backups for every VM whose host wasn't currently
// holding the snapshot-scheduler lease — a real correctness bug.
// The per-host model has no such failure mode.

package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// SnapshotRunner is what the scheduler calls when a cron fires. The
// production implementation lives in internal/grpcapi (lockVM +
// pbsstore.PushFile + retention); tests pass a stub that records calls.
//
// The runAt argument is the scheduler's view of "now" — runners MUST
// use it as the manifest timestamp instead of consulting time.Now()
// directly. Two backups in the same wall-clock second from different
// schedulers (or fast virtual-time test ticks) would otherwise collide
// on the manifest filename and silently overwrite each other.
type SnapshotRunner interface {
	RunBackup(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error
}

// ReplicationRunner is called for schedules with type='replication' (the
// production impl lives in internal/grpcapi: ReplicateVolume + keep_replicas
// pruning). Optional — nil means replication rows are skipped.
type ReplicationRunner interface {
	RunReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error
}

// SnapshotScheduler is a per-host minute-tick scheduler. Each daemon
// runs its own instance; ownership is decided at tick time by reading
// `vms.host_name`. There is no cluster-wide lease.
type SnapshotScheduler struct {
	DB            *corrosion.Client
	HostName      string
	Runner        SnapshotRunner
	ReplRunner    ReplicationRunner // optional; handles type='replication' rows
	PollInterval  time.Duration     // default 60s
	Now           func() time.Time

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewSnapshotScheduler returns a configured scheduler with sensible defaults.
func NewSnapshotScheduler(db *corrosion.Client, hostName string, runner SnapshotRunner) *SnapshotScheduler {
	return &SnapshotScheduler{
		DB:           db,
		HostName:     hostName,
		Runner:       runner,
		PollInterval: 60 * time.Second,
		Now:          func() time.Time { return time.Now().UTC() },
		stopCh:       make(chan struct{}),
	}
}

// Run blocks until ctx is cancelled or Stop is called, ticking every
// PollInterval. The first tick fires immediately so a freshly-started
// daemon can pick up overdue schedules before the next minute boundary.
func (s *SnapshotScheduler) Run(ctx context.Context) {
	if s.PollInterval <= 0 {
		s.PollInterval = 60 * time.Second
	}
	if s.Now == nil {
		s.Now = func() time.Time { return time.Now().UTC() }
	}
	ticker := time.NewTicker(s.PollInterval)
	defer ticker.Stop()
	s.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

// Stop interrupts a running scheduler. Idempotent.
func (s *SnapshotScheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Tick runs one scheduling pass. Exposed for tests so virtual-time
// runs can drive minute boundaries directly without sleeping.
func (s *SnapshotScheduler) Tick(ctx context.Context) {
	now := s.Now()
	schedules, err := corrosion.ListBackupSchedules(ctx, s.DB)
	if err != nil {
		slog.Warn("snapshot scheduler: list schedules", "error", err)
		return
	}
	for _, sched := range schedules {
		if !sched.Enabled {
			continue
		}
		cron, err := ParseCron(sched.Cron)
		if err != nil {
			slog.Warn("snapshot scheduler: bad cron",
				"vm", sched.VMName, "pool", sched.PoolName, "repo", sched.Repo,
				"cron", sched.Cron, "error", err)
			continue
		}
		if !cron.Matches(now) {
			continue
		}
		if alreadyRanThisMinute(sched.LastRunAt, now) {
			continue
		}

		// Fan-out scopes (pool / cluster / project): expand to every
		// matching VM owned by THIS host and fire one backup each.
		// Per-VM scope: the single-host-owner gate below.
		if fanoutVMs, isFanout := s.expandScope(ctx, sched); isFanout {
			if len(fanoutVMs) == 0 {
				// No matching VMs on this host's slice — nothing to do.
				// Don't mark the row run; other hosts may own matches.
				continue
			}
			for _, vmName := range fanoutVMs {
				fanout := sched
				fanout.VMName = vmName
				fanout.Scope = "vm"
				fanout.PoolName = ""
				fanout.ProjectName = ""
				s.dispatch(ctx, fanout, now)
			}
			// Record one last_run_at on the scope row per minute, keyed
			// by the row's identity (sentinel vm_name for non-vm scopes).
			_ = corrosion.MarkBackupScheduleRun(ctx, s.DB, sched.VMName, sched.Repo, "", now)
			continue
		}

		// Per-VM mode: route only when this host owns the VM.
		owner, ok := s.vmOwner(ctx, sched.VMName)
		if !ok || owner != s.HostName {
			continue
		}
		s.dispatch(ctx, sched, now)
	}
}

// expandScope resolves a fan-out schedule to the VMs on this host it should
// back up. It returns (vmNames, true) for pool/cluster/project scopes and
// (nil, false) for the per-VM scope. A legacy pool row (pool_name set with no
// explicit scope) is still treated as a pool fan-out.
func (s *SnapshotScheduler) expandScope(ctx context.Context, sched corrosion.BackupScheduleRecord) ([]string, bool) {
	switch {
	case sched.Scope == "cluster":
		vms, err := corrosion.VMsOnHost(ctx, s.DB, s.HostName)
		if err != nil {
			slog.Warn("snapshot scheduler: list cluster vms", "error", err)
			return nil, true
		}
		return vms, true
	case sched.Scope == "project":
		vms, err := corrosion.VMsInProject(ctx, s.DB, s.HostName, sched.ProjectName)
		if err != nil {
			slog.Warn("snapshot scheduler: list project vms", "project", sched.ProjectName, "error", err)
			return nil, true
		}
		return vms, true
	case sched.Scope == "pool" || sched.PoolName != "":
		vms, err := corrosion.VMsOnPool(ctx, s.DB, s.HostName, sched.PoolName)
		if err != nil {
			slog.Warn("snapshot scheduler: list pool vms", "pool", sched.PoolName, "error", err)
			return nil, true
		}
		return vms, true
	default:
		return nil, false
	}
}

// vmOwner returns the host_name column of the VM and a not-found flag.
// Schedules whose VM has been deleted return ok=false so dispatch
// silently skips the row rather than logging an error every tick.
func (s *SnapshotScheduler) vmOwner(ctx context.Context, vmName string) (string, bool) {
	rows, err := s.DB.Query(ctx,
		`SELECT host_name FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName)
	if err != nil || len(rows) == 0 {
		return "", false
	}
	return rows[0].String("host_name"), true
}

// dispatch fires one backup and records the outcome. The runAt
// timestamp is the scheduler's view of "now" so virtual-time tests are
// reproducible.
func (s *SnapshotScheduler) dispatch(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) {
	var err error
	if sched.Type == "replication" {
		if s.ReplRunner == nil {
			slog.Warn("snapshot scheduler: nil replication runner, skipping", "vm", sched.VMName)
			return
		}
		err = s.ReplRunner.RunReplication(ctx, sched, runAt)
	} else {
		if s.Runner == nil {
			slog.Warn("snapshot scheduler: nil runner, skipping", "vm", sched.VMName)
			return
		}
		err = s.Runner.RunBackup(ctx, sched, runAt)
	}
	runErr := ""
	if err != nil {
		runErr = err.Error()
		slog.Error("snapshot scheduler: schedule run failed", "type", sched.Type, "vm", sched.VMName, "repo", sched.Repo, "error", err)
	} else {
		slog.Info("snapshot scheduler: schedule run ok", "type", sched.Type, "vm", sched.VMName, "repo", sched.Repo)
	}
	if mErr := corrosion.MarkBackupScheduleRun(ctx, s.DB, sched.VMName, sched.Repo, runErr, runAt); mErr != nil {
		slog.Warn("snapshot scheduler: mark run", "vm", sched.VMName, "error", mErr)
	}
}

// alreadyRanThisMinute returns true if last_run_at falls in the same
// UTC minute as now — prevents a fast-poll loop from double-firing.
func alreadyRanThisMinute(lastRunAt string, now time.Time) bool {
	if lastRunAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastRunAt)
	if err != nil {
		return false
	}
	return t.UTC().Truncate(time.Minute).Equal(now.UTC().Truncate(time.Minute))
}

// ErrNoRepoConfigured is returned by RunnerWithRepoResolver when a
// schedule references a logical repo name not present in the daemon
// config. The dispatcher logs and records it but continues — a
// misconfigured row should not stall the whole scheduler.
var ErrNoRepoConfigured = errors.New("no backup_repos entry resolves the repo name")
