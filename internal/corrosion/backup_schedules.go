package corrosion

import (
	"context"
	"fmt"
	"time"
)

// BackupScheduleRecord is one row of the backup_schedules table. A schedule
// targets one of four scopes (Scope): "vm" (back up VMName), "pool" (every VM
// whose disks live on PoolName), "cluster" (every VM), or "project" (every VM
// in ProjectName). The scheduler fans the non-vm scopes out per host at tick
// time. VMName always holds the row's identity key — for non-vm scopes it is a
// sentinel (see ScheduleKey) so several scopes can share one repo under the
// (vm_name, repo) primary key.
type BackupScheduleRecord struct {
	VMName      string
	PoolName    string // set when Scope == "pool"
	ProjectName string // set when Scope == "project"
	Scope       string // "vm" | "pool" | "cluster" | "project"; "" treated as "vm"
	Repo        string
	Cron        string
	KeepLast    int
	KeepDaily   int
	KeepWeekly  int
	KeepMonthly int
	KeepYearly  int
	Enabled     bool
	LastRunAt   string // RFC3339 UTC; "" = never run
	LastRunErr  string // empty = success

	// Replication (v17). Type "" / "backup" is a backup schedule; "replication"
	// replicates the VM's disks to TargetPool (on TargetHost, or a shared pool,
	// or an auto-selected healthy peer). KeepReplicas caps retained copies.
	// Replication rows store the destination pool in Repo (so the (vm_name,repo)
	// PK stays unique and meaningful).
	Type         string
	TargetPool   string
	TargetHost   string
	KeepReplicas int

	// Replication follow-ups (v18). Incremental transfers only dirty extents
	// into raw replicas (full-copy fallback when unavailable). AutoPromote lets
	// failover bring up the freshest replica on host loss. LastCheckpoint is the
	// per-schedule dirty-bitmap chain anchor advanced after each incremental run.
	Incremental    bool
	AutoPromote    bool
	LastCheckpoint string
}

// ScheduleKey returns the value stored in backup_schedules.vm_name for a
// schedule of the given scope. For "vm" scope it is the VM name; for the other
// scopes it is a sentinel so multiple scopes can coexist on one repo under the
// (vm_name, repo) primary key.
func ScheduleKey(scope, vmName, poolName, projectName string) string {
	switch scope {
	case "pool":
		return "@pool:" + poolName
	case "project":
		return "@project:" + projectName
	case "cluster":
		return "@cluster"
	default:
		return vmName
	}
}

// UpsertBackupSchedule creates or replaces a schedule by (vm_name, repo).
// PoolName is stored alongside but is not part of the primary key —
// callers wanting a pool-level row leave VMName empty and set PoolName.
// The PRIMARY KEY is still (vm_name, repo), with the convention that
// an empty vm_name + non-empty pool_name maps to a single pool row
// per repo.
func UpsertBackupSchedule(ctx context.Context, c *Client, s BackupScheduleRecord) error {
	now := c.NowTS()
	scope := s.Scope
	if scope == "" {
		scope = "vm"
	}
	typ := s.Type
	if typ == "" {
		typ = "backup"
	}
	return c.Execute(ctx,
		`INSERT INTO backup_schedules
		   (vm_name, pool_name, project_name, scope, repo, cron, keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly, enabled, type, target_pool, target_host, keep_replicas, incremental, auto_promote, last_checkpoint, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(vm_name, repo) DO UPDATE SET
		   pool_name = excluded.pool_name,
		   project_name = excluded.project_name,
		   scope = excluded.scope,
		   cron = excluded.cron,
		   keep_last = excluded.keep_last,
		   keep_daily = excluded.keep_daily,
		   keep_weekly = excluded.keep_weekly,
		   keep_monthly = excluded.keep_monthly,
		   keep_yearly = excluded.keep_yearly,
		   enabled = excluded.enabled,
		   type = excluded.type,
		   target_pool = excluded.target_pool,
		   target_host = excluded.target_host,
		   keep_replicas = excluded.keep_replicas,
		   incremental = excluded.incremental,
		   auto_promote = excluded.auto_promote,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		s.VMName, nullableString(s.PoolName), nullableString(s.ProjectName), scope, s.Repo, s.Cron,
		s.KeepLast, s.KeepDaily, s.KeepWeekly, s.KeepMonthly, s.KeepYearly,
		s.Enabled, typ, nullableString(s.TargetPool), nullableString(s.TargetHost), s.KeepReplicas,
		boolToInt(s.Incremental), boolToInt(s.AutoPromote), nullableString(s.LastCheckpoint), now,
	)
}

// nullableString maps "" → SQL NULL so we don't carry an empty-string
// pool_name on per-VM rows. SQLite treats "" and NULL distinctly in
// some predicates; keep them aligned.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// CountActiveSchedulesUsingPool counts ENABLED, non-deleted schedules that target
// (host, poolName) — the schedule half of the pool-delete reference guard
// (disabled schedules don't block). Three matches, per the host-scoping nuance:
//   - a pool-scoped backup schedule (scope='pool', pool_name=poolName);
//   - a replication schedule targeting poolName with NO target_host set — ambiguous
//     across same-named pools on other hosts, so blocked CONSERVATIVELY (any pool
//     of that name) unless --force;
//   - a replication schedule targeting (poolName, host) explicitly.
func CountActiveSchedulesUsingPool(ctx context.Context, c *Client, host, poolName string) (int, error) {
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM backup_schedules
		 WHERE deleted_at IS NULL AND enabled = 1 AND (
		     (scope = 'pool' AND pool_name = ?)
		  OR (target_pool = ? AND COALESCE(target_host, '') = '')
		  OR (target_pool = ? AND target_host = ?)
		 )`,
		poolName, poolName, poolName, host)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// ListBackupSchedules returns every non-deleted schedule.
func ListBackupSchedules(ctx context.Context, c *Client) ([]BackupScheduleRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, pool_name, project_name, scope, repo, cron, keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly,
		        enabled, last_run_at, last_run_err, type, target_pool, target_host, keep_replicas, incremental, auto_promote, last_checkpoint
		 FROM backup_schedules
		 WHERE deleted_at IS NULL
		 ORDER BY scope, vm_name, repo`)
	if err != nil {
		return nil, fmt.Errorf("list backup_schedules: %w", err)
	}
	out := make([]BackupScheduleRecord, 0, len(rows))
	for _, r := range rows {
		scope := r.String("scope")
		if scope == "" {
			scope = "vm"
		}
		typ := r.String("type")
		if typ == "" {
			typ = "backup"
		}
		out = append(out, BackupScheduleRecord{
			VMName:         r.String("vm_name"),
			PoolName:       r.String("pool_name"),
			ProjectName:    r.String("project_name"),
			Scope:          scope,
			Repo:           r.String("repo"),
			Cron:           r.String("cron"),
			KeepLast:       r.Int("keep_last"),
			KeepDaily:      r.Int("keep_daily"),
			KeepWeekly:     r.Int("keep_weekly"),
			KeepMonthly:    r.Int("keep_monthly"),
			KeepYearly:     r.Int("keep_yearly"),
			Enabled:        r.Int("enabled") != 0,
			LastRunAt:      r.String("last_run_at"),
			LastRunErr:     r.String("last_run_err"),
			Type:           typ,
			TargetPool:     r.String("target_pool"),
			TargetHost:     r.String("target_host"),
			KeepReplicas:   r.Int("keep_replicas"),
			Incremental:    r.Int("incremental") != 0,
			AutoPromote:    r.Int("auto_promote") != 0,
			LastCheckpoint: r.String("last_checkpoint"),
		})
	}
	return out, nil
}

// VMsOnPool returns the VM names whose disks live on the given
// storage pool. Used by the snapshot scheduler to expand a
// pool-level backup_schedules row at tick time.
func VMsOnPool(ctx context.Context, c *Client, hostName, poolName string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT vms.name
		 FROM vms
		 JOIN vm_disks ON vm_disks.vm_name = vms.name
		 WHERE vms.host_name = ?
		   AND vms.deleted_at IS NULL
		   AND vm_disks.deleted_at IS NULL
		   AND vm_disks.storage_volume = ?
		 ORDER BY vms.name`, hostName, poolName)
	if err != nil {
		return nil, fmt.Errorf("vms_on_pool: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// VMsOnHost returns every VM owned by the given host. Used by the snapshot
// scheduler to expand a cluster-scoped backup_schedules row at tick time.
func VMsOnHost(ctx context.Context, c *Client, hostName string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT name FROM vms
		 WHERE host_name = ? AND deleted_at IS NULL
		 ORDER BY name`, hostName)
	if err != nil {
		return nil, fmt.Errorf("vms_on_host: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// VMsInProject returns the host's VMs that belong to the given tenancy
// project. Used by the snapshot scheduler to expand a project-scoped
// backup_schedules row at tick time.
func VMsInProject(ctx context.Context, c *Client, hostName, project string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT name FROM vms
		 WHERE host_name = ? AND project = ? AND deleted_at IS NULL
		 ORDER BY name`, hostName, project)
	if err != nil {
		return nil, fmt.Errorf("vms_in_project: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// DeleteBackupSchedule marks the (vm_name, repo) schedule deleted.
func DeleteBackupSchedule(ctx context.Context, c *Client, vmName, repo string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE backup_schedules
		 SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND repo = ?`,
		now, now, vmName, repo)
}

// MarkBackupScheduleRun records the outcome of a scheduled run; runErr
// "" means success. runAt is the timestamp to persist as last_run_at —
// callers driving virtual time pass their injected clock here so the
// "already ran this minute" guard in the scheduler is reproducible.
func MarkBackupScheduleRun(ctx context.Context, c *Client, vmName, repo, runErr string, runAt time.Time) error {
	ts := runAt.UTC().Format(time.RFC3339) // last_run_at = the actual run time
	return c.Execute(ctx,
		`UPDATE backup_schedules
		 SET last_run_at = ?, last_run_err = ?, updated_at = ?
		 WHERE vm_name = ? AND repo = ?`,
		ts, runErr, c.NowTS(), vmName, repo)
}

// SetReplicationCheckpoint advances the per-schedule dirty-bitmap chain anchor
// after a successful incremental replication run. An empty checkpoint resets
// the chain (next run is a full push). Separate from the schedule upsert so an
// operator edit can't accidentally rewind the chain.
// Keyed by the REAL vm + repo in the dedicated replication_checkpoints table
// (NOT backup_schedules.last_checkpoint, which is the schedule-row sentinel for
// fan-out scopes — writing there missed every fanned-out VM). An empty
// checkpoint resets the chain. Upsert so per-VM and fan-out both persist.
func SetReplicationCheckpoint(ctx context.Context, c *Client, vmName, repo, checkpoint string) error {
	now := c.NowTS()
	if checkpoint == "" {
		// Reset: tombstone the row so the next run re-bases (parent = "").
		return c.Execute(ctx,
			`UPDATE replication_checkpoints SET deleted_at = ?, updated_at = ?
			 WHERE vm_name = ? AND repo = ?`, now, now, vmName, repo)
	}
	return c.Execute(ctx,
		`INSERT INTO replication_checkpoints (vm_name, repo, checkpoint, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, NULL)
		 ON CONFLICT(vm_name, repo) DO UPDATE SET checkpoint = excluded.checkpoint,
		   updated_at = excluded.updated_at, deleted_at = NULL`,
		vmName, repo, checkpoint, now)
}

// GetReplicationCheckpoint returns the recorded incremental-replication anchor
// for (vmName, repo), or "" if none (chain not yet established / was reset).
func GetReplicationCheckpoint(ctx context.Context, c *Client, vmName, repo string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT checkpoint FROM replication_checkpoints
		 WHERE vm_name = ? AND repo = ? AND deleted_at IS NULL`, vmName, repo)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("checkpoint"), nil
}
