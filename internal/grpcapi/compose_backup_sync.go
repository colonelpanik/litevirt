package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// syncComposeBackupSchedule reconciles `backup_schedules` against the
// compose VMDef's `backup:` block. Called from the stack deploy /
// redeploy paths in `stacks.go` so a `lv compose up` is enough to
// install a snapshot schedule.
//
// Semantics:
//   - Block present  → upsert (creates or replaces, defaulting Enabled=true).
//   - Block absent   → soft-delete any existing schedule for this VM.
//
// The schedule's `Repo` is the logical name from compose (e.g. "main"),
// resolved at scheduler tick time via daemon config `backup_repos:`.
func (s *Server) syncComposeBackupSchedule(ctx context.Context, vmName string, vmDef *compose.VMDef) error {
	if vmDef.Backup == nil {
		// Block removed on redeploy — wipe any existing row so the
		// scheduler stops firing. List → delete is racy but fine in
		// CRDT-land: the deleted_at LWW resolves correctly even if
		// two operators redeploy concurrently.
		existing, _ := corrosion.ListBackupSchedules(ctx, s.db)
		for _, e := range existing {
			if e.VMName == vmName {
				_ = corrosion.DeleteBackupSchedule(ctx, s.db, e.VMName, e.Repo)
			}
		}
		return nil
	}
	b := vmDef.Backup
	if b.Repo == "" {
		return fmt.Errorf("compose backup block for %q missing repo:", vmName)
	}
	if b.Schedule == "" {
		return fmt.Errorf("compose backup block for %q missing schedule:", vmName)
	}
	if _, err := scheduler.ParseCron(b.Schedule); err != nil {
		return fmt.Errorf("compose backup schedule %q invalid: %w", b.Schedule, err)
	}
	rec := corrosion.BackupScheduleRecord{
		VMName:  vmName,
		Repo:    b.Repo,
		Cron:    b.Schedule,
		Enabled: true,
	}
	if b.Retention != nil {
		rec.KeepLast = b.Retention.KeepLast
		rec.KeepDaily = b.Retention.KeepDaily
		rec.KeepWeekly = b.Retention.KeepWeekly
		rec.KeepMonthly = b.Retention.KeepMonthly
		rec.KeepYearly = b.Retention.KeepYearly
	}
	return corrosion.UpsertBackupSchedule(ctx, s.db, rec)
}
