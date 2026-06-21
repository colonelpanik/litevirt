package scheduler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type recordingRunner struct {
	mu    sync.Mutex
	calls []corrosion.BackupScheduleRecord
	err   error
}

func (r *recordingRunner) RunBackup(_ context.Context, s corrosion.BackupScheduleRecord, _ time.Time) error {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
	return r.err
}

func (r *recordingRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func newSchedTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// seedVM inserts a VM owned by host-a so the per-host ownership gate
// passes. Tests that drive the post-fix scheduler need this row;
// orphan-schedule tests deliberately skip it.
func seedVM(t *testing.T, db *corrosion.Client, name string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: name, HostName: "host-a", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func TestSnapshotScheduler_FiresOnCronMatch(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "main", Cron: "0 2 * * *", Enabled: true, KeepDaily: 7,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	r := &recordingRunner{}
	s := NewSnapshotScheduler(db, "host-a", r)
	// Virtual time pinned at 02:00 UTC — cron should match.
	now := time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }

	s.Tick(ctx)
	if got := r.callCount(); got != 1 {
		t.Fatalf("first tick fired %d times, want 1", got)
	}

	// Second tick within the same minute must NOT re-fire.
	s.Tick(ctx)
	if got := r.callCount(); got != 1 {
		t.Errorf("same-minute re-tick fired again (count=%d); dedup broken", got)
	}

	// Advance into the next minute — still 02:01 — cron no longer matches.
	s.Now = func() time.Time { return now.Add(1 * time.Minute) }
	s.Tick(ctx)
	if got := r.callCount(); got != 1 {
		t.Errorf("non-matching minute fired (count=%d)", got)
	}
}

func TestSnapshotScheduler_SkipsDisabled(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm-off")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm-off", Repo: "main", Cron: "* * * * *", Enabled: false,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	r := &recordingRunner{}
	s := NewSnapshotScheduler(db, "host-a", r)
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC) }
	s.Tick(ctx)
	if got := r.callCount(); got != 0 {
		t.Errorf("disabled schedule fired (count=%d)", got)
	}
}

func TestSnapshotScheduler_BadCronSkipped(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm-bad")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm-bad", Repo: "main", Cron: "not a cron", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	r := &recordingRunner{}
	s := NewSnapshotScheduler(db, "host-a", r)
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx) // must not panic; logs the error
	if got := r.callCount(); got != 0 {
		t.Errorf("malformed cron fired (count=%d)", got)
	}
}

func TestSnapshotScheduler_RecordsRunOutcome(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm-fail")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm-fail", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	r := &recordingRunner{err: errors.New("disk full")}
	s := NewSnapshotScheduler(db, "host-a", r)
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx)

	got, err := corrosion.ListBackupSchedules(ctx, db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(got))
	}
	if got[0].LastRunErr != "disk full" {
		t.Errorf("LastRunErr = %q, want %q", got[0].LastRunErr, "disk full")
	}
	if got[0].LastRunAt == "" {
		t.Error("LastRunAt should be recorded even on failure")
	}
}

// TestSnapshotScheduler_PerHostOwnership pins the post-fix contract:
// each host's scheduler fires only its own VMs. A VM on host-A must
// produce a backup on host-A regardless of which host's scheduler
// is ticking — there is no leader gate that can swallow it.
func TestSnapshotScheduler_PerHostOwnership(t *testing.T) {
	ctx := context.Background()
	dbA, err := corrosion.NewSharedTestClient("snapshot-perhost", "host-a")
	if err != nil {
		t.Fatalf("NewSharedTestClient host-a: %v", err)
	}
	t.Cleanup(func() { dbA.Close() })
	if err := corrosion.InitSchema(ctx, dbA); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dbB, err := corrosion.NewSharedTestClient("snapshot-perhost", "host-b")
	if err != nil {
		t.Fatalf("NewSharedTestClient host-b: %v", err)
	}
	t.Cleanup(func() { dbB.Close() })

	// vm-a lives on host-a; vm-b lives on host-b. Both have a "fire every
	// minute" schedule.
	for _, h := range []struct{ name, region string }{
		{"host-a", "ny"}, {"host-b", "lon"},
	} {
		if err := corrosion.InsertHost(ctx, dbA, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0." + h.name, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	for _, vm := range []struct{ name, host string }{
		{"vm-a", "host-a"}, {"vm-b", "host-b"},
	} {
		if err := corrosion.InsertVM(ctx, dbA, corrosion.VMRecord{
			Name: vm.name, HostName: vm.host, Spec: "{}", State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
		if err := corrosion.UpsertBackupSchedule(ctx, dbA, corrosion.BackupScheduleRecord{
			VMName: vm.name, Repo: "main", Cron: "* * * * *", Enabled: true,
		}); err != nil {
			t.Fatalf("Upsert %s: %v", vm.name, err)
		}
	}
	now := time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC)

	var aCalled, bCalled atomic.Int32
	a := NewSnapshotScheduler(dbA, "host-a", schedRunnerFn(func(s corrosion.BackupScheduleRecord) error {
		aCalled.Add(1)
		if s.VMName != "vm-a" {
			t.Errorf("host-a scheduler fired for foreign VM %q", s.VMName)
		}
		return nil
	}))
	a.Now = func() time.Time { return now }
	b := NewSnapshotScheduler(dbB, "host-b", schedRunnerFn(func(s corrosion.BackupScheduleRecord) error {
		bCalled.Add(1)
		if s.VMName != "vm-b" {
			t.Errorf("host-b scheduler fired for foreign VM %q", s.VMName)
		}
		return nil
	}))
	b.Now = func() time.Time { return now }

	a.Tick(ctx)
	b.Tick(ctx)
	if aCalled.Load() != 1 {
		t.Errorf("host-a should fire exactly once for vm-a, got %d", aCalled.Load())
	}
	if bCalled.Load() != 1 {
		t.Errorf("host-b should fire exactly once for vm-b, got %d", bCalled.Load())
	}
}

// TestSnapshotScheduler_OrphanScheduleSkipped covers the
// schedule-without-VM case (e.g. mid-delete): runner is not called
// and last_run_at stays empty so the next tick re-evaluates.
func TestSnapshotScheduler_OrphanScheduleSkipped(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "ghost", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	var called atomic.Int32
	s := NewSnapshotScheduler(db, "host-a", schedRunnerFn(func(corrosion.BackupScheduleRecord) error {
		called.Add(1)
		return nil
	}))
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }
	s.Tick(ctx)
	if called.Load() != 0 {
		t.Errorf("orphan schedule fired (count=%d); vmOwner gate broken", called.Load())
	}
	got, _ := corrosion.ListBackupSchedules(ctx, db)
	if len(got) != 1 || got[0].LastRunAt != "" {
		t.Errorf("orphan schedule last_run_at = %q, want empty", got[0].LastRunAt)
	}
}

type schedRunnerFn func(corrosion.BackupScheduleRecord) error

func (f schedRunnerFn) RunBackup(_ context.Context, s corrosion.BackupScheduleRecord, _ time.Time) error {
	return f(s)
}
