package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type recordingReplRunner struct {
	mu    sync.Mutex
	calls []corrosion.BackupScheduleRecord
}

func (r *recordingReplRunner) RunReplication(_ context.Context, s corrosion.BackupScheduleRecord, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
	return nil
}

// TestScheduler_ReplicationDispatch: a type='replication' row goes to the
// ReplRunner, and the backup runner is NOT called for it.
func TestScheduler_ReplicationDispatch(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedVM(t, db, "vm1")
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr-pool", Cron: "0 2 * * *", Enabled: true,
		Type: "replication", TargetPool: "dr-pool", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	backup := &recordingRunner{}
	repl := &recordingReplRunner{}
	s := NewSnapshotScheduler(db, "host-a", backup)
	s.ReplRunner = repl
	s.Now = func() time.Time { return time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC) }

	s.Tick(ctx)
	repl.mu.Lock()
	n := len(repl.calls)
	var tp string
	if n > 0 {
		tp = repl.calls[0].TargetPool
	}
	repl.mu.Unlock()
	if n != 1 {
		t.Fatalf("ReplRunner fired %d times, want 1", n)
	}
	if tp != "dr-pool" {
		t.Errorf("replicated to %q, want dr-pool", tp)
	}
	if got := backup.callCount(); got != 0 {
		t.Errorf("backup runner fired %d times for a replication row, want 0", got)
	}
}
