package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestSnapshotScheduler_PoolModeFansOut confirms a single
// pool-level backup_schedules row dispatches one backup per VM
// whose disks live on the pool — only for VMs owned by THIS host.
func TestSnapshotScheduler_PoolModeFansOut(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)

	// Two VMs owned by host-a on pool "fast"; one VM owned by
	// host-b also on "fast". A's scheduler should fire 2 (its own
	// pair) and skip host-b's VM.
	for _, vm := range []struct{ name, host string }{
		{"vm-a1", "host-a"},
		{"vm-a2", "host-a"},
		{"vm-b1", "host-b"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: vm.host, Spec: "{}", State: "running",
		}, nil, []corrosion.DiskRecord{
			{VMName: vm.name, DiskName: "root", Path: "/tmp/" + vm.name, StorageVolume: "fast", SizeBytes: 1},
		}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}

	// Single pool-level schedule.
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		PoolName: "fast", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert pool schedule: %v", err)
	}

	var fired atomic.Int32
	var firedNames []string
	s := NewSnapshotScheduler(db, "host-a", schedRunnerFn(func(rec corrosion.BackupScheduleRecord) error {
		fired.Add(1)
		firedNames = append(firedNames, rec.VMName)
		return nil
	}))
	s.Now = func() time.Time { return time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC) }
	s.Tick(ctx)

	if got := fired.Load(); got != 2 {
		t.Errorf("expected 2 fires (host-a's two VMs), got %d (%v)", got, firedNames)
	}
	for _, n := range firedNames {
		if n == "vm-b1" {
			t.Errorf("scheduler fired for foreign-host VM %q", n)
		}
	}
}
