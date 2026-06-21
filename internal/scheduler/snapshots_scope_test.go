package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedScopeVMs inserts three VMs: two owned by host-a (one in project "acme",
// one in "_default") and one owned by host-b in "acme".
func seedScopeVMs(t *testing.T, ctx context.Context, db *corrosion.Client) {
	t.Helper()
	vms := []struct{ name, host, project string }{
		{"vm-a1", "host-a", "acme"},
		{"vm-a2", "host-a", "_default"},
		{"vm-b1", "host-b", "acme"},
	}
	for _, vm := range vms {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: vm.host, Project: vm.project, Spec: "{}", State: "running",
		}, nil, []corrosion.DiskRecord{
			{VMName: vm.name, DiskName: "root", Path: "/tmp/" + vm.name, StorageVolume: "fast", SizeBytes: 1},
		}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}
}

func runScopeTick(t *testing.T, ctx context.Context, db *corrosion.Client, host string) []string {
	t.Helper()
	var firedNames []string
	var fired atomic.Int32
	s := NewSnapshotScheduler(db, host, schedRunnerFn(func(rec corrosion.BackupScheduleRecord) error {
		fired.Add(1)
		firedNames = append(firedNames, rec.VMName)
		return nil
	}))
	s.Now = func() time.Time { return time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC) }
	s.Tick(ctx)
	return firedNames
}

// TestSnapshotScheduler_ClusterScope fans out to every VM owned by this host.
func TestSnapshotScheduler_ClusterScope(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedScopeVMs(t, ctx, db)

	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: corrosion.ScheduleKey("cluster", "", "", ""),
		Scope:  "cluster", Repo: "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert cluster schedule: %v", err)
	}

	fired := runScopeTick(t, ctx, db, "host-a")
	if len(fired) != 2 {
		t.Fatalf("cluster scope: expected 2 fires (host-a's VMs), got %d (%v)", len(fired), fired)
	}
	for _, n := range fired {
		if n == "vm-b1" {
			t.Errorf("cluster scope fired for foreign-host VM %q", n)
		}
	}
}

// TestSnapshotScheduler_ProjectScope fans out to this host's VMs in the project.
func TestSnapshotScheduler_ProjectScope(t *testing.T) {
	ctx := context.Background()
	db := newSchedTestDB(t)
	seedScopeVMs(t, ctx, db)

	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName:      corrosion.ScheduleKey("project", "", "", "acme"),
		Scope:       "project",
		ProjectName: "acme",
		Repo:        "main", Cron: "* * * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert project schedule: %v", err)
	}

	fired := runScopeTick(t, ctx, db, "host-a")
	// Only vm-a1 is on host-a AND in project acme.
	if len(fired) != 1 || fired[0] != "vm-a1" {
		t.Fatalf("project scope: expected [vm-a1], got %v", fired)
	}
}

// TestScheduleKey covers the sentinel encoding for non-vm scopes.
func TestScheduleKey(t *testing.T) {
	cases := []struct{ scope, vm, pool, project, want string }{
		{"vm", "web", "", "", "web"},
		{"pool", "", "fast", "", "@pool:fast"},
		{"project", "", "", "acme", "@project:acme"},
		{"cluster", "", "", "", "@cluster"},
		{"", "web", "", "", "web"},
	}
	for _, c := range cases {
		if got := corrosion.ScheduleKey(c.scope, c.vm, c.pool, c.project); got != c.want {
			t.Errorf("ScheduleKey(%q,%q,%q,%q) = %q, want %q", c.scope, c.vm, c.pool, c.project, got, c.want)
		}
	}
}
