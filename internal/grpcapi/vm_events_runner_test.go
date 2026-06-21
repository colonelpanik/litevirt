package grpcapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func vmEventTypes(t *testing.T, s *Server, vm string) map[string]string {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 0, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	byType := map[string]string{} // type -> result
	for _, e := range evs {
		byType[e.Type] = e.Result
	}
	return byType
}

// TestRunBackup_EmitsSucceeded: a scheduled backup that completes records a
// per-VM backup.succeeded event (this is what makes a fan-out VM's outcome
// visible — the runner is called once per expanded VM).
func TestRunBackup_EmitsSucceeded(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	tmp := t.TempDir()
	diskPath := filepath.Join(tmp, "disk.qcow2")
	if err := qcow2.Create(diskPath, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "host-a", Path: diskPath, SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	repoDir := filepath.Join(tmp, "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}

	runner := BackupRunnerForScheduler(s, map[string]string{"main": repoDir})
	if err := runner.RunBackup(ctx, corrosion.BackupScheduleRecord{VMName: "vm1", Repo: "main", Scope: "vm"}, time.Now()); err != nil {
		t.Fatalf("RunBackup: %v", err)
	}
	ev := vmEventTypes(t, s, "vm1")
	if ev["backup.succeeded"] != "ok" {
		t.Fatalf("expected backup.succeeded(ok), got %v", ev)
	}
}

// TestRunBackup_EmitsFailed: a backup that fails (VM gone) records a per-VM
// backup.failed event with result=error — the previously-invisible signal.
func TestRunBackup_EmitsFailed(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	runner := BackupRunnerForScheduler(s, map[string]string{"main": repoDir})
	// "ghost" VM not in corrosion → runBackupInner errors → backup.failed.
	if err := runner.RunBackup(ctx, corrosion.BackupScheduleRecord{VMName: "ghost", Repo: "main", Scope: "vm"}, time.Now()); err == nil {
		t.Fatal("expected RunBackup error for missing VM")
	}
	ev := vmEventTypes(t, s, "ghost")
	if ev["backup.failed"] != "error" {
		t.Fatalf("expected backup.failed(error), got %v", ev)
	}
	if _, ok := ev["backup.succeeded"]; ok {
		t.Error("must not emit backup.succeeded on failure")
	}
}

// TestRunBackup_NoEventForUnconfiguredRepo: a schedule pointing at a repo this
// host doesn't have is a config issue that fires every cron tick — it must NOT
// spam vm_events.
func TestRunBackup_NoEventForUnconfiguredRepo(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	runner := BackupRunnerForScheduler(s, map[string]string{}) // no repos configured
	_ = runner.RunBackup(ctx, corrosion.BackupScheduleRecord{VMName: "vm1", Repo: "main", Scope: "vm"}, time.Now())
	if ev := vmEventTypes(t, s, "vm1"); len(ev) != 0 {
		t.Fatalf("unconfigured repo must emit no vm_events, got %v", ev)
	}
}
