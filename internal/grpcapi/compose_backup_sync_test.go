package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func newSyncTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "host-a"}
}

func TestSyncComposeBackupSchedule_Inserts(t *testing.T) {
	s := newSyncTestServer(t)
	vmDef := &compose.VMDef{
		Backup: &compose.BackupDef{
			Repo:     "main",
			Schedule: "0 2 * * *",
			Retention: &compose.RetentionDef{
				KeepDaily:  7,
				KeepWeekly: 4,
			},
		},
	}
	if err := s.syncComposeBackupSchedule(context.Background(), "vm1", vmDef); err != nil {
		t.Fatalf("sync: %v", err)
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.VMName != "vm1" || r.Repo != "main" || r.Cron != "0 2 * * *" {
		t.Errorf("row mismatch: %+v", r)
	}
	if r.KeepDaily != 7 || r.KeepWeekly != 4 {
		t.Errorf("retention not propagated: %+v", r)
	}
	if !r.Enabled {
		t.Errorf("schedule defaults to enabled=true, got %v", r.Enabled)
	}
}

func TestSyncComposeBackupSchedule_RemovesWhenBlockGone(t *testing.T) {
	s := newSyncTestServer(t)
	if err := corrosion.UpsertBackupSchedule(context.Background(), s.db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "main", Cron: "0 2 * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := s.syncComposeBackupSchedule(context.Background(), "vm1", &compose.VMDef{}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows after block removal, got %d", len(rows))
	}
}

func TestSyncComposeBackupSchedule_RejectsBadCron(t *testing.T) {
	s := newSyncTestServer(t)
	err := s.syncComposeBackupSchedule(context.Background(), "vm1", &compose.VMDef{
		Backup: &compose.BackupDef{Repo: "main", Schedule: "not-a-cron"},
	})
	if err == nil {
		t.Fatal("expected error for malformed cron")
	}
}

func TestSyncComposeBackupSchedule_RejectsMissingRepo(t *testing.T) {
	s := newSyncTestServer(t)
	err := s.syncComposeBackupSchedule(context.Background(), "vm1", &compose.VMDef{
		Backup: &compose.BackupDef{Schedule: "0 2 * * *"},
	})
	if err == nil {
		t.Fatal("expected error for missing repo:")
	}
}
