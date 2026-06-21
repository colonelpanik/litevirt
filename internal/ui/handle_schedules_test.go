package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestHandleSchedules_Empty asserts the empty-state CTA is rendered
// when no backup schedules exist.
func TestHandleSchedules_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/schedules", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "No backup schedules", "Add schedule")
}

// TestHandleSchedules_Rows renders a table when the gRPC mock returns
// at least one schedule.
func TestHandleSchedules_Rows(t *testing.T) {
	mock := newDefaultMock()
	mock.listSchedulesResp = &pb.ListBackupSchedulesResponse{
		Schedules: []*pb.BackupSchedule{
			{
				VmName: "vm-a", Repo: "main", Cron: "0 2 * * *",
				KeepDaily: 7, Enabled: true, LastRunAt: "2026-05-09T02:00:00Z",
			},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(httptest.NewRequest(http.MethodGet, "/schedules", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Cron is shown raw alongside the humanized form; last-run is rendered as a
	// relative time with the absolute value in the <abbr> title attribute.
	mustContain(t, w.Body.String(), "vm-a", "main", "0 2 * * *", "Daily at 02:00", "2026-05-09 02:00:00")
}
