package ui

import (
	"net/http"
	"net/url"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ── atoi32 (unit) ─────────────────────────────────────────────────────────────

func TestAtoi32(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"7", 7},
		{"  3 ", 3},
		{"abc", 0}, // invalid → 0 (unbounded)
		{"-2", -2}, // negative passes through
		{"0", 0},
	}
	for _, tc := range cases {
		if got := atoi32(tc.in); got != tc.want {
			t.Errorf("atoi32(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ── /schedules page ───────────────────────────────────────────────────────────

func TestSchedulesPage_RendersAddAndDelete(t *testing.T) {
	mock := newDefaultMock()
	mock.listSchedulesResp = &pb.ListBackupSchedulesResponse{
		Schedules: []*pb.BackupSchedule{{VmName: "vm1", Repo: "main", Cron: "0 2 * * *", Enabled: true, KeepDaily: 7}},
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/schedules")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Add schedule")
	assertContains(t, w, "vm1")
	assertContains(t, w, "/ui/schedules/vm1?scope=") // scope-aware delete target
	assertContains(t, w, "repo=main")
}

// ── handleScheduleModal ───────────────────────────────────────────────────────

func TestScheduleModal_ListsVMs(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock()) // default mock has vm1, vm2
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/schedules/create-modal")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Add backup schedule")
	assertContains(t, w, "vm1")
	assertContains(t, w, "vm2")
}

// ── handleCreateSchedule ──────────────────────────────────────────────────────

func TestCreateSchedule_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{
		"vm_name":      {"vm1"},
		"repo":         {"main"},
		"cron":         {"0 2 * * *"},
		"keep_last":    {"3"},
		"keep_daily":   {"7"},
		"keep_weekly":  {"4"},
		"keep_monthly": {"6"},
		"keep_yearly":  {"1"},
		"enabled":      {"on"},
	}
	w := serveRequest(s, formPost(t, "/ui/schedules", form))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/schedules")
	req := mock.lastCreateScheduleReq
	if req == nil {
		t.Fatal("CreateBackupSchedule not called")
	}
	if req.VmName != "vm1" || req.Repo != "main" || req.Cron != "0 2 * * *" {
		t.Errorf("req core = %+v", req)
	}
	if req.KeepLast != 3 || req.KeepDaily != 7 || req.KeepWeekly != 4 || req.KeepMonthly != 6 || req.KeepYearly != 1 {
		t.Errorf("retention = %d/%d/%d/%d/%d", req.KeepLast, req.KeepDaily, req.KeepWeekly, req.KeepMonthly, req.KeepYearly)
	}
	if !req.Enabled {
		t.Error("Enabled should be true when checkbox is 'on'")
	}
}

func TestCreateSchedule_EnabledUncheckedIsFalse(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"vm_name": {"vm1"}, "repo": {"main"}, "cron": {"@daily"}} // no "enabled"
	w := serveRequest(s, formPost(t, "/ui/schedules", form))
	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateScheduleReq.Enabled {
		t.Error("Enabled should be false when checkbox absent")
	}
}

func TestCreateSchedule_MissingFieldsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"no vm", url.Values{"repo": {"main"}, "cron": {"@daily"}}},
		{"no repo", url.Values{"vm_name": {"vm1"}, "cron": {"@daily"}}},
		{"no cron", url.Values{"vm_name": {"vm1"}, "repo": {"main"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newDefaultMock()
			s := newTestUIServer(t, mock)
			w := serveRequest(s, formPost(t, "/ui/schedules", tc.form))
			assertStatus(t, w, http.StatusBadRequest)
			assertToast(t, w, "required")
			if mock.lastCreateScheduleReq != nil {
				t.Error("CreateBackupSchedule should not be called")
			}
		})
	}
}

func TestCreateSchedule_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.createScheduleErr = errSimulated
	s := newTestUIServer(t, mock)
	form := url.Values{"vm_name": {"vm1"}, "repo": {"main"}, "cron": {"@daily"}}
	w := serveRequest(s, formPost(t, "/ui/schedules", form))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}

// ── handleDeleteSchedule ──────────────────────────────────────────────────────

func TestDeleteSchedule_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/schedules/vm1?repo=main")))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/schedules")
	if mock.lastDeleteScheduleReq == nil || mock.lastDeleteScheduleReq.VmName != "vm1" || mock.lastDeleteScheduleReq.Repo != "main" {
		t.Errorf("delete req = %+v, want {vm1 main}", mock.lastDeleteScheduleReq)
	}
}

func TestDeleteSchedule_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteScheduleErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/schedules/vm1?repo=main")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}
