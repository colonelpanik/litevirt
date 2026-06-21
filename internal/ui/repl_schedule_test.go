package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestReplicationScheduleUI(t *testing.T) {
	mock := newDefaultMock()
	mock.listReplSchedulesResp = &pb.ListReplicationSchedulesResponse{Schedules: []*pb.ReplicationSchedule{
		{VmName: "web-1", TargetPool: "dr-pool", Cron: "0 * * * *", KeepReplicas: 3, Enabled: true, Scope: "vm"},
	}}
	s := newTestUIServer(t, mock)

	t.Run("schedules page shows replication section", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/schedules")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "Replication schedules", "dr-pool", "/ui/schedules/repl-create-modal")
	})

	t.Run("modal renders", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/schedules/repl-create-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "Add replication schedule", `name="target_pool"`, `name="keep_replicas"`)
	})

	t.Run("create posts the right request", func(t *testing.T) {
		m := newDefaultMock()
		cs := newTestUIServer(t, m)
		r := ctPost(t, "/ui/schedules/repl", "scope=vm&vm_name=web-1&target_pool=dr-pool&target_host=host-b&cron=0 2 * * *&keep_replicas=5&enabled=on")
		w := serveRequest(cs, withAuth(r))
		assertStatus(t, w, http.StatusOK)
		req := m.lastCreateReplReq
		if req == nil || req.TargetPool != "dr-pool" || req.TargetHost != "host-b" || req.KeepReplicas != 5 || req.VmName != "web-1" {
			t.Fatalf("CreateReplicationSchedule req = %+v", req)
		}
		if w.Header().Get("HX-Redirect") != "/schedules" {
			t.Errorf("HX-Redirect = %q", w.Header().Get("HX-Redirect"))
		}
	})

	t.Run("delete", func(t *testing.T) {
		m := newDefaultMock()
		cs := newTestUIServer(t, m)
		w := serveRequest(cs, withAuth(mustReq(t, "DELETE", "/ui/schedules/repl/web-1?scope=vm&target=dr-pool")))
		assertStatus(t, w, http.StatusOK)
		if m.lastDeleteReplReq == nil || m.lastDeleteReplReq.TargetPool != "dr-pool" {
			t.Errorf("delete req = %+v", m.lastDeleteReplReq)
		}
	})
}
