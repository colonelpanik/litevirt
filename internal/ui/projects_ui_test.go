package ui

import (
	"net/http"
	"net/url"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ── /projects page ────────────────────────────────────────────────────────────

func TestProjectsPage_RendersUsageAndUnbounded(t *testing.T) {
	mock := newDefaultMock()
	mock.listProjectsResp = &pb.ListProjectsResponse{
		Projects: []*pb.Project{{Name: "/acme", Display: "Acme Corp", ParentName: ""}},
	}
	mock.getProjectQuotaResp = &pb.ProjectQuota{VcpuLimit: 16, MemMibLimit: 0} // mem unbounded
	mock.getProjectUsageResp = &pb.ProjectUsage{VcpuUsed: 4, MemMibUsed: 2048, VmCount: 2}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/projects")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "/acme")
	assertContains(t, w, "Acme Corp")
	assertContains(t, w, "4 / 16")   // vCPU used/limit
	assertContains(t, w, "2048 / ∞") // mem unbounded
}

func TestProjectsPage_EmptyState(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/projects")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "No projects defined")
}

func TestProjectsPage_ListError(t *testing.T) {
	mock := newDefaultMock()
	mock.listProjectsErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/projects")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "simulated error")
}

// ── handleProjectCreateModal ──────────────────────────────────────────────────

func TestProjectCreateModal_ListsParents(t *testing.T) {
	mock := newDefaultMock()
	mock.listProjectsResp = &pb.ListProjectsResponse{Projects: []*pb.Project{{Name: "/acme"}}}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/projects/create-modal")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Create project")
	assertContains(t, w, "/acme") // available as a parent option
}

// ── handleCreateProject ───────────────────────────────────────────────────────

func TestCreateProject_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"/acme/db"}, "display": {"Database"}, "parent": {"/acme"}}
	w := serveRequest(s, formPost(t, "/ui/projects", form))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/projects")
	req := mock.lastCreateProjectReq
	if req == nil || req.Name != "/acme/db" || req.Display != "Database" || req.ParentName != "/acme" {
		t.Errorf("create req = %+v", req)
	}
}

func TestCreateProject_MissingNameRejected(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {""}, "display": {"x"}}
	w := serveRequest(s, formPost(t, "/ui/projects", form))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "required")
	if mock.lastCreateProjectReq != nil {
		t.Error("CreateProject should not be called with empty name")
	}
}

func TestCreateProject_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.createProjectErr = errSimulated
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"/acme"}}
	w := serveRequest(s, formPost(t, "/ui/projects", form))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}

// ── handleDeleteProject (hierarchical name in query param) ─────────────────────

func TestDeleteProject_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/projects?name=/acme/db")))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/projects")
	if mock.lastDeleteProjectReq == nil || mock.lastDeleteProjectReq.Name != "/acme/db" {
		t.Errorf("delete req = %+v, want /acme/db", mock.lastDeleteProjectReq)
	}
}

func TestDeleteProject_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteProjectErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/projects?name=/acme")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}

// ── handleProjectQuotaModal ───────────────────────────────────────────────────

func TestProjectQuotaModal_Prefills(t *testing.T) {
	mock := newDefaultMock()
	mock.getProjectQuotaResp = &pb.ProjectQuota{ProjectName: "/acme", VcpuLimit: 8, MemMibLimit: 4096}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/projects/quota-modal?name=/acme")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Quota — /acme")
	assertContains(t, w, `value="8"`)
	assertContains(t, w, `value="4096"`)
}

func TestProjectQuotaModal_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.getProjectQuotaErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/projects/quota-modal?name=/acme")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "Load quota failed")
}

// ── handleSetProjectQuota ─────────────────────────────────────────────────────

func TestSetProjectQuota_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{
		"vcpu": {"16"}, "mem": {"8192"}, "disk": {"500"},
		"nics": {"4"}, "ips": {"2"}, "backup": {"1000"},
	}
	w := serveRequest(s, formPost(t, "/ui/projects/quota?name=/acme", form))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/projects")
	q := mock.lastSetQuotaReq.GetQuota()
	if q == nil || q.ProjectName != "/acme" {
		t.Fatalf("set quota req = %+v", mock.lastSetQuotaReq)
	}
	if q.VcpuLimit != 16 || q.MemMibLimit != 8192 || q.DiskGibLimit != 500 || q.NicLimit != 4 || q.PublicIpLimit != 2 || q.BackupGibLimit != 1000 {
		t.Errorf("quota fields = %+v", q)
	}
}

func TestSetProjectQuota_NameFromFormFallback(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"/acme"}, "vcpu": {"1"}}
	w := serveRequest(s, formPost(t, "/ui/projects/quota", form)) // no name query param
	assertStatus(t, w, http.StatusOK)
	if mock.lastSetQuotaReq.GetQuota().ProjectName != "/acme" {
		t.Errorf("ProjectName = %q, want /acme (form fallback)", mock.lastSetQuotaReq.GetQuota().ProjectName)
	}
}

func TestSetProjectQuota_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.setProjectQuotaErr = errSimulated
	s := newTestUIServer(t, mock)
	form := url.Values{"vcpu": {"1"}}
	w := serveRequest(s, formPost(t, "/ui/projects/quota?name=/acme", form))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}
