package ui

import (
	"net/http"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// projectRow joins a project with its quota and live usage for the table.
type projectRow struct {
	Project *pb.Project
	Quota   *pb.ProjectQuota
	Usage   *pb.ProjectUsage
}

// handleProjects renders /projects — the tenancy buckets with quota + live usage
// and create/delete/quota actions. Mirrors `lv project create/ls/rm/quota/usage`.
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Projects", "projects")
	ctx := s.uiBearerCtx(r)
	resp, err := s.grpc.ListProjects(ctx, &emptypb.Empty{})
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "projects.html", data)
		return
	}
	rows := make([]projectRow, 0, len(resp.Projects))
	for _, p := range resp.Projects {
		q, _ := s.grpc.GetProjectQuota(ctx, &pb.GetProjectQuotaRequest{ProjectName: p.Name})
		u, _ := s.grpc.GetProjectUsage(ctx, &pb.GetProjectUsageRequest{ProjectName: p.Name})
		if q == nil {
			q = &pb.ProjectQuota{ProjectName: p.Name}
		}
		if u == nil {
			u = &pb.ProjectUsage{ProjectName: p.Name}
		}
		rows = append(rows, projectRow{Project: p, Quota: q, Usage: u})
	}
	data["Projects"] = rows
	s.renderPage(w, "projects.html", data)
}

// handleProjectCreateModal renders the "Create project" form, with a parent
// dropdown built from existing projects (hierarchy is name-based, e.g. /acme/db).
func (s *Server) handleProjectCreateModal(w http.ResponseWriter, r *http.Request) {
	var names []string
	resp, _ := s.grpc.ListProjects(s.uiBearerCtx(r), &emptypb.Empty{})
	for _, p := range resp.GetProjects() {
		names = append(names, p.Name)
	}
	s.renderFragment(w, "project_create_modal.html", map[string]any{"Parents": names})
}

// handleCreateProject mirrors `lv project create <name> --display --parent`.
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		sendToast(w, "Project name is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err := s.grpc.CreateProject(s.uiBearerCtx(r), &pb.CreateProjectRequest{
		Name:       name,
		Display:    strings.TrimSpace(r.FormValue("display")),
		ParentName: r.FormValue("parent"),
	})
	if err != nil {
		sendToast(w, "Create project failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Project '"+name+"' created", "success")
	w.Header().Set("HX-Redirect", "/projects")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteProject mirrors `lv project rm <name>` (must be empty of VMs). The
// name is a query param because project names are hierarchical (contain slashes).
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if _, err := s.grpc.DeleteProject(s.uiBearerCtx(r), &pb.DeleteProjectRequest{Name: name}); err != nil {
		sendToast(w, "Delete project failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Project '"+name+"' removed", "success")
	w.Header().Set("HX-Redirect", "/projects")
	w.WriteHeader(http.StatusOK)
}

// handleProjectQuotaModal renders the quota editor prefilled with the current
// limits (0 = unbounded). Mirrors the read side of `lv project quota`.
func (s *Server) handleProjectQuotaModal(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q, err := s.grpc.GetProjectQuota(s.uiBearerCtx(r), &pb.GetProjectQuotaRequest{ProjectName: name})
	if err != nil {
		sendToast(w, "Load quota failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.renderFragment(w, "project_quota_modal.html", map[string]any{"Name": name, "Quota": q})
}

// handleSetProjectQuota mirrors the write side of `lv project quota <name> --vcpu …`.
func (s *Server) handleSetProjectQuota(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = strings.TrimSpace(r.FormValue("name"))
	}
	_, err := s.grpc.SetProjectQuota(s.uiBearerCtx(r), &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{
			ProjectName:    name,
			VcpuLimit:      atoi32(r.FormValue("vcpu")),
			MemMibLimit:    atoi32(r.FormValue("mem")),
			DiskGibLimit:   atoi32(r.FormValue("disk")),
			NicLimit:       atoi32(r.FormValue("nics")),
			PublicIpLimit:  atoi32(r.FormValue("ips")),
			BackupGibLimit: atoi32(r.FormValue("backup")),
		},
	})
	if err != nil {
		sendToast(w, "Set quota failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Quota updated for '"+name+"'", "success")
	w.Header().Set("HX-Redirect", "/projects")
	w.WriteHeader(http.StatusOK)
}
