package ui

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// handleSchedules renders /schedules — every configured backup schedule with
// last-run status, plus create/delete actions. surface, mirrors
// `lv backup schedule add/ls/rm`.
func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Schedules", "schedules")
	resp, err := s.grpc.ListBackupSchedules(s.uiBearerCtx(r), &pb.ListBackupSchedulesRequest{})
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "schedules.html", data)
		return
	}
	data["Schedules"] = resp.Schedules
	if rr, err := s.grpc.ListReplicationSchedules(s.uiBearerCtx(r), &pb.ListReplicationSchedulesRequest{}); err == nil {
		data["ReplSchedules"] = rr.GetSchedules()
	}
	s.renderPage(w, "schedules.html", data)
}

// handleReplScheduleModal renders the "Add replication schedule" form.
func (s *Server) handleReplScheduleModal(w http.ResponseWriter, r *http.Request) {
	var vms, pools, projects []string
	if resp, err := s.grpc.ListVMs(s.uiBearerCtx(r), &pb.ListVMsRequest{}); err == nil {
		for _, v := range resp.GetVms() {
			vms = append(vms, v.Name)
		}
	}
	if resp, err := s.grpc.ListStoragePools(s.uiBearerCtx(r), &pb.ListStoragePoolsRequest{}); err == nil {
		seen := map[string]bool{}
		for _, p := range resp.GetPools() {
			if !seen[p.GetName()] {
				seen[p.GetName()] = true
				pools = append(pools, p.GetName())
			}
		}
		sort.Strings(pools)
	}
	if resp, err := s.grpc.ListProjects(s.uiBearerCtx(r), &emptypb.Empty{}); err == nil {
		for _, p := range resp.GetProjects() {
			projects = append(projects, p.GetName())
		}
	}
	s.renderFragment(w, "repl_schedule_modal.html", map[string]any{
		"VMs": vms, "Pools": pools, "Projects": projects,
	})
}

// handleCreateReplSchedule wires the modal to CreateReplicationSchedule.
func (s *Server) handleCreateReplSchedule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		scope = "vm"
	}
	req := &pb.CreateReplicationScheduleRequest{
		Scope:        scope,
		VmName:       strings.TrimSpace(r.FormValue("vm_name")),
		PoolName:     strings.TrimSpace(r.FormValue("pool_name")),
		ProjectName:  strings.TrimSpace(r.FormValue("project_name")),
		TargetPool:   strings.TrimSpace(r.FormValue("target_pool")),
		TargetHost:   strings.TrimSpace(r.FormValue("target_host")),
		Cron:         strings.TrimSpace(r.FormValue("cron")),
		KeepReplicas: atoi32(r.FormValue("keep_replicas")),
		Enabled:      r.FormValue("enabled") == "on",
		Incremental:  r.FormValue("incremental") == "on",
		AutoPromote:  r.FormValue("auto_promote") == "on",
	}
	if req.TargetPool == "" || req.Cron == "" {
		sendToast(w, "Target pool and cron are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := s.grpc.CreateReplicationSchedule(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Add replication schedule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Replication schedule added", "success")
	w.Header().Set("HX-Redirect", "/schedules")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteReplSchedule removes a replication schedule.
func (s *Server) handleDeleteReplSchedule(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := q.Get("scope")
	if scope == "" {
		scope = "vm"
	}
	req := &pb.DeleteReplicationScheduleRequest{
		Scope:       scope,
		VmName:      r.PathValue("vm"),
		PoolName:    q.Get("pool"),
		ProjectName: q.Get("project"),
		TargetPool:  q.Get("target"),
	}
	if _, err := s.grpc.DeleteReplicationSchedule(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Delete replication schedule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Replication schedule removed", "success")
	w.Header().Set("HX-Redirect", "/schedules")
	w.WriteHeader(http.StatusOK)
}

// handleScheduleModal renders the "Add schedule" form. It offers four scopes —
// VM, storage pool, all-VMs (cluster), and tenancy project — populating the
// relevant dropdowns so the operator picks a target without typing free text.
func (s *Server) handleScheduleModal(w http.ResponseWriter, r *http.Request) {
	var vms, pools, projects, repos []string
	if resp, err := s.grpc.ListVMs(s.uiBearerCtx(r), &pb.ListVMsRequest{}); err == nil {
		for _, v := range resp.GetVms() {
			vms = append(vms, v.Name)
		}
	}
	if resp, err := s.grpc.ListStoragePools(s.uiBearerCtx(r), &pb.ListStoragePoolsRequest{}); err == nil {
		seen := map[string]bool{}
		for _, p := range resp.GetPools() {
			if !seen[p.GetName()] {
				seen[p.GetName()] = true
				pools = append(pools, p.GetName())
			}
		}
		sort.Strings(pools)
	}
	if resp, err := s.grpc.ListProjects(s.uiBearerCtx(r), &emptypb.Empty{}); err == nil {
		for _, p := range resp.GetProjects() {
			projects = append(projects, p.GetName())
		}
	}
	for name := range s.backupRepos {
		repos = append(repos, name)
	}
	sort.Strings(repos)
	s.renderFragment(w, "schedule_create_modal.html", map[string]any{
		"VMs": vms, "Pools": pools, "Projects": projects, "Repos": repos,
	})
}

// handleCreateSchedule wires the modal to CreateBackupSchedule. Mirrors
// `lv backup schedule add <vm> --repo --cron --keep-*`.
func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		scope = "vm"
	}
	repo := strings.TrimSpace(r.FormValue("repo"))
	cron := strings.TrimSpace(r.FormValue("cron"))
	vm := strings.TrimSpace(r.FormValue("vm_name"))
	pool := strings.TrimSpace(r.FormValue("pool_name"))
	project := strings.TrimSpace(r.FormValue("project_name"))
	if repo == "" || cron == "" {
		sendToast(w, "Repo and cron are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Validate the scope target before the RPC so the UI gives an immediate,
	// specific message (the daemon enforces the same rules authoritatively).
	switch scope {
	case "vm":
		if vm == "" {
			sendToast(w, "A VM is required for a VM-scoped schedule", "error")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	case "pool":
		if pool == "" {
			sendToast(w, "A storage pool is required for a pool-scoped schedule", "error")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	case "project":
		if project == "" {
			sendToast(w, "A project is required for a project-scoped schedule", "error")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	req := &pb.CreateBackupScheduleRequest{
		Scope:       scope,
		VmName:      vm,
		PoolName:    pool,
		ProjectName: project,
		Repo:        repo,
		Cron:        cron,
		KeepLast:    atoi32(r.FormValue("keep_last")),
		KeepDaily:   atoi32(r.FormValue("keep_daily")),
		KeepWeekly:  atoi32(r.FormValue("keep_weekly")),
		KeepMonthly: atoi32(r.FormValue("keep_monthly")),
		KeepYearly:  atoi32(r.FormValue("keep_yearly")),
		Enabled:     r.FormValue("enabled") == "on",
	}
	if _, err := s.grpc.CreateBackupSchedule(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Add schedule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Backup schedule added", "success")
	w.Header().Set("HX-Redirect", "/schedules")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSchedule removes a schedule. The scope + target identify the row
// (the daemon derives the same sentinel key create used). Mirrors
// `lv backup schedule rm`.
func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := q.Get("scope")
	if scope == "" {
		scope = "vm"
	}
	req := &pb.DeleteBackupScheduleRequest{
		Scope:       scope,
		VmName:      r.PathValue("vm"),
		PoolName:    q.Get("pool"),
		ProjectName: q.Get("project"),
		Repo:        q.Get("repo"),
	}
	if _, err := s.grpc.DeleteBackupSchedule(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Delete schedule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Backup schedule removed", "success")
	w.Header().Set("HX-Redirect", "/schedules")
	w.WriteHeader(http.StatusOK)
}

// atoi32 parses a retention count from a form field; blank/invalid → 0 (unbounded).
func atoi32(s string) int32 {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return int32(n)
}
