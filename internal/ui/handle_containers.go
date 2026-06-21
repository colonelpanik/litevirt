package ui

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleContainers renders /containers: cluster-wide LXC/OCI list with
// lifecycle controls. Reads via gRPC ListContainers so the page works
// against any host the UI talks to.
func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Containers", "containers")
	ctx := s.uiBearerCtx(r)
	resp, err := s.grpc.ListContainers(ctx, &pb.ListContainersRequest{HostName: r.URL.Query().Get("host")})
	if err != nil {
		slog.Error("ui: list containers", "error", err)
		data["Error"] = err.Error()
		s.renderPage(w, "containers.html", data)
		return
	}
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	data["Containers"] = resp.Containers
	data["Hosts"] = hosts.GetHosts()
	s.renderPage(w, "containers.html", data)
}

// handleContainersTable renders just the auto-refreshing list region.
func (s *Server) handleContainersTable(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	resp, _ := s.grpc.ListContainers(ctx, &pb.ListContainersRequest{HostName: r.URL.Query().Get("host")})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	s.renderPartial(w, "containers.html", "containers-table", map[string]any{
		"Containers": resp.GetContainers(),
		"Hosts":      hosts.GetHosts(),
	})
}

// handleNewContainerModal renders the create-container form (LXC download
// template — the path CreateContainer wires end-to-end, mirroring `lv ct create`).
func (s *Server) handleNewContainerModal(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	s.renderFragment(w, "container_create_modal.html", map[string]any{
		"Hosts": hosts.GetHosts(),
	})
}

func (s *Server) handleCreateContainer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	cpu, _ := strconv.Atoi(r.FormValue("cpu"))
	mem, _ := strconv.Atoi(r.FormValue("memory"))
	req := &pb.CreateContainerRequest{
		HostName:  r.FormValue("host"),
		Name:      strings.TrimSpace(r.FormValue("name")),
		Template:  "download",
		Distro:    strings.TrimSpace(r.FormValue("distro")),
		Release:   strings.TrimSpace(r.FormValue("release")),
		Arch:      strings.TrimSpace(r.FormValue("arch")),
		Cpu:       int32(cpu),
		MemoryMib: int32(mem),
	}
	if br := strings.TrimSpace(r.FormValue("bridge")); br != "" {
		nic := &pb.ContainerNetwork{Name: "eth0", Bridge: br}
		if ip := strings.TrimSpace(r.FormValue("ip")); ip != "" {
			nic.Ip = ip
		}
		req.Networks = []*pb.ContainerNetwork{nic}
	}
	slog.Info("UI: creating container", "name", req.Name, "host", req.HostName, "distro", req.Distro, "release", req.Release)
	if _, err := s.grpc.CreateContainer(s.uiBearerCtx(r), req); err != nil {
		slog.Error("UI: create container failed", "name", req.Name, "error", err)
		sendToast(w, "Create container failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Container '"+req.Name+"' created", "success")
	w.Header().Set("HX-Redirect", "/containers")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStartContainer(w http.ResponseWriter, r *http.Request) {
	host, name := r.PathValue("host"), r.PathValue("name")
	if _, err := s.grpc.StartContainer(s.uiBearerCtx(r), &pb.StartContainerRequest{HostName: host, Name: name}); err != nil {
		slog.Error("UI: start container failed", "name", name, "host", host, "error", err)
		sendToast(w, "Start failed: "+err.Error(), "error")
	} else {
		sendToast(w, "Container '"+name+"' starting", "success")
	}
	s.handleContainersTable(w, r)
}

func (s *Server) handleStopContainer(w http.ResponseWriter, r *http.Request) {
	host, name := r.PathValue("host"), r.PathValue("name")
	if _, err := s.grpc.StopContainer(s.uiBearerCtx(r), &pb.StopContainerRequest{HostName: host, Name: name, TimeoutSec: 30}); err != nil {
		slog.Error("UI: stop container failed", "name", name, "host", host, "error", err)
		sendToast(w, "Stop failed: "+err.Error(), "error")
	} else {
		sendToast(w, "Container '"+name+"' stopping", "success")
	}
	s.handleContainersTable(w, r)
}

func (s *Server) handleDeleteContainer(w http.ResponseWriter, r *http.Request) {
	host, name := r.PathValue("host"), r.PathValue("name")
	if _, err := s.grpc.DeleteContainer(s.uiBearerCtx(r), &pb.DeleteContainerRequest{HostName: host, Name: name}); err != nil {
		slog.Error("UI: delete container failed", "name", name, "host", host, "error", err)
		sendToast(w, "Delete failed: "+err.Error(), "error")
	} else {
		sendToast(w, "Container '"+name+"' deleted", "success")
	}
	s.handleContainersTable(w, r)
}

// handleContainerExecModal / handleExecContainer drive a one-shot command form
// against a running container (reuses the VM exec_output fragment).
func (s *Server) handleContainerExecModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "container_exec_modal.html", map[string]any{
		"Host": r.PathValue("host"),
		"Name": r.PathValue("name"),
	})
}

func (s *Server) handleExecContainer(w http.ResponseWriter, r *http.Request) {
	host, name := r.PathValue("host"), r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	cmdStr := strings.TrimSpace(r.FormValue("command"))
	if cmdStr == "" {
		http.Error(w, "command required", 400)
		return
	}
	resp, err := s.grpc.ExecContainer(s.uiBearerCtx(r), &pb.ExecContainerRequest{
		HostName: host, Name: name, Argv: strings.Fields(cmdStr),
	})
	if err != nil {
		s.renderFragment(w, "exec_output.html", map[string]any{"Error": err.Error()})
		return
	}
	s.renderFragment(w, "exec_output.html", map[string]any{
		"ExitCode": resp.ExitCode,
		"Stdout":   string(resp.Stdout),
		"Stderr":   string(resp.Stderr),
	})
}
