package ui

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleLB(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	lbs, _ := s.grpc.ListLoadBalancers(ctx, &emptypb.Empty{})
	data := s.pageData("Load Balancers", "lb")
	data["LBs"] = lbs.GetLbs()
	s.renderPage(w, "lb.html", data)
}

func (s *Server) handleLBDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)
	lb, err := s.grpc.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: name})
	if err != nil {
		http.Error(w, "Load balancer not found", http.StatusNotFound)
		return
	}
	data := s.pageData(name, "lb")
	data["LB"] = lb

	// Fetch stats (best effort — may fail if HAProxy isn't running).
	stats, err := s.grpc.LBStats(ctx, &pb.LBStatsRequest{Name: name})
	if err == nil {
		data["Stats"] = stats
	}

	s.renderPage(w, "lb_detail.html", data)
}

func (s *Server) handleLBDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.DeleteLoadBalancer(s.uiBearerCtx(r), &pb.DeleteLBRequest{Name: name}); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusOK)
		return
	}
	sendToast(w, "Load balancer '"+name+"' deleted", "success")
	w.Header().Set("HX-Redirect", "/lb")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLBDrain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	backend := r.FormValue("backend")
	if backend == "" {
		http.Error(w, "backend parameter required", http.StatusBadRequest)
		return
	}
	if _, err := s.grpc.DrainBackend(s.uiBearerCtx(r), &pb.DrainBackendRequest{
		LbName:  name,
		Backend: backend,
	}); err != nil {
		sendToast(w, "Drain failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusOK)
		return
	}
	sendToast(w, "Backend '"+backend+"' draining", "success")
	w.Header().Set("HX-Redirect", "/lb/"+name)
	w.WriteHeader(http.StatusOK)
}

// ── LB Create/Update Wizard ─────────────────────────────────────────────────

func (s *Server) handleLBCreateModal(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	s.renderFragment(w, "lb_create_modal.html", map[string]any{
		"Hosts": hosts.GetHosts(),
	})
}

func (s *Server) handleCreateLB(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	name := r.FormValue("name")
	vip := r.FormValue("vip")
	algorithm := r.FormValue("algorithm")
	if name == "" || vip == "" {
		http.Error(w, "name and vip required", 400)
		return
	}

	// Parse ports (parallel arrays: listen[], target[], protocol[])
	listens := r.Form["listen"]
	targets := r.Form["target"]
	protocols := r.Form["protocol"]
	var ports []*pb.LBPort
	for i := range listens {
		listen, _ := strconv.Atoi(listens[i])
		target, _ := strconv.Atoi(targets[i])
		proto := "tcp"
		if i < len(protocols) && protocols[i] != "" {
			proto = protocols[i]
		}
		if listen > 0 && target > 0 {
			ports = append(ports, &pb.LBPort{
				Listen:   int32(listen),
				Target:   int32(target),
				Protocol: proto,
			})
		}
	}

	// Parse backends (parallel arrays: backend_name[], backend_address[])
	bNames := r.Form["backend_name"]
	bAddrs := r.Form["backend_address"]
	var backends []*pb.LBBackendAddress
	for i := range bNames {
		if i < len(bAddrs) && bNames[i] != "" && bAddrs[i] != "" {
			backends = append(backends, &pb.LBBackendAddress{
				Name:    bNames[i],
				Address: bAddrs[i],
			})
		}
	}

	// Parse hosts
	selectedHosts := r.Form["lb_hosts"]

	_, err := s.grpc.CreateLoadBalancer(s.uiBearerCtx(r), &pb.CreateLBRequest{
		Name:      name,
		Vip:       vip,
		Algorithm: algorithm,
		Ports:     ports,
		Hosts:     selectedHosts,
		Backends:  backends,
	})
	if err != nil {
		slog.Error("UI: create LB failed", "error", err)
		sendToast(w, "Create LB failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Load balancer '"+name+"' created", "success")
	w.Header().Set("HX-Redirect", "/lb/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLBEditModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	lb, err := s.grpc.InspectLoadBalancer(s.uiBearerCtx(r), &pb.InspectLBRequest{Name: name})
	if err != nil {
		http.Error(w, "LB not found", 404)
		return
	}
	hosts, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	s.renderFragment(w, "lb_edit_modal.html", map[string]any{
		"LB":    lb,
		"Hosts": hosts.GetHosts(),
	})
}

func (s *Server) handleUpdateLB(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}

	req := &pb.UpdateLBRequest{
		Name:      name,
		Vip:       r.FormValue("vip"),
		Algorithm: r.FormValue("algorithm"),
	}

	// Parse backends to add
	bNames := r.Form["backend_name"]
	bAddrs := r.Form["backend_address"]
	for i := range bNames {
		if i < len(bAddrs) && bNames[i] != "" && bAddrs[i] != "" {
			req.AddBackends = append(req.AddBackends, &pb.LBBackendAddress{
				Name:    bNames[i],
				Address: bAddrs[i],
			})
		}
	}

	// Parse backends to remove
	if rm := r.FormValue("remove_backends"); rm != "" {
		req.RemoveBackends = strings.Split(rm, ",")
	}

	_, err := s.grpc.UpdateLoadBalancer(s.uiBearerCtx(r), req)
	if err != nil {
		slog.Error("UI: update LB failed", "error", err)
		sendToast(w, "Update LB failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Load balancer '"+name+"' updated", "success")
	w.Header().Set("HX-Redirect", "/lb/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLBEnableBackend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	backend := r.PathValue("backend")
	_, err := s.grpc.EnableBackend(s.uiBearerCtx(r), &pb.EnableBackendRequest{
		LbName:  name,
		Backend: backend,
	})
	if err != nil {
		sendToast(w, "Enable failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Backend '"+backend+"' enabled", "success")
	w.Header().Set("HX-Redirect", "/lb/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLBDisableBackend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	backend := r.PathValue("backend")
	_, err := s.grpc.DisableBackend(s.uiBearerCtx(r), &pb.DisableBackendRequest{
		LbName:  name,
		Backend: backend,
	})
	if err != nil {
		sendToast(w, "Disable failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Backend '"+backend+"' disabled", "success")
	w.Header().Set("HX-Redirect", "/lb/"+name)
	w.WriteHeader(http.StatusOK)
}
