package ui

import (
	"net/http"
	"strconv"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	nets, _ := s.grpc.ListNetworks(s.uiBearerCtx(r), &emptypb.Empty{})
	data := s.pageData("Networks", "networks")
	data["Networks"] = nets.GetNetworks()
	s.renderPage(w, "networks.html", data)
}

func (s *Server) handleCreateNetworkModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "network_create_modal.html", nil)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		sendToast(w, "Network name is required", "error")
		w.WriteHeader(400)
		return
	}
	vni, _ := strconv.Atoi(r.FormValue("vni"))
	req := &pb.CreateNetworkRequest{
		Name:    name,
		Type:    r.FormValue("type"),
		Iface:   r.FormValue("iface"),
		Subnet:  r.FormValue("subnet"),
		Dhcp:    r.FormValue("dhcp") == "on",
		Vni:     int32(vni),
		Pf:      r.FormValue("pf"),
	}
	if _, err := s.grpc.CreateNetwork(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Create network failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Network '"+name+"' created", "success")
	w.Header().Set("HX-Redirect", "/networks")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	force := r.URL.Query().Get("force") == "true"
	if _, err := s.grpc.DeleteNetwork(s.uiBearerCtx(r), &pb.DeleteNetworkRequest{Name: name, Force: force}); err != nil {
		sendToast(w, "Delete network failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Network '"+name+"' deleted", "success")
	w.Header().Set("HX-Redirect", "/networks")
	w.WriteHeader(http.StatusOK)
}
