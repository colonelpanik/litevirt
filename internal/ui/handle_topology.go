package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

type topoNetwork struct {
	Name    string
	Type    string
	Subnet  string
	Gateway string
	VNI     int32
	VMs     []topoVM
}

type topoVM struct {
	Name string
	IP   string
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	nets, _ := s.grpc.ListNetworks(ctx, &emptypb.Empty{})
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})

	// Build map: network name → []topoVM
	netVMs := map[string][]topoVM{}
	for _, vm := range vms.GetVms() {
		for _, iface := range vm.Interfaces {
			if iface.NetworkName != "" {
				netVMs[iface.NetworkName] = append(netVMs[iface.NetworkName], topoVM{
					Name: vm.Name,
					IP:   iface.Ip,
				})
			}
		}
	}

	var topology []topoNetwork
	for _, n := range nets.GetNetworks() {
		topology = append(topology, topoNetwork{
			Name:    n.Name,
			Type:    n.Type,
			Subnet:  n.Subnet,
			Gateway: n.Gateway,
			VNI:     n.Vni,
			VMs:     netVMs[n.Name],
		})
	}

	data := s.pageData("Topology", "topology")
	data["Networks"] = topology
	s.renderPage(w, "topology.html", data)
}
