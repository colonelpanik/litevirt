package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) handlePCI(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})

	type hostDevices struct {
		HostName string
		Devices  []*pb.PCIDevice
	}
	var allDevices []hostDevices
	for _, h := range hosts.GetHosts() {
		devs, _ := s.grpc.ListHostDevices(ctx, &pb.ListHostDevicesRequest{Name: h.Name})
		if devs != nil && len(devs.Devices) > 0 {
			allDevices = append(allDevices, hostDevices{HostName: h.Name, Devices: devs.Devices})
		}
	}

	data := s.pageData("PCI Devices", "pci")
	data["AllDevices"] = allDevices
	s.renderPage(w, "pci.html", data)
}
