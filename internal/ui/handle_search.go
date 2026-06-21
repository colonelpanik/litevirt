package ui

import (
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		w.Write([]byte(""))
		return
	}
	q = strings.ToLower(q)
	ctx := s.uiBearerCtx(r)

	// Fetch all resources in parallel via goroutines would be ideal,
	// but sequential is simpler and fast enough for small clusters.
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	networks, _ := s.grpc.ListNetworks(ctx, &emptypb.Empty{})
	stacks, _ := s.grpc.ListStacks(ctx, &emptypb.Empty{})
	images, _ := s.grpc.ListImages(ctx, &emptypb.Empty{})
	lbs, _ := s.grpc.ListLoadBalancers(ctx, &emptypb.Empty{})

	var matchVMs []*pb.VM
	for _, vm := range vms.GetVms() {
		if strings.Contains(strings.ToLower(vm.Name), q) {
			matchVMs = append(matchVMs, vm)
		}
	}
	var matchHosts []*pb.Host
	for _, h := range hosts.GetHosts() {
		if strings.Contains(strings.ToLower(h.Name), q) {
			matchHosts = append(matchHosts, h)
		}
	}
	var matchNets []*pb.NetworkInfo
	for _, n := range networks.GetNetworks() {
		if strings.Contains(strings.ToLower(n.Name), q) {
			matchNets = append(matchNets, n)
		}
	}
	var matchStacks []*pb.StackSummary
	for _, st := range stacks.GetStacks() {
		if strings.Contains(strings.ToLower(st.Name), q) {
			matchStacks = append(matchStacks, st)
		}
	}
	var matchImages []*pb.Image
	for _, img := range images.GetImages() {
		if strings.Contains(strings.ToLower(img.Name), q) {
			matchImages = append(matchImages, img)
		}
	}
	var matchLBs []*pb.LoadBalancer
	for _, lb := range lbs.GetLbs() {
		if strings.Contains(strings.ToLower(lb.Name), q) {
			matchLBs = append(matchLBs, lb)
		}
	}

	total := len(matchVMs) + len(matchHosts) + len(matchNets) + len(matchStacks) + len(matchImages) + len(matchLBs)

	s.renderFragment(w, "search_results.html", map[string]any{
		"Query":    q,
		"VMs":      matchVMs,
		"Hosts":    matchHosts,
		"Networks": matchNets,
		"Stacks":   matchStacks,
		"Images":   matchImages,
		"LBs":      matchLBs,
		"Total":    total,
	})
}
