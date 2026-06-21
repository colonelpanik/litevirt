package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleHealthTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetHostHealth(ctx, &emptypb.Empty{})
	cs, _ := s.grpc.GetClusterStatus(ctx, &emptypb.Empty{})
	audit, _ := s.grpc.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 50})

	// Build host list for matrix
	hostSet := map[string]bool{}
	for _, e := range health.GetEntries() {
		hostSet[e.Observer] = true
		hostSet[e.Target] = true
	}
	var hostNames []string
	for h := range hostSet {
		hostNames = append(hostNames, h)
	}

	// Build matrix map: observer→target→status
	matrix := map[string]map[string]string{}
	for _, e := range health.GetEntries() {
		if matrix[e.Observer] == nil {
			matrix[e.Observer] = map[string]string{}
		}
		matrix[e.Observer][e.Target] = e.Status
	}

	data := s.pageData("Health", "health")
	data["HostNames"] = hostNames
	data["Matrix"] = matrix
	data["Alerts"] = cs.GetAlerts()
	data["Events"] = audit.GetEntries()
	s.renderPage(w, "health_timeline.html", data)
}

func (s *Server) handleHealthTimelinePartial(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetHostHealth(ctx, &emptypb.Empty{})
	cs, _ := s.grpc.GetClusterStatus(ctx, &emptypb.Empty{})

	hostSet := map[string]bool{}
	for _, e := range health.GetEntries() {
		hostSet[e.Observer] = true
		hostSet[e.Target] = true
	}
	var hostNames []string
	for h := range hostSet {
		hostNames = append(hostNames, h)
	}
	matrix := map[string]map[string]string{}
	for _, e := range health.GetEntries() {
		if matrix[e.Observer] == nil {
			matrix[e.Observer] = map[string]string{}
		}
		matrix[e.Observer][e.Target] = e.Status
	}

	s.renderPartial(w, "health_timeline.html", "health-matrix", map[string]any{
		"HostNames":   hostNames,
		"Matrix":      matrix,
		"Alerts":      cs.GetAlerts(),
		"ClusterName": s.cluster,
	})
}
