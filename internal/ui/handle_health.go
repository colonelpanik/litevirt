package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// healthView derives the template inputs from the one health read: the
// connectivity matrix (observer→target status) and the host list it spans.
func healthView(h *pb.ClusterHealth) (hostNames []string, matrix map[string]map[string]string) {
	hostSet := map[string]bool{}
	for _, e := range h.GetConnectivity() {
		hostSet[e.Observer] = true
		hostSet[e.Target] = true
	}
	for name := range hostSet {
		hostNames = append(hostNames, name)
	}
	matrix = map[string]map[string]string{}
	for _, e := range h.GetConnectivity() {
		if matrix[e.Observer] == nil {
			matrix[e.Observer] = map[string]string{}
		}
		matrix[e.Observer][e.Target] = e.Status
	}
	return hostNames, matrix
}

func (s *Server) handleHealthTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	audit, _ := s.grpc.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 50})

	hostNames, matrix := healthView(health)
	data := s.pageData("Health", "health")
	data["HostNames"] = hostNames
	data["Matrix"] = matrix
	data["Overall"] = health.GetOverall()
	data["Conditions"] = health.GetConditions()
	data["Evaluators"] = health.GetEvaluators()
	data["Events"] = audit.GetEntries()
	s.renderPage(w, "health_timeline.html", data)
}

func (s *Server) handleHealthTimelinePartial(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	health, _ := s.grpc.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})

	hostNames, matrix := healthView(health)
	s.renderPartial(w, "health_timeline.html", "health-matrix", map[string]any{
		"HostNames":   hostNames,
		"Matrix":      matrix,
		"Overall":     health.GetOverall(),
		"Conditions":  health.GetConditions(),
		"ClusterName": s.cluster,
	})
}
