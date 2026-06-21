package ui

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/litevirt/litevirt/internal/cephdeploy"
)

// handleCephDashboard renders /storage/ceph: cluster health, MON / OSD
// counts, and the CRUSH topology. We always go through cephdeploy's
// Runner abstraction so a future gRPC call can replace the local
// shell-out without changing the page.
func (s *Server) handleCephDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	runner := cephdeploy.NewCephadmRunner()
	data := s.pageData("Ceph", "storage")
	data["Available"] = false

	st, err := runner.Status(ctx)
	if err != nil {
		// Most common case in homelab: cephadm/ceph not installed yet.
		// Render a friendly empty-state page rather than 500.
		slog.Info("ceph dashboard: status unavailable", "error", err)
		data["Error"] = err.Error()
	} else {
		data["Available"] = true
		data["Status"] = st
		if tree, terr := runner.OSDTree(ctx); terr == nil {
			data["Tree"] = tree
		}
	}
	s.renderPage(w, "ceph.html", data)
}
