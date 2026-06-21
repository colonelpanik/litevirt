package ui

import (
	"net/http"

	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	digest, err := s.grpc.GetStateDigest(s.uiBearerCtx(r), &emptypb.Empty{})
	data := s.pageData("Diagnostics", "diagnostics")
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Tables"] = digest.GetTables()
	}
	s.renderPage(w, "diagnostics.html", data)
}

func (s *Server) handleDiagnosticsPartial(w http.ResponseWriter, r *http.Request) {
	digest, err := s.grpc.GetStateDigest(s.uiBearerCtx(r), &emptypb.Empty{})
	data := map[string]any{"ClusterName": s.cluster}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Tables"] = digest.GetTables()
	}
	s.renderPartial(w, "diagnostics.html", "diagnostics-table", data)
}

func (s *Server) handleForceSync(w http.ResponseWriter, r *http.Request) {
	// GetStateDump triggers a full state dump which can be used to force resync.
	_, err := s.grpc.GetStateDump(s.uiBearerCtx(r), &emptypb.Empty{})
	if err != nil {
		sendToast(w, "Sync failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "State sync triggered", "success")
	w.WriteHeader(http.StatusOK)
}
