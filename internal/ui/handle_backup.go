package ui

import (
	"net/http"
)

// handleRestoreModal is DEPRECATED alongside handleRestoreVM — the raw
// restore-from-file flow is retired in favor of repo-backed restore.
func (s *Server) handleRestoreModal(w http.ResponseWriter, r *http.Request) {
	sendToast(w, "Raw restore-from-file is deprecated; restore from a backup repo snapshot instead.", "error")
	w.WriteHeader(http.StatusGone)
}

// handleRestoreVM is DEPRECATED. Raw restore-from-uploaded-file is retired in
// favor of the repo-backed restore (Restore from a backup snapshot). The
// underlying RestoreVM RPC now returns Unimplemented, so this surfaces a clear
// message instead of streaming into a dead RPC.
func (s *Server) handleRestoreVM(w http.ResponseWriter, r *http.Request) {
	sendToast(w, "Raw restore-from-file is deprecated; restore from a backup repo snapshot instead.", "error")
	w.WriteHeader(http.StatusGone)
}
