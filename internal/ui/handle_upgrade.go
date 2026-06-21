package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) handleUpgradeModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "upgrade_modal.html", map[string]any{
		"HostName": name,
	})
}

func (s *Server) handleUpgradeHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseMultipartForm(256 << 20); err != nil { // 256MB max
		http.Error(w, "bad form: "+err.Error(), 400)
		return
	}

	file, _, err := r.FormFile("binary")
	if err != nil {
		http.Error(w, "binary file required", 400)
		return
	}
	defer file.Close()

	// Read entire file to compute checksum (binaries are typically <20MB)
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error: "+err.Error(), 500)
		return
	}
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	stream, err := s.grpc.UpgradeHost(s.uiBearerCtx(r))
	if err != nil {
		http.Error(w, "Upgrade failed: "+err.Error(), 500)
		return
	}

	// Send in 256KB chunks
	chunkSize := 256 * 1024
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		req := &pb.UpgradeHostRequest{
			Chunk: data[i:end],
		}
		if i == 0 {
			req.Checksum = checksum
			req.TargetHost = name
		}
		if err := stream.Send(req); err != nil {
			slog.Error("upgrade stream send error", "error", err)
			sendToast(w, "Upgrade failed: "+err.Error(), "error")
			w.WriteHeader(500)
			return
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		slog.Error("upgrade close error", "error", err)
		sendToast(w, "Upgrade failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}

	sendToast(w, "Host '"+resp.HostName+"' upgraded: "+resp.OldVersion+" → "+resp.NewVersion, "success")
	w.Header().Set("HX-Redirect", "/hosts/"+name)
	w.WriteHeader(http.StatusOK)
}
