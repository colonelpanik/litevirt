package ui

import (
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) handleExecModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "exec_modal.html", map[string]any{
		"VMName": name,
	})
}

func (s *Server) handleExecVM(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	cmdStr := strings.TrimSpace(r.FormValue("command"))
	if cmdStr == "" {
		http.Error(w, "command required", 400)
		return
	}

	// Split command string into executable + args.
	parts := strings.Fields(cmdStr)

	resp, err := s.grpc.ExecVM(s.uiBearerCtx(r), &pb.ExecVMRequest{
		Name:    name,
		Command: parts,
	})
	if err != nil {
		s.renderFragment(w, "exec_output.html", map[string]any{
			"Error": err.Error(),
		})
		return
	}
	s.renderFragment(w, "exec_output.html", map[string]any{
		"ExitCode": resp.ExitCode,
		"Stdout":   string(resp.Stdout),
		"Stderr":   string(resp.Stderr),
	})
}
