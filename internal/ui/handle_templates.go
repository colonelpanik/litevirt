package ui

import (
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleCloneModal renders the clone dialog for a template or stopped VM.
func (s *Server) handleCloneModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	vm, _ := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name})
	isTemplate := vm != nil && vm.IsTemplate
	s.renderFragment(w, "clone_modal.html", map[string]any{
		"Source":     name,
		"IsTemplate": isTemplate,
		"Suggested":  name + "-clone",
	})
}

// handleCloneVM clones a template/VM. Storage-aware default mode; the clone
// gets a fresh identity (new MACs + regenerated cloud-init).
func (s *Server) handleCloneVM(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := r.FormValue("target")
	if target == "" {
		sendToast(w, "Clone needs a name", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	vm, err := s.grpc.CloneVM(s.uiBearerCtx(r), &pb.CloneVMRequest{
		Source: source,
		Target: target,
		Mode:   r.FormValue("mode"), // "" (auto) | linked | full
		Ip:     r.FormValue("ip"),
		Start:  r.FormValue("start") == "on",
	})
	if err != nil {
		sendToast(w, "Clone failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Cloned "+source+" → "+vm.Name, "success")
	w.Header().Set("HX-Redirect", "/vms/"+vm.Name)
	w.WriteHeader(http.StatusOK)
}

// handleConvertTemplate converts a stopped VM to a template, or reverts one
// (form value revert=on).
func (s *Server) handleConvertTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = r.ParseForm()
	revert := r.FormValue("revert") == "on"
	_, err := s.grpc.ConvertToTemplate(s.uiBearerCtx(r), &pb.ConvertToTemplateRequest{
		Name:   name,
		Revert: revert,
	})
	if err != nil {
		sendToast(w, "Operation failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if revert {
		sendToast(w, name+" reverted to a normal VM", "success")
	} else {
		sendToast(w, name+" is now a template", "success")
	}
	w.Header().Set("HX-Redirect", "/vms/"+name)
	w.WriteHeader(http.StatusOK)
}
