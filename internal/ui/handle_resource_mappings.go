package ui

import (
	"net/http"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Resource-mapping CRUD runs in-process against the host-local Corrosion handle
// (same as the `lv mapping` CLI), CRDT-replicating cluster-wide. These handlers
// sit behind the UI's authenticated session (see docs/ui.md).

// handleResourceMappings renders /resource-mappings: each mapping with its
// per-host devices, plus create / add-device / delete actions (#14).
func (s *Server) handleResourceMappings(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Resource Mappings", "resource-mappings")
	if s.db == nil {
		data["Error"] = "corrosion DB not wired into UI server (build mismatch)"
		s.renderPage(w, "resource_mappings.html", data)
		return
	}
	mappings, err := corrosion.ListResourceMappings(r.Context(), s.db)
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "resource_mappings.html", data)
		return
	}
	data["Mappings"] = mappings
	s.renderPage(w, "resource_mappings.html", data)
}

func (s *Server) handleMappingCreateModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "mapping_create_modal.html", nil)
}

func (s *Server) handleCreateMapping(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		sendToast(w, "Name is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := corrosion.CreateResourceMapping(r.Context(), s.db, name, strings.TrimSpace(r.FormValue("description"))); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Resource mapping "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := corrosion.DeleteResourceMapping(r.Context(), s.db, r.PathValue("name")); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Resource mapping deleted", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMappingDeviceModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "mapping_device_modal.html", map[string]any{"Mapping": r.PathValue("name")})
}

func (s *Server) handleAddMappingDeviceUI(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mapping := r.PathValue("name")
	host := strings.TrimSpace(r.FormValue("host"))
	address := strings.TrimSpace(r.FormValue("address"))
	if host == "" || address == "" {
		sendToast(w, "Host and PCI address are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := corrosion.AddMappingDevice(r.Context(), s.db, mapping, host, address,
		strings.TrimSpace(r.FormValue("vendor")), strings.TrimSpace(r.FormValue("device"))); err != nil {
		sendToast(w, "Add device failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Device added to "+mapping, "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRemoveMappingDeviceUI(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	mapping := r.PathValue("name")
	host := r.URL.Query().Get("host")
	address := r.URL.Query().Get("address")
	if err := corrosion.RemoveMappingDevice(r.Context(), s.db, mapping, host, address); err != nil {
		sendToast(w, "Remove device failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Device removed", "success")
	w.Header().Set("HX-Redirect", "/resource-mappings")
	w.WriteHeader(http.StatusOK)
}
