package ui

import (
	"net/http"
	"sort"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// parseTags turns a "env=prod, team=infra, gpu" string into a label map. A bare
// token (no '=') becomes a key with an empty value. Returns nil when empty.
func parseTags(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if found {
			out[k] = strings.TrimSpace(v)
		} else {
			out[k] = ""
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// labelsToString renders a label map back to a stable "k=v, k2=v2" string for
// prefilling the edit field (bare keys when the value is empty).
func labelsToString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if labels[k] == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+labels[k])
		}
	}
	return strings.Join(parts, ", ")
}

// handleVMTagsModal renders the tag editor prefilled with the VM's current tags.
func (s *Server) handleVMTagsModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	vm, err := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name})
	if err != nil {
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}
	cur := ""
	if vm.Spec != nil {
		cur = labelsToString(vm.Spec.Labels)
	}
	s.renderFragment(w, "vm_tags_modal.html", map[string]any{"Name": name, "Tags": cur})
}

// handleSetVMTags applies the edited tag set via SetVMLabels (metadata-only,
// works on running VMs).
func (s *Server) handleSetVMTags(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	labels := parseTags(r.FormValue("tags"))
	if _, err := s.grpc.SetVMLabels(s.uiBearerCtx(r), &pb.SetVMLabelsRequest{Name: name, Labels: labels}); err != nil {
		sendToast(w, "Set tags failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusOK)
		return
	}
	sendToast(w, "Tags updated", "success")
	w.Header().Set("HX-Redirect", "/vms/"+name)
	w.WriteHeader(http.StatusOK)
}
