package ui

import (
	"net/http"
	"sort"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// rbacNode is a path-prefix tree node assembled from role_bindings.
// Each node carries the bindings attached at that exact path; child
// nodes carry bindings on longer paths. Rendered recursively in the
// template.
type rbacNode struct {
	Segment  string // last path segment, e.g. "vms" or "vm-1"
	Path     string // full path, e.g. "/projects/_default/vms"
	Bindings []corrosion.RoleBindingRecord
	Children []*rbacNode
}

// handleRBACBindingModal renders the "Add role binding" modal, optionally
// pre-filling the path (when launched from a tree node).
func (s *Server) handleRBACBindingModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "rbac_binding_modal.html", map[string]any{
		"Path":  r.URL.Query().Get("path"),
		"Roles": []string{"viewer", "operator", "admin"},
	})
}

// handleGrantRole creates a role binding via the auth gRPC. Mirrors
// `lv auth grant`.
func (s *Server) handleGrantRole(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	role := strings.TrimSpace(r.FormValue("role"))
	principal := strings.TrimSpace(r.FormValue("principal"))
	if path == "" || role == "" || principal == "" {
		sendToast(w, "path, role and principal are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err := s.grpc.GrantRole(s.uiBearerCtx(r), &pb.GrantRoleRequest{
		Path: path, Role: role, Principal: principal, Propagate: r.FormValue("propagate") == "on",
	})
	if err != nil {
		sendToast(w, "Grant failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Granted "+role+" on "+path+" to "+principal, "success")
	w.Header().Set("HX-Redirect", "/rbac")
	w.WriteHeader(http.StatusOK)
}

// handleRevokeRole removes a role binding by id. Mirrors `lv auth revoke`.
func (s *Server) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.grpc.RevokeRole(s.uiBearerCtx(r), &pb.RevokeRoleRequest{Id: id}); err != nil {
		sendToast(w, "Revoke failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Role binding revoked", "success")
	w.Header().Set("HX-Redirect", "/rbac")
	w.WriteHeader(http.StatusOK)
}

// handleRBAC renders /rbac — the path-rooted role-binding tree, with
// add-binding and revoke actions.
func (s *Server) handleRBAC(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("RBAC", "rbac")
	if s.db == nil {
		data["Error"] = "Corrosion DB not wired into UI server."
		s.renderPage(w, "rbac.html", data)
		return
	}
	bindings, err := corrosion.ListRoleBindings(r.Context(), s.db)
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "rbac.html", data)
		return
	}
	data["Tree"] = buildRBACTree(bindings)
	data["BindingCount"] = len(bindings)
	s.renderPage(w, "rbac.html", data)
}

func buildRBACTree(bindings []corrosion.RoleBindingRecord) *rbacNode {
	root := &rbacNode{Path: "/", Segment: "/"}
	nodeByPath := map[string]*rbacNode{"/": root}

	var ensure func(path string) *rbacNode
	ensure = func(path string) *rbacNode {
		if n, ok := nodeByPath[path]; ok {
			return n
		}
		idx := strings.LastIndex(path, "/")
		parentPath := "/"
		if idx > 0 {
			parentPath = path[:idx]
		}
		parent := ensure(parentPath)
		seg := path[idx+1:]
		if seg == "" {
			seg = path
		}
		n := &rbacNode{Path: path, Segment: seg}
		parent.Children = append(parent.Children, n)
		nodeByPath[path] = n
		return n
	}

	for _, b := range bindings {
		p := b.Path
		if p == "" {
			p = "/"
		}
		ensure(p).Bindings = append(ensure(p).Bindings, b)
	}

	// Sort children alphabetically for stable rendering.
	var sortRec func(n *rbacNode)
	sortRec = func(n *rbacNode) {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Segment < n.Children[j].Segment })
		for _, c := range n.Children {
			sortRec(c)
		}
	}
	sortRec(root)
	return root
}
