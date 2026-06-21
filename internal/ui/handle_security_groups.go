package ui

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Security-group CRUD is performed in-process against the host-local Corrosion
// handle (the same DB the read path uses), which CRDT-replicates the change
// cluster-wide exactly like the `lv sg` CLI's direct writes; each host's
// firewall reconciler re-renders on its next tick. These handlers run behind
// the UI's authenticated session but do NOT pass the gRPC RBAC interceptor —
// treat SG edits as an operator action (see docs/ui.md).

// handleSecurityGroups renders /security-groups: every SG with its rules, plus
// create / add-rule / delete actions.
func (s *Server) handleSecurityGroups(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Security Groups", "security-groups")

	if s.db == nil {
		data["Error"] = "corrosion DB not wired into UI server (build mismatch)"
		s.renderPage(w, "security_groups.html", data)
		return
	}

	sgs, err := corrosion.ListSecurityGroups(r.Context(), s.db, "")
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "security_groups.html", data)
		return
	}

	type sgRow struct {
		ID, Name, Stack string
		Rules           []corrosion.SGRule
	}
	rows := make([]sgRow, 0, len(sgs))
	for _, sg := range sgs {
		rules, _ := corrosion.ListSGRules(r.Context(), s.db, sg.ID)
		rows = append(rows, sgRow{
			ID: sg.ID, Name: sg.Name, Stack: sg.StackName, Rules: rules,
		})
	}
	data["Groups"] = rows
	s.renderPage(w, "security_groups.html", data)
}

// handleSGCreateModal renders the "Create security group" modal.
func (s *Server) handleSGCreateModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_create_modal.html", nil)
}

// handleCreateSG creates a security group. Mirrors `lv sg create`.
func (s *Server) handleCreateSG(w http.ResponseWriter, r *http.Request) {
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
	id, err := newUIID()
	if err != nil {
		sendToast(w, "id generation failed", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := corrosion.InsertSecurityGroup(r.Context(), s.db, corrosion.SecurityGroup{
		ID: id, Name: name, StackName: strings.TrimSpace(r.FormValue("stack")),
	}); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Security group "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSG removes a security group and its rules. Mirrors `lv sg rm`.
func (s *Server) handleDeleteSG(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	_ = corrosion.DeleteSGRules(r.Context(), s.db, id)
	if err := corrosion.DeleteSecurityGroup(r.Context(), s.db, id); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Security group deleted", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleSGRuleModal renders the "Add rule" modal for one SG.
func (s *Server) handleSGRuleModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_rule_modal.html", map[string]any{"SGID": r.PathValue("id")})
}

// handleAddSGRule appends a rule to a security group. Mirrors `lv sg rule-add`.
func (s *Server) handleAddSGRule(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	sgID := r.PathValue("id")
	id, err := newUIID()
	if err != nil {
		sendToast(w, "id generation failed", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))
	if err := corrosion.InsertSGRule(r.Context(), s.db, corrosion.SGRule{
		ID:        id,
		SGID:      sgID,
		Direction: r.FormValue("direction"),
		Proto:     r.FormValue("proto"),
		PortRange: strings.TrimSpace(r.FormValue("port_range")),
		CIDR:      strings.TrimSpace(r.FormValue("cidr")),
		Action:    r.FormValue("action"),
		Priority:  priority,
	}); err != nil {
		sendToast(w, "Add rule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Rule added", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSGRule removes a single rule.
func (s *Server) handleDeleteSGRule(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := corrosion.DeleteSGRule(r.Context(), s.db, r.PathValue("rule")); err != nil {
		sendToast(w, "Delete rule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Rule removed", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// newUIID generates a random hex id (matches the `lv` CLI's newID scheme).
func newUIID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
