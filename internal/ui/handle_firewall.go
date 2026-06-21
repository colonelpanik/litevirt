package ui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Distributed-firewall management for the cluster/host tiers, named ip sets,
// and the default-deny policy (v21). The per-NIC tier (security groups) has its
// own page at /security-groups. Like the SG handlers, writes go in-process to
// the host-local Corrosion handle (CRDT-replicated); each host's reconciler
// re-renders on its next tick. Behind the UI's authenticated session.

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Firewall", "firewall")
	if s.db == nil {
		data["Error"] = "corrosion DB not wired into UI server (build mismatch)"
		s.renderPage(w, "firewall.html", data)
		return
	}
	clusterRules, err := corrosion.ListClusterFirewallRules(r.Context(), s.db)
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "firewall.html", data)
		return
	}
	hostRules, _ := corrosion.ListHostFirewallRules(r.Context(), s.db, "")
	ipsets, _ := corrosion.ListIPSets(r.Context(), s.db)
	clusterDefault, _ := corrosion.GetFirewallDefault(r.Context(), s.db, "cluster")

	data["ClusterRules"] = clusterRules
	data["HostRules"] = hostRules
	data["IPSets"] = ipsets
	data["DefaultDeny"] = clusterDefault != nil && clusterDefault.DefaultDeny
	s.renderPage(w, "firewall.html", data)
}

func (s *Server) handleFWClusterRuleModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "firewall_rule_modal.html", map[string]any{"Tier": "cluster"})
}

func (s *Server) handleFWHostRuleModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "firewall_rule_modal.html", map[string]any{"Tier": "host"})
}

func (s *Server) handleFWIPSetModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "firewall_ipset_modal.html", nil)
}

// ruleFromForm builds a corrosion.FirewallRule from the shared rule form.
func ruleFromForm(r *http.Request) corrosion.FirewallRule {
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))
	return corrosion.FirewallRule{
		HostName:  strings.TrimSpace(r.FormValue("host_name")),
		Direction: r.FormValue("direction"),
		Proto:     r.FormValue("proto"),
		PortRange: strings.TrimSpace(r.FormValue("port_range")),
		CIDR:      strings.TrimSpace(r.FormValue("cidr")),
		Action:    r.FormValue("action"),
		Priority:  priority,
		Comment:   strings.TrimSpace(r.FormValue("comment")),
	}
}

func (s *Server) handleCreateFWClusterRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	_ = r.ParseForm()
	rule := ruleFromForm(r)
	rule.ID = mustUIID()
	if err := corrosion.InsertClusterFirewallRule(r.Context(), s.db, rule); err != nil {
		sendToast(w, "Add failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.fwRedirect(w, "Cluster rule added")
}

func (s *Server) handleDeleteFWClusterRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if err := corrosion.DeleteClusterFirewallRule(r.Context(), s.db, r.PathValue("id")); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.fwRedirect(w, "Cluster rule removed")
}

func (s *Server) handleCreateFWHostRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	_ = r.ParseForm()
	rule := ruleFromForm(r)
	if rule.HostName == "" {
		sendToast(w, "Host is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	rule.ID = mustUIID()
	if err := corrosion.InsertHostFirewallRule(r.Context(), s.db, rule); err != nil {
		sendToast(w, "Add failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.fwRedirect(w, "Host rule added")
}

func (s *Server) handleDeleteFWHostRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if err := corrosion.DeleteHostFirewallRule(r.Context(), s.db, r.PathValue("id")); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.fwRedirect(w, "Host rule removed")
}

func (s *Server) handleCreateFWIPSet(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		sendToast(w, "Name is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Accept comma- or newline-separated CIDRs.
	var cidrs []string
	for _, f := range strings.FieldsFunc(r.FormValue("cidrs"), func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
		if c := strings.TrimSpace(f); c != "" {
			cidrs = append(cidrs, c)
		}
	}
	if err := corrosion.InsertIPSet(r.Context(), s.db, corrosion.IPSet{ID: mustUIID(), Name: name, CIDRs: cidrs}); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.fwRedirect(w, "IP set "+name+" created")
}

func (s *Server) handleDeleteFWIPSet(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if err := corrosion.DeleteIPSet(r.Context(), s.db, r.PathValue("id")); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.fwRedirect(w, "IP set removed")
}

func (s *Server) handleSetFWDefaultDeny(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	_ = r.ParseForm()
	deny := r.FormValue("deny") == "on" || r.FormValue("deny") == "true"
	if err := corrosion.SetFirewallDefault(r.Context(), s.db, "cluster", deny, ""); err != nil {
		sendToast(w, "Update failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	verdict := "accept"
	if deny {
		verdict = "deny"
	}
	s.fwRedirect(w, "Cluster default policy set to "+verdict)
}

// fwDBReady guards handlers that need the cluster DB; writes a toast + status
// and returns false if it's missing.
func (s *Server) fwDBReady(w http.ResponseWriter) bool {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}
	return true
}

// fwRedirect sends a success toast and an HX-Redirect back to /firewall.
func (s *Server) fwRedirect(w http.ResponseWriter, msg string) {
	sendToast(w, msg, "success")
	w.Header().Set("HX-Redirect", "/firewall")
	w.WriteHeader(http.StatusOK)
}

// mustUIID returns a random hex id. newUIID only errors if crypto/rand fails,
// which doesn't happen on a real host; the empty-string fallback is never hit
// in practice.
func mustUIID() string {
	id, _ := newUIID()
	return id
}
