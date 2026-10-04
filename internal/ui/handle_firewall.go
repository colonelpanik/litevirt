package ui

import (
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Distributed-firewall management for the cluster/host tiers, named ip sets,
// and the default-deny policy (v21). The per-NIC tier (security groups) has its
// own page at /security-groups.
//
// READS use the host-local Corrosion handle directly, which is cheap and needs
// no RPC. WRITES go through the gRPC twin, because that is where authorization
// lives: RequirePerm consults the token's scope paths and the caller's RBAC
// bindings, neither of which is visible from the coarse role string the HTTP
// session gate can see. Writing corrosion rows from this process left
// cluster-wide firewall state with no authorization in front of it.

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

// ruleFromForm builds a pb.FirewallRule from the shared rule form.
//
// pb, not corrosion: these handlers go through the gRPC twin so the daemon
// authorizes them. Writing corrosion rows straight from the UI process left
// cluster-wide firewall state with no authorization in front of it at all --
// the HTTP gate ahead of it could only see a coarse role string, which neither
// honours a token's scope paths nor sees an RBAC binding.
func ruleFromForm(r *http.Request) *pb.FirewallRule {
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))
	return &pb.FirewallRule{
		HostName:  strings.TrimSpace(r.FormValue("host_name")),
		Direction: r.FormValue("direction"),
		Proto:     r.FormValue("proto"),
		Port:      strings.TrimSpace(r.FormValue("port_range")),
		Cidr:      strings.TrimSpace(r.FormValue("cidr")),
		Action:    r.FormValue("action"),
		Priority:  int32(priority),
		Comment:   strings.TrimSpace(r.FormValue("comment")),
	}
}

func (s *Server) handleCreateFWClusterRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	_ = r.ParseForm()
	rule := ruleFromForm(r)
	rule.Id = randid.New()
	if _, err := s.grpc.CreateClusterFirewallRule(s.uiBearerCtx(r),
		&pb.CreateClusterFirewallRuleRequest{Rule: rule}); err != nil {
		sendToast(w, "Add failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	s.fwRedirect(w, "Cluster rule added")
}

func (s *Server) handleDeleteFWClusterRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if _, err := s.grpc.DeleteClusterFirewallRule(s.uiBearerCtx(r),
		&pb.DeleteClusterFirewallRuleRequest{Id: r.PathValue("id")}); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
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
	rule.Id = randid.New()
	if _, err := s.grpc.CreateHostFirewallRule(s.uiBearerCtx(r),
		&pb.CreateHostFirewallRuleRequest{Rule: rule}); err != nil {
		sendToast(w, "Add failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	s.fwRedirect(w, "Host rule added")
}

func (s *Server) handleDeleteFWHostRule(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if _, err := s.grpc.DeleteHostFirewallRule(s.uiBearerCtx(r),
		&pb.DeleteHostFirewallRuleRequest{Id: r.PathValue("id")}); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
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
	if _, err := s.grpc.CreateIpSet(s.uiBearerCtx(r),
		&pb.CreateIpSetRequest{Name: name, Cidrs: cidrs}); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	s.fwRedirect(w, "IP set "+name+" created")
}

func (s *Server) handleDeleteFWIPSet(w http.ResponseWriter, r *http.Request) {
	if !s.fwDBReady(w) {
		return
	}
	if _, err := s.grpc.DeleteIpSet(s.uiBearerCtx(r),
		&pb.DeleteIpSetRequest{Id: r.PathValue("id")}); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
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
	if _, err := s.grpc.SetFirewallDefault(s.uiBearerCtx(r),
		&pb.SetFirewallDefaultRequest{Scope: "cluster", DefaultDeny: deny}); err != nil {
		sendToast(w, "Update failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
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
