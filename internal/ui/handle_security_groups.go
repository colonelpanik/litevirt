package ui

import (
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Security groups are READ in-process against the host-local Corrosion handle
// (the same DB the rest of the read path uses), but every mutation goes through
// the daemon's security-group RPCs (internal/grpcapi/security_groups.go) with
// the session's bearer, so the daemon's own interceptor and RequirePerm decide
// (colonelpanik/litevirt#182).
//
// The pages used to write in-process behind an in-process check that resolved
// the caller from INCOMING gRPC metadata the UI never has, so on a cluster
// without strict mTLS identity it authorized every session as the bearerless
// admin: a Viewer could create and delete security groups and rules. That check
// also asked for the generic "write" verb at "/", which only Admin's "*"
// grants, so a NetworkAdmin (sg.*) was refused. Routing through the RPCs leaves
// one check and one audit row, written by the handler that performed the
// change.

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

// sgWriteFailed reports a refused or failed security-group RPC. The status
// comes from the gRPC code, so the daemon's PermissionDenied reaches the
// browser as 403 rather than as a server fault.
func sgWriteFailed(w http.ResponseWriter, what string, err error) {
	sendToast(w, what+" failed: "+err.Error(), "error")
	w.WriteHeader(httpStatusFor(err))
}

// handleCreateSG creates a security group through CreateSecurityGroup.
func (s *Server) handleCreateSG(w http.ResponseWriter, r *http.Request) {
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
	if _, err := s.grpc.CreateSecurityGroup(s.uiBearerCtx(r), &pb.CreateSecurityGroupRequest{
		Name: name, StackName: strings.TrimSpace(r.FormValue("stack")),
	}); err != nil {
		sgWriteFailed(w, "Create", err)
		return
	}
	sendToast(w, "Security group "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSG removes a security group and its rules through
// DeleteSecurityGroup.
func (s *Server) handleDeleteSG(w http.ResponseWriter, r *http.Request) {
	if _, err := s.grpc.DeleteSecurityGroup(s.uiBearerCtx(r),
		&pb.DeleteSecurityGroupRequest{Id: r.PathValue("id")}); err != nil {
		sgWriteFailed(w, "Delete", err)
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

// handleAddSGRule appends a rule to a security group through
// AddSecurityGroupRule.
func (s *Server) handleAddSGRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Parsed at 32 bits, and any error (empty, junk, out of range) reads as 0,
	// the default, rather than wrapping into some other priority.
	priority, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("priority")), 10, 32)
	if err != nil {
		priority = 0
	}
	if _, err := s.grpc.AddSecurityGroupRule(s.uiBearerCtx(r), &pb.AddSecurityGroupRuleRequest{
		Rule: &pb.SecurityGroupRule{
			SgId:      r.PathValue("id"),
			Direction: r.FormValue("direction"),
			Proto:     r.FormValue("proto"),
			Port:      strings.TrimSpace(r.FormValue("port_range")),
			Cidr:      strings.TrimSpace(r.FormValue("cidr")),
			Action:    r.FormValue("action"),
			Priority:  int32(priority),
		},
	}); err != nil {
		sgWriteFailed(w, "Add rule", err)
		return
	}
	sendToast(w, "Rule added", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSGRule removes a single rule through RemoveSecurityGroupRule.
func (s *Server) handleDeleteSGRule(w http.ResponseWriter, r *http.Request) {
	if _, err := s.grpc.RemoveSecurityGroupRule(s.uiBearerCtx(r),
		&pb.RemoveSecurityGroupRuleRequest{Id: r.PathValue("rule")}); err != nil {
		sgWriteFailed(w, "Delete rule", err)
		return
	}
	sendToast(w, "Rule removed", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}
