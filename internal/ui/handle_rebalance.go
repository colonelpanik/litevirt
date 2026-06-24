package ui

import (
	"fmt"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleRebalance renders /rebalance — the placement rebalancer's proposal queue
// with run/approve/reject actions. Mirrors `lv rebalance list/run/approve/reject`.
func (s *Server) handleRebalance(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Rebalance", "rebalance")
	statusFilter := r.URL.Query().Get("status")
	data["StatusFilter"] = statusFilter
	resp, err := s.grpc.ListRebalanceProposals(s.uiBearerCtx(r),
		&pb.ListRebalanceProposalsRequest{StatusFilter: statusFilter})
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Proposals"] = resp.Proposals
	}
	s.renderPage(w, "rebalance.html", data)
}

// handleRebalanceRun forces one evaluation cycle. ?dry_run=true mirrors the CLI's
// --dry-run, which records proposals regardless of each VM's resolved mode.
func (s *Server) handleRebalanceRun(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	resp, err := s.grpc.RunRebalance(s.uiBearerCtx(r), &pb.RunRebalanceRequest{DryRun: dryRun})
	if err != nil {
		sendToast(w, "Run failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, fmt.Sprintf("Emitted %d new proposal(s)", resp.ProposalsEmitted), "success")
	w.Header().Set("HX-Redirect", "/rebalance")
	w.WriteHeader(http.StatusOK)
}

// handleRebalanceApprove approves a pending proposal; the leader's rebalance
// executor then live-migrates it. Mirrors `lv rebalance approve <id>`.
func (s *Server) handleRebalanceApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.grpc.ApproveRebalanceProposal(s.uiBearerCtx(r), &pb.ApproveRebalanceProposalRequest{Id: id})
	if err != nil {
		sendToast(w, "Approve failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, fmt.Sprintf("Proposal approved (%s → %s for %s)", p.SrcHost, p.DstHost, p.VmName), "success")
	w.Header().Set("HX-Redirect", "/rebalance")
	w.WriteHeader(http.StatusOK)
}

// handleRebalanceReject rejects a pending proposal. The optional reason comes from
// the HTMX hx-prompt header. Mirrors `lv rebalance reject <id> --reason`.
func (s *Server) handleRebalanceReject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reason := r.Header.Get("HX-Prompt")
	if _, err := s.grpc.RejectRebalanceProposal(s.uiBearerCtx(r), &pb.RejectRebalanceProposalRequest{Id: id, Reason: reason}); err != nil {
		sendToast(w, "Reject failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Proposal "+id+" rejected", "success")
	w.Header().Set("HX-Redirect", "/rebalance")
	w.WriteHeader(http.StatusOK)
}
