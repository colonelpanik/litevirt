package ui

import (
	"fmt"
	"net/http"
	"strconv"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// uiQueryInt reads a non-negative integer query parameter; absent or
// unparseable reads as 0, so a hand-edited URL lands on the first page rather
// than an error.
func uiQueryInt(r *http.Request, key string) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// handleRebalance renders /rebalance — the placement rebalancer's proposal queue
// with run/approve/reject actions. Mirrors `lv rebalance list/run/approve/reject`.
func (s *Server) handleRebalance(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Rebalance", "rebalance")
	statusFilter := r.URL.Query().Get("status")
	offset := uiQueryInt(r, "offset")
	data["StatusFilter"] = statusFilter
	data["Offset"] = offset
	resp, err := s.grpc.ListRebalanceProposals(s.uiBearerCtx(r),
		&pb.ListRebalanceProposalsRequest{
			StatusFilter: statusFilter,
			Offset:       int32(offset),
		})
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Proposals"] = resp.Proposals
		// The page header counts the whole table, not this page: rendering
		// len(Proposals) as the count would report 200 on a 60k-row table.
		data["TotalCount"] = int(resp.GetTotalCount())
		data["Truncated"] = resp.GetTruncated()
		data["NextOffset"] = offset + len(resp.GetProposals())
		data["PrevOffset"] = max(0, offset-len(resp.GetProposals()))
		data["ShowFrom"] = offset + 1
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
