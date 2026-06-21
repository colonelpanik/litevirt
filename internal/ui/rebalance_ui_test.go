package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ── /rebalance page ───────────────────────────────────────────────────────────

func TestRebalancePage_RendersProposals(t *testing.T) {
	mock := newDefaultMock()
	mock.listRebalanceResp = &pb.ListRebalanceProposalsResponse{
		Proposals: []*pb.RebalanceProposal{{
			Id: "p1", VmName: "vm1", SrcHost: "host1", DstHost: "host2",
			Policy: "balance", ExpectedGain: 12.34, Status: "pending", ProposedAt: "2026-06-04T00:00:00Z",
		}},
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/rebalance")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "vm1")
	assertContains(t, w, "host1 → host2")
	assertContains(t, w, "12.3") // %.1f formatting
	assertContains(t, w, "Run now")
	assertContains(t, w, "/ui/rebalance/p1/approve")
	assertContains(t, w, "/ui/rebalance/p1/reject")
}

func TestRebalancePage_StatusFilterForwarded(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/rebalance?status=approved")))
	assertStatus(t, w, http.StatusOK)
	if mock.lastListRebalanceReq == nil || mock.lastListRebalanceReq.StatusFilter != "approved" {
		t.Errorf("StatusFilter = %+v, want approved", mock.lastListRebalanceReq)
	}
}

func TestRebalancePage_EmptyState(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/rebalance")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "No proposals")
}

func TestRebalancePage_OnlyPendingHaveActions(t *testing.T) {
	mock := newDefaultMock()
	mock.listRebalanceResp = &pb.ListRebalanceProposalsResponse{
		Proposals: []*pb.RebalanceProposal{{Id: "applied1", VmName: "vm9", Status: "applied"}},
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/rebalance")))
	assertStatus(t, w, http.StatusOK)
	if bodyHas(w.Body.String(), "/ui/rebalance/applied1/approve") {
		t.Error("non-pending proposal should not render approve action")
	}
}

// ── handleRebalanceRun ────────────────────────────────────────────────────────

func TestRebalanceRun_Default(t *testing.T) {
	mock := newDefaultMock()
	mock.runRebalanceResp = &pb.RunRebalanceResponse{ProposalsEmitted: 3}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/run")))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/rebalance")
	assertToast(t, w, "3")
	if mock.lastRunRebalanceReq == nil || mock.lastRunRebalanceReq.DryRun {
		t.Errorf("DryRun = %+v, want false", mock.lastRunRebalanceReq)
	}
}

func TestRebalanceRun_DryRun(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/run?dry_run=true")))
	assertStatus(t, w, http.StatusOK)
	if mock.lastRunRebalanceReq == nil || !mock.lastRunRebalanceReq.DryRun {
		t.Errorf("DryRun = %+v, want true", mock.lastRunRebalanceReq)
	}
}

func TestRebalanceRun_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.runRebalanceErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/run")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "Run failed")
}

// ── handleRebalanceApprove ────────────────────────────────────────────────────

func TestRebalanceApprove_Happy(t *testing.T) {
	mock := newDefaultMock()
	mock.approveRebalanceResp = &pb.RebalanceProposal{Id: "p1", SrcHost: "host1", DstHost: "host2", VmName: "vm1"}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/p1/approve")))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/rebalance")
	if mock.lastApproveID != "p1" {
		t.Errorf("approve id = %q, want p1", mock.lastApproveID)
	}
}

func TestRebalanceApprove_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.approveRebalanceErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/p1/approve")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "Approve failed")
}

// ── handleRebalanceReject ─────────────────────────────────────────────────────

func TestRebalanceReject_CapturesReasonFromPrompt(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/rebalance/p1/reject"))
	r.Header.Set("HX-Prompt", "too risky during business hours")
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/rebalance")
	if mock.lastRejectReq == nil || mock.lastRejectReq.Id != "p1" || mock.lastRejectReq.Reason != "too risky during business hours" {
		t.Errorf("reject req = %+v", mock.lastRejectReq)
	}
}

func TestRebalanceReject_NoReason(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/p1/reject")))
	assertStatus(t, w, http.StatusOK)
	if mock.lastRejectReq == nil || mock.lastRejectReq.Reason != "" {
		t.Errorf("reason = %+v, want empty", mock.lastRejectReq)
	}
}

func TestRebalanceReject_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.rejectRebalanceErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/rebalance/p1/reject")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "Reject failed")
}
