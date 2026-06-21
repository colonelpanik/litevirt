package ui

import (
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ── /audit page header actions render ─────────────────────────────────────────

func TestAuditPage_RendersVerifyAndExport(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/audit")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Verify chain")
	assertContains(t, w, "/ui/audit/export")
}

// ── handleAuditVerify ─────────────────────────────────────────────────────────

func TestAuditVerify_Intact(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{RowsChecked: 42}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "intact")
	assertToast(t, w, "42")
	assertToast(t, w, "success")
}

func TestAuditVerify_Broken(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{RowsChecked: 10, BrokenAtId: "row-77"}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "broken")
	assertToast(t, w, "row-77")
	assertToast(t, w, "error")
}

func TestAuditVerify_ResponseErrorField(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{Error: "db locked"}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "db locked")
	assertToast(t, w, "error")
}

func TestAuditVerify_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "Verify failed")
}

// ── handleAuditExport ─────────────────────────────────────────────────────────

func TestAuditExport_DownloadsJSON(t *testing.T) {
	mock := newDefaultMock()
	mock.exportAuditResp = &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"1"}]}`, RowCount: 1}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/audit/export?since=2026-01-01T00:00:00Z&until=2026-06-01T00:00:00Z")))
	assertStatus(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != "attachment; filename=audit-export.json" {
		t.Errorf("Content-Disposition = %q", cd)
	}
	assertContains(t, w, `"rows":[{"id":"1"}]`)
	if mock.lastExportReq == nil || mock.lastExportReq.Since != "2026-01-01T00:00:00Z" || mock.lastExportReq.Until != "2026-06-01T00:00:00Z" {
		t.Errorf("export req = %+v, want since/until forwarded", mock.lastExportReq)
	}
}

func TestAuditExport_RPCError(t *testing.T) {
	mock := newDefaultMock()
	mock.exportAuditErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/audit/export")))
	assertStatus(t, w, http.StatusInternalServerError)
}
