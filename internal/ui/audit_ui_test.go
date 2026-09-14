package ui

import (
	"net/http"
	"strings"
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
	// Tampered is what the server sets alongside a break; the toast branches on
	// it rather than re-deriving the rule from the individual findings.
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{
		RowsChecked: 10, BrokenAtId: "row-77", Tampered: true,
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "TAMPERED")
	assertToast(t, w, "row-77")
	assertToast(t, w, "error")
}

// A signature finding must name itself in the toast. Reporting only "chain
// broken" would send an operator hunting for a hash mismatch that isn't there,
// when what actually happened is a row edited by someone without the host key.
func TestAuditVerify_BadSignatureNamedInToast(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{
		RowsChecked:  10,
		BadSignature: []string{"row-9: signature does not verify"},
		SeqGaps:      []string{"node-b: row row-9 has seq 14 after 11"},
		Tampered:     true,
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "bad signature")
	assertToast(t, w, "sequence gap")
	assertToast(t, w, "error")
}

// Unsigned rows are every cluster's state before signing was switched on. A red
// toast here would teach operators that a red audit toast means nothing, so the
// count is reported on the success path.
func TestAuditVerify_UnsignedIsNotTampering(t *testing.T) {
	mock := newDefaultMock()
	mock.verifyAuditResp = &pb.VerifyAuditChainResponse{RowsChecked: 40, UnsignedRows: 12}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/audit/verify")))
	assertStatus(t, w, http.StatusOK)
	assertToast(t, w, "intact")
	assertToast(t, w, "12")
	assertToast(t, w, "success")
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

// The export is what an operator ships to WORM storage. The server pages it, so
// a handler that sends one request returns page one — which is a well-formed
// document that looks complete and is not. Asserting on the rows rather than on
// the number of RPCs is deliberate: the defect is the missing rows, and a
// handler could make the calls and still drop them.
func TestAuditExport_FollowsTheCursorToTheEndOfTheChain(t *testing.T) {
	mock := newDefaultMock()
	mock.exportAuditPages = map[string]*pb.ExportAuditChainResponse{
		"": {
			Json:       `{"rows":[{"id":"r1"},{"id":"r2"}],"chain_heads":[{"host":"h1"}],"ca_pem":"CA"}`,
			RowCount:   2,
			NextCursor: "c1",
		},
		"c1": {
			Json:       `{"rows":[{"id":"r3"}]}`,
			RowCount:   1,
			NextCursor: "c2",
		},
		"c2": {
			Json:     `{"rows":[{"id":"r4"}]}`,
			RowCount: 1,
		},
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/audit/export")))
	assertStatus(t, w, http.StatusOK)

	body := w.Body.String()
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		if !strings.Contains(body, `"id":"`+id+`"`) {
			t.Errorf("downloaded export is missing row %s; it stopped before the end of the chain", id)
		}
	}
	// Evidence rides on the first page. Without the heads a truncated chain
	// replays clean, so an export that loses them cannot do its job either.
	if !strings.Contains(body, `"chain_heads"`) {
		t.Error("downloaded export dropped chain_heads")
	}
	if !strings.Contains(body, `"ca_pem"`) {
		t.Error("downloaded export dropped ca_pem")
	}
}
