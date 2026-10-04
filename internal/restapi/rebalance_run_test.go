package restapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRebalanceRun(t *testing.T, body string) (*httptest.ResponseRecorder, *mockGRPC) {
	t.Helper()
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rebalance/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec, mock
}

// POST /api/v1/rebalance/run forwards dry_run to the RPC, in either JSON
// spelling protojson accepts.
func TestRebalanceRun_ForwardsDryRun(t *testing.T) {
	for _, body := range []string{`{"dry_run":true}`, `{"dryRun":true}`} {
		rec, mock := postRebalanceRun(t, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d body=%q", body, rec.Code, rec.Body.String())
		}
		if mock.lastRunRebalanceReq == nil || !mock.lastRunRebalanceReq.GetDryRun() {
			t.Errorf("%s: forwarded %+v, want dry_run=true", body, mock.lastRunRebalanceReq)
		}
	}
}

// An empty body is a real (non-dry) run, as it always was.
func TestRebalanceRun_EmptyBodyIsRealRun(t *testing.T) {
	rec, mock := postRebalanceRun(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%q", rec.Code, rec.Body.String())
	}
	if mock.lastRunRebalanceReq == nil || mock.lastRunRebalanceReq.GetDryRun() {
		t.Errorf("forwarded %+v, want dry_run=false", mock.lastRunRebalanceReq)
	}
}

// A body that does not parse must be refused, not read as an empty request.
// The handler used to swallow the decode error and send RunRebalanceRequest{},
// so a caller who meant a dry run but wrote `"dry_run":"true"` got a real run
// that auto-approves — the one outcome a dry run exists to rule out.
func TestRebalanceRun_MalformedBodyRefused(t *testing.T) {
	for _, body := range []string{`{"dry_run":"true"}`, `{"dry_run":tru`, `{"dryrun":true}`} {
		rec, mock := postRebalanceRun(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
		if mock.runRebalanceCalls != 0 {
			t.Errorf("%s: RunRebalance called %d time(s), want 0", body, mock.runRebalanceCalls)
		}
	}
}
