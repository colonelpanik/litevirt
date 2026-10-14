package restapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The export RPC pages. A handler that sends one request answers with page one
// and no way to ask for page two — the endpoint then cannot perform the export
// it advertises, and a compliance poller archives a fragment. Asserted on the
// rows in the body rather than on call count: the defect is the missing rows.
func TestAuditExport_ReturnsTheWholeChainNotTheFirstPage(t *testing.T) {
	s, mock := newMockServer("test-token")
	mock.exportAuditPages = map[string]*pb.ExportAuditChainResponse{
		"": {
			Json:       `{"rows":[{"id":"r1"}],"chain_heads":[{"host":"h1"}],"ca_pem":"CA"}`,
			RowCount:   1,
			NextCursor: "c1",
		},
		"c1": {
			Json:       `{"rows":[{"id":"r2"}]}`,
			RowCount:   1,
			NextCursor: "c2",
		},
		"c2": {
			Json:     `{"rows":[{"id":"r3"}]}`,
			RowCount: 1,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var envelope struct {
		JSON       string `json:"json"`
		RowCount   int    `json:"row_count"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (body: %s)", err, rec.Body.String())
	}

	var doc struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
		ChainHeads json.RawMessage `json:"chain_heads"`
		CAPem      string          `json:"ca_pem"`
	}
	if err := json.Unmarshal([]byte(envelope.JSON), &doc); err != nil {
		t.Fatalf("decode export document: %v (json: %s)", err, envelope.JSON)
	}

	got := make([]string, len(doc.Rows))
	for i, r := range doc.Rows {
		got[i] = r.ID
	}
	want := []string{"r1", "r2", "r3"}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v — the handler stopped before the end of the chain", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rows = %v, want %v (order matters: the chain links in this order)", got, want)
		}
	}
	if envelope.RowCount != 3 {
		t.Errorf("row_count = %d, want 3 — it must count what was returned", envelope.RowCount)
	}
	// The whole chain is in the body, so there is no next page to ask for. A
	// non-empty cursor here would tell a client to fetch rows it already holds.
	if envelope.NextCursor != "" {
		t.Errorf("next_cursor = %q, want empty once the whole chain is assembled", envelope.NextCursor)
	}
	if len(doc.ChainHeads) == 0 {
		t.Error("export dropped chain_heads; a truncated chain then replays clean")
	}
	if doc.CAPem == "" {
		t.Error("export dropped ca_pem")
	}
}
