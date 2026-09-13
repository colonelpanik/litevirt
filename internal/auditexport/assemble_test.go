package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// pager serves a fixed list of pages, handing out the next cursor each time and
// recording the cursors it was asked for. A caller that ignores NextCursor sees
// only pages[0].
type pager struct {
	pages []*pb.ExportAuditChainResponse
	asked []string
}

func (p *pager) fetch(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
	p.asked = append(p.asked, cursor)
	idx := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil {
			return nil, err
		}
		idx = n
	}
	if idx >= len(p.pages) {
		return nil, errors.New("cursor past the end")
	}
	return p.pages[idx], nil
}

// page builds one export page. next=="" marks the last page.
func page(next string, rows ...string) *pb.ExportAuditChainResponse {
	raw := "["
	for i, r := range rows {
		if i > 0 {
			raw += ","
		}
		raw += r
	}
	raw += "]"
	return &pb.ExportAuditChainResponse{
		Json:       `{"rows":` + raw + `}`,
		RowCount:   int32(len(rows)),
		NextCursor: next,
	}
}

func rowIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal assembled doc: %v", err)
	}
	ids := make([]string, len(doc.Rows))
	for i, r := range doc.Rows {
		ids[i] = r.ID
	}
	return ids
}

// A caller that stops at the first page produces a document that LOOKS whole.
// That is the failure this exists to prevent, so it is asserted on the rows
// themselves rather than on the number of calls made.
func TestAssemble_CarriesEveryPagesRows(t *testing.T) {
	p := &pager{pages: []*pb.ExportAuditChainResponse{
		page("1", `{"id":"a"}`, `{"id":"b"}`),
		page("2", `{"id":"c"}`),
		page("", `{"id":"d"}`),
	}}

	body, total, err := Assemble(context.Background(), p.fetch)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	got := rowIDs(t, body)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rows = %v, want %v (order matters: the chain links in this order)", got, want)
		}
	}
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
}

// Evidence and the CA ride on the first page only. Dropping them turns an
// attestation into a row dump: without the chain heads a truncated chain
// replays clean.
func TestAssemble_KeepsFirstPageEvidence(t *testing.T) {
	first := page("1", `{"id":"a"}`)
	first.Json = `{"rows":[{"id":"a"}],"chain_heads":[{"host":"h1"}],"ca_pem":"REAL"}`

	// A later page carrying the same keys with different values stands in for a
	// peer that answers a page mid-walk. Page one is the attested one, so its
	// evidence must survive: evidence swapped in later is evidence chosen after
	// the rows it is meant to attest to were already seen.
	late := page("", `{"id":"b"}`)
	late.Json = `{"rows":[{"id":"b"}],"chain_heads":[{"host":"IMPOSTOR"}],"ca_pem":"SWAPPED"}`

	p := &pager{pages: []*pb.ExportAuditChainResponse{first, late}}

	body, _, err := Assemble(context.Background(), p.fetch)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	heads, ok := doc["chain_heads"]
	if !ok {
		t.Fatal("assembled document dropped chain_heads; a truncated chain then replays clean")
	}
	if string(heads) != `[{"host":"h1"}]` {
		t.Errorf("chain_heads = %s, want the first page's; a later page must not replace the evidence", heads)
	}
	ca, ok := doc["ca_pem"]
	if !ok {
		t.Fatal("assembled document dropped ca_pem; a certificate can then not be attributed to this cluster")
	}
	if string(ca) != `"REAL"` {
		t.Errorf("ca_pem = %s, want the first page's", ca)
	}
	if ids := rowIDs(t, body); len(ids) != 2 {
		t.Errorf("rows = %v, want both pages", ids)
	}
}

// The loop is driven by a value the server chooses. A server that repeats a
// cursor must end the walk, not spin forever holding an operator's request open.
func TestAssemble_StopsOnARepeatedCursor(t *testing.T) {
	stuck := page("same", `{"id":"a"}`)
	p := &pager{pages: []*pb.ExportAuditChainResponse{stuck}}
	fetch := func(ctx context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		p.asked = append(p.asked, cursor)
		return stuck, nil
	}

	_, _, err := Assemble(context.Background(), fetch)
	if err == nil {
		t.Fatal("Assemble returned nil error on a server that never advances its cursor")
	}
	if len(p.asked) > 3 {
		t.Errorf("made %d calls before giving up; want it to stop as soon as the cursor repeats", len(p.asked))
	}
}

func TestAssemble_ReturnsTheFetchError(t *testing.T) {
	want := errors.New("boom")
	_, _, err := Assemble(context.Background(), func(context.Context, string) (*pb.ExportAuditChainResponse, error) {
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want it to wrap %v", err, want)
	}
}
