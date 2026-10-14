package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// TestAssemble_RefusesAChainTooLargeToHold is the OOM bound.
//
// audit_log is append-only with no retention prune, so the input to this
// assembler is unbounded — and it holds every row, then doubles the allocation
// twice to marshal. A compliance poller asking a two-year-old cluster for the
// whole chain takes the daemon out via the OOM killer, and because that is
// SIGKILL the watchdog Heartbeat's deferred disarm never runs: on a host that
// still owns workloads the watchdog keeps counting with the control plane down.
//
// Refusing, and naming the streaming alternative, is a worse export and a much
// better failure than letting the kernel choose which process dies.
func TestAssemble_RefusesAChainTooLargeToHold(t *testing.T) {
	prev := MaxAssembledBytes
	MaxAssembledBytes = 4 << 10
	t.Cleanup(func() { MaxAssembledBytes = prev })

	big := strings.Repeat("x", 2<<10)
	page := fmt.Sprintf(`{"rows":[{"id":"%s"},{"id":"%s"},{"id":"%s"}]}`, big, big, big)

	_, _, err := Assemble(context.Background(), func(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		return &pb.ExportAuditChainResponse{Json: page, RowCount: 3, NextCursor: "keep-going-" + cursor}, nil
	})
	if err == nil {
		t.Fatal("an unbounded chain assembled without complaint; this is the allocation " +
			"that ends in the OOM killer")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %v; it should name the size problem and the alternative", err)
	}
}

// An ordinary export must still assemble — a bound that fires on normal input
// would simply break the feature.
func TestAssemble_OrdinaryChainStillAssembles(t *testing.T) {
	calls := 0
	body, total, err := Assemble(context.Background(), func(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		calls++
		if calls == 1 {
			return &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"a"}],"chain_heads":[]}`, RowCount: 1, NextCursor: "n1"}, nil
		}
		return &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"b"}]}`, RowCount: 1}, nil
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if !strings.Contains(string(body), `"chain_heads"`) {
		t.Errorf("page-one evidence was dropped: %s", body)
	}
}

// TestAssemble_RefusesRowsSignedByAnUnexportedKey is the mid-export key
// rotation.
//
// The evidence tables — signing_keys, key_lifecycle, chain_heads — ride on page
// ONE. A host that rotates its signing key after that page emits rows on later
// pages signed by a certificate the document does not contain, and an external
// verifier cannot check them at all. The artifact replays as broken, which is
// indistinguishable from tampering — the one thing it exists to tell apart.
func TestAssemble_RefusesRowsSignedByAnUnexportedKey(t *testing.T) {
	calls := 0
	_, _, err := Assemble(context.Background(), func(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		calls++
		if calls == 1 {
			return &pb.ExportAuditChainResponse{
				Json: `{"rows":[{"id":"a","host_name":"kvm001","key_id":"k1"}],
				         "signing_keys":[{"key_id":"k1","host_name":"kvm001"}]}`,
				RowCount: 1, NextCursor: "n1",
			}, nil
		}
		// kvm001 rotated to k2 after page one; k2's certificate is not in the
		// evidence this document carries.
		return &pb.ExportAuditChainResponse{
			Json:     `{"rows":[{"id":"b","host_name":"kvm001","key_id":"k2"}]}`,
			RowCount: 1,
		}, nil
	})
	if err == nil {
		t.Fatal("assembled a document whose rows are signed by a key it does not contain; " +
			"offline verification of those rows is impossible and reads as tampering")
	}
	if !strings.Contains(err.Error(), "k2") {
		t.Errorf("the refusal should name the uncovered key, got: %v", err)
	}
}

// Pre-v45 rows carry no key_id. They are chain-verified but not
// tamper-evident, and the verifier reports them as such — so an empty key_id
// must not be treated as a coverage failure, or every upgraded cluster's
// export would refuse.
func TestAssemble_AllowsPreV45RowsWithNoKeyID(t *testing.T) {
	_, _, err := Assemble(context.Background(), func(_ context.Context, _ string) (*pb.ExportAuditChainResponse, error) {
		return &pb.ExportAuditChainResponse{
			Json: `{"rows":[{"id":"a","host_name":"kvm001","key_id":""}],
			         "signing_keys":[{"key_id":"k1","host_name":"kvm001"}]}`,
			RowCount: 1,
		}, nil
	})
	if err != nil {
		t.Fatalf("a pre-v45 row with no key_id was refused: %v", err)
	}
}

// A seq gap the server reported must not be swallowed either: this package
// exists to refuse a partial chain.
func TestAssemble_RefusesAReportedSeqGap(t *testing.T) {
	_, _, err := Assemble(context.Background(), func(_ context.Context, _ string) (*pb.ExportAuditChainResponse, error) {
		return &pb.ExportAuditChainResponse{
			Json: `{"rows":[{"id":"a","host_name":"kvm001","key_id":"k1"}],
			         "signing_keys":[{"key_id":"k1","host_name":"kvm001"}],
			         "seq_gaps":[{"host_name":"kvm001","missing_from":"3","missing_to":"3"}]}`,
			RowCount: 1,
		}, nil
	})
	if err == nil {
		t.Fatal("a reported seq gap was assembled into a document that looks whole")
	}
}

// The size refusal must name a remedy that works. It used to send the
// operator to plain `lv audit export`, which assembled through this same
// function and failed the same way; the CLI now spools with Write, and only
// `--out <file>` or stdout from the CLI reaches it.
//
// Mutation: restore the old message — this goes red.
func TestAssemble_TheSizeRefusalNamesAWorkingRemedy(t *testing.T) {
	prev := MaxAssembledBytes
	MaxAssembledBytes = 1 << 10
	t.Cleanup(func() { MaxAssembledBytes = prev })
	big := strings.Repeat("x", 2<<10)
	_, _, err := Assemble(context.Background(), func(_ context.Context, _ string) (*pb.ExportAuditChainResponse, error) {
		return &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"` + big + `"}]}`, RowCount: 1}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "lv audit export --out") {
		t.Fatalf("size refusal = %v; it must name `lv audit export --out`, the path with no cap", err)
	}
}

// gappedPages is a two-page chain with a reported gap on each page.
func gappedPages() *pager {
	return &pager{pages: []*pb.ExportAuditChainResponse{
		{Json: `{"rows":[{"id":"a","host_name":"kvm001","seq":"1"},{"id":"c","host_name":"kvm001","seq":"3"}],
		        "signing_keys":[],
		        "seq_gaps":[{"host_name":"kvm001","missing_from":"2","missing_to":"2"}]}`,
			RowCount: 2, NextCursor: "1"},
		{Json: `{"rows":[{"id":"f","host_name":"kvm001","seq":"6"}],
		        "seq_gaps":[{"host_name":"kvm001","missing_from":"4","missing_to":"5"}]}`,
			RowCount: 1},
	}}
}

// TestWrite_AllowGapsExportsTheChainWithEveryGapListed: a gap that persists is
// rows missing from a host's chain — deletion, the case an investigator most
// needs the export for. The default refuses it, and that refusal must name the
// way through; --allow-gaps writes the chain with EVERY page's gaps listed (a
// later page's gaps used to be dropped behind page one's), so the document
// cannot read as whole.
//
// Mutations, each red: ignore AllowGaps — the export is refused; keep only
// the first page's seq_gaps — one gap is listed, not two; drop the remedy from
// the refusal — the default case goes red.
func TestWrite_AllowGapsExportsTheChainWithEveryGapListed(t *testing.T) {
	var buf strings.Builder
	_, err := Write(context.Background(), gappedPages().fetch, &buf, Options{})
	if err == nil || !strings.Contains(err.Error(), "--allow-gaps") {
		t.Fatalf("default export of a gapped chain = %v; want a refusal naming --allow-gaps", err)
	}

	buf.Reset()
	total, err := Write(context.Background(), gappedPages().fetch, &buf, Options{AllowGaps: true})
	if err != nil {
		t.Fatalf("Write with AllowGaps: %v", err)
	}
	var doc struct {
		Rows []map[string]string `json:"rows"`
		Gaps []map[string]string `json:"seq_gaps"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, buf.String())
	}
	if total != 3 || len(doc.Rows) != 3 {
		t.Fatalf("exported %d rows (total %d), want 3", len(doc.Rows), total)
	}
	var got []string
	for _, g := range doc.Gaps {
		got = append(got, g["missing_from"]+".."+g["missing_to"])
	}
	if strings.Join(got, ",") != "2..2,4..5" {
		t.Fatalf("seq_gaps = %v, want every page's gaps: 2..2,4..5", got)
	}
}

// Write and Assemble are one walk: Assemble's document is Write's.
func TestWrite_MatchesAssemble(t *testing.T) {
	pages := func() *pager {
		return &pager{pages: []*pb.ExportAuditChainResponse{
			{Json: `{"rows":[{"id":"a"}],"chain_heads":[{"h":"x"}],"ca_pem":"PEM"}`, RowCount: 1, NextCursor: "1"},
			page("", `{"id":"b"}`),
		}}
	}
	body, total, err := Assemble(context.Background(), pages().fetch)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	wtotal, err := Write(context.Background(), pages().fetch, &buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(body) || wtotal != total {
		t.Fatalf("Write = %s (%d), Assemble = %s (%d)", buf.String(), wtotal, body, total)
	}
	if !json.Valid(body) || !strings.Contains(string(body), `"ca_pem":"PEM"`) {
		t.Fatalf("assembled document lost page-one evidence or is not JSON: %s", body)
	}
}
