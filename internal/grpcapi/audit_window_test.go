package grpcapi

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The instant every window test below is written around, and the same instant
// with an offset. The lab row that exposed the bug was stamped
// 2026-10-03T22:16:30.767241380Z, and `lv audit ls --since
// 2026-10-03T22:16:30Z` left it out.
const (
	winT       = "2026-10-03T22:16:30Z"
	winTOffset = "2026-10-04T00:16:30+02:00"
)

// seedWindowRows writes three rows on one host: just after T, half a second
// after T, and one second after T — the first two inside the second T names.
func seedWindowRows(t *testing.T, s *Server) {
	t.Helper()
	ctx := adminCtx()
	for _, r := range []struct{ id, ts string }{
		{"w-a", "2026-10-03T22:16:30.000000001Z"},
		{"w-b", "2026-10-03T22:16:30.500000000Z"},
		{"w-c", "2026-10-03T22:16:31.000000000Z"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: r.id, Username: "u", HostName: "node-3",
			Action: "cluster.lease_term_tie.acknowledge", Target: "failover:1", Result: "ok", Timestamp: r.ts,
		}); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", r.id, err)
		}
	}
}

// TestListAuditLog_WindowIsTimeNotText pins `lv audit ls --since/--until` to
// the time each bound names.
//
// The stored stamp is fixed-width with nine fractional digits; the bound was a
// whole-second RFC3339 string compared to it as TEXT. '.' sorts below 'Z', so
// every row inside the bound's own second sorted before it and --since dropped
// it. An offset bound compared its local digits with UTC ones and was wrong by
// the offset.
func TestListAuditLog_WindowIsTimeNotText(t *testing.T) {
	s := testServerR2(t)
	seedWindowRows(t, s)
	ctx := adminCtx()

	for _, tc := range []struct {
		name         string
		since, until string
		want         []string
	}{
		{"since a whole second keeps the rows inside it", winT, "", []string{"w-a", "w-b", "w-c"}},
		{"since with an offset is the same instant", winTOffset, "", []string{"w-a", "w-b", "w-c"}},
		{"until a whole second includes the rows inside it", "", winT, []string{"w-a", "w-b"}},
		{"until with an offset is the same instant", "", winTOffset, []string{"w-a", "w-b"}},
		{"since a sub-second instant", "2026-10-03T22:16:30.5Z", "", []string{"w-b", "w-c"}},
		{"since a date", "2026-10-03", "", []string{"w-a", "w-b", "w-c"}},
		{"until a date covers the whole day", "", "2026-10-03", []string{"w-a", "w-b", "w-c"}},
		{"until the end of time matches everything", "", "9999-12-31T23:59:59Z", []string{"w-a", "w-b", "w-c"}},
		{"until year 9999 matches everything", "", "9999", []string{"w-a", "w-b", "w-c"}},
		{"since 0 is the beginning", "0", "", []string{"w-a", "w-b", "w-c"}},
		{"since an hour", "2026-10-03T22", "", []string{"w-a", "w-b", "w-c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Since: tc.since, Until: tc.until, Limit: 50})
			if err != nil {
				t.Fatalf("ListAuditLog: %v", err)
			}
			var got []string
			for _, e := range resp.Entries {
				got = append(got, map[string]string{
					"2026-10-03T22:16:30.000000001Z": "w-a",
					"2026-10-03T22:16:30.500000000Z": "w-b",
					"2026-10-03T22:16:31.000000000Z": "w-c",
				}[e.Timestamp])
			}
			slices.Sort(got)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("since=%q until=%q returned %v, want %v", tc.since, tc.until, got, tc.want)
			}
		})
	}
}

// TestAuditWindow_RefusesAnUnparseableBound: a bound that names no instant is
// refused, where it used to be compared as text and return a silently wrong
// listing ("yesterday" sorts after every stamp, so --since returned nothing
// and --until everything).
func TestAuditWindow_RefusesAnUnparseableBound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for _, req := range []*pb.ListAuditLogRequest{{Since: "yesterday"}, {Until: "yesterday"}} {
		_, err := s.ListAuditLog(ctx, req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("ListAuditLog(%+v) = %v, want InvalidArgument", req, err)
		}
	}
	for _, req := range []*pb.ExportAuditChainRequest{{Since: "yesterday"}, {Until: "yesterday"}} {
		_, err := s.ExportAuditChain(ctx, req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("ExportAuditChain(%+v) = %v, want InvalidArgument", req, err)
		}
	}
	_, err := s.ListVMEvents(ctx, &pb.ListVMEventsRequest{Since: "yesterday"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("ListVMEvents(since=yesterday) = %v, want InvalidArgument", err)
	}
}

// TestListAuditLog_RelativeBound: a duration is "that long ago", which is what
// an operator typing `--since 1h` means. It used to be compared as text, where
// "1h" sorts below every stamp and the listing returned every row.
func TestListAuditLog_RelativeBound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	seedWindowRows(t, s) // 2026-10-03: long before "1h ago" on any clock running this test
	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "recent", Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Since: "1h", Limit: 50})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Action != "vm.start" {
		t.Fatalf("since=1h returned %d entries %+v, want only the row just written", len(resp.Entries), resp.Entries)
	}
}

func exportIDs(t *testing.T, s *Server, req *pb.ExportAuditChainRequest) (ids []string, gaps []string) {
	t.Helper()
	ctx := adminCtx()
	for {
		resp, err := s.ExportAuditChain(ctx, req)
		if err != nil {
			t.Fatalf("ExportAuditChain: %v", err)
		}
		var doc struct {
			Rows []map[string]string `json:"rows"`
			Gaps []map[string]string `json:"seq_gaps"`
		}
		if err := json.Unmarshal([]byte(resp.Json), &doc); err != nil {
			t.Fatalf("unmarshal export: %v", err)
		}
		for _, r := range doc.Rows {
			ids = append(ids, r["id"])
		}
		for _, g := range doc.Gaps {
			gaps = append(gaps, g["missing_from"]+".."+g["missing_to"])
		}
		if resp.NextCursor == "" {
			return ids, gaps
		}
		req.Cursor = resp.NextCursor
	}
}

// TestExportAuditChain_WindowIsTimeNotText is the export's half of the same
// bug, one page at a time and all at once: the pages must agree with each
// other and with `lv audit ls`.
func TestExportAuditChain_WindowIsTimeNotText(t *testing.T) {
	s := testServerR2(t)
	seedWindowRows(t, s)
	for _, tc := range []struct {
		since, until string
		want         []string
	}{
		{winT, "", []string{"w-a", "w-b", "w-c"}},
		{winTOffset, "", []string{"w-a", "w-b", "w-c"}},
		{"", winT, []string{"w-a", "w-b"}},
		{"", winTOffset, []string{"w-a", "w-b"}},
	} {
		for _, limit := range []int32{1, 50} {
			got, gaps := exportIDs(t, s, &pb.ExportAuditChainRequest{Since: tc.since, Until: tc.until, Limit: limit})
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("since=%q until=%q limit=%d exported %v, want %v", tc.since, tc.until, limit, got, tc.want)
			}
			if len(gaps) > 0 {
				t.Errorf("since=%q until=%q limit=%d reported gaps %v on a complete chain", tc.since, tc.until, limit, gaps)
			}
		}
	}
}

// TestExportAuditChain_GapCheckUsesTheSameWindow: a windowed export tells a
// row the window left out from a seq that is really missing by asking whether
// the seq has a row OUTSIDE the window (seqsAbsentOutsideWindow). That query
// has to draw the window where the export did. With an offset bound the text
// comparison drew it in a different place: a row after the bound in time read
// as inside it, so the gap check found no row "outside" and reported a
// deletion that never happened.
func TestExportAuditChain_GapCheckUsesTheSameWindow(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for seq, ts := range map[int64]string{
		1: "2026-10-03T22:16:27.000000000Z",
		2: "2026-10-03T22:16:40.000000000Z", // after the bound: left out, not missing
		3: "2026-10-03T22:16:29.000000000Z",
	} {
		if err := s.db.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			 result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("g-%d", seq), ts, "u", "node-3", "vm.start", "x", "", "ok",
			"ph", "ch", "k", "sig", seq); err != nil {
			t.Fatalf("insert seq %d: %v", seq, err)
		}
	}
	// 22:16:30Z, written so its digits sort AFTER seq 2's stamp as text.
	got, gaps := exportIDs(t, s, &pb.ExportAuditChainRequest{Until: "2026-10-03T23:16:30+01:00", Limit: 50})
	if fmt.Sprint(got) != fmt.Sprint([]string{"g-1", "g-3"}) {
		t.Errorf("exported %v, want [g-1 g-3]", got)
	}
	if len(gaps) > 0 {
		t.Errorf("seq_gaps = %v; seq 2 is in the table, outside the window, and is not a gap", gaps)
	}
}

// TestListVMEvents_SinceIsTimeNotText: `lv events <vm> --since` had the same
// text comparison against the same fixed-width stamps.
func TestListVMEvents_SinceIsTimeNotText(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for _, ev := range []corrosion.VMEventRecord{
		{ID: "e-a", VMName: "web", HostName: "node-3", Type: "vm.started", TS: "2026-10-03T22:16:29.900000000Z"},
		{ID: "e-b", VMName: "web", HostName: "node-3", Type: "vm.stopped", TS: "2026-10-03T22:16:30.767241380Z"},
	} {
		if err := corrosion.InsertVMEvent(ctx, s.db, ev); err != nil {
			t.Fatalf("InsertVMEvent %s: %v", ev.ID, err)
		}
	}
	for _, since := range []string{winT, winTOffset} {
		resp, err := s.ListVMEvents(ctx, &pb.ListVMEventsRequest{Since: since})
		if err != nil {
			t.Fatalf("ListVMEvents: %v", err)
		}
		var got []string
		for _, e := range resp.Events {
			got = append(got, e.Id)
		}
		if fmt.Sprint(got) != "[e-b]" {
			t.Errorf("since=%q returned %v, want [e-b]", since, got)
		}
	}
}

// TestExportAuditChain_RelativeBoundHoldsStillAcrossPages: a duration bound is
// resolved once, against the first page's clock, and every later page uses
// that instant. Resolved afresh per page, `--since 24h` would move under a
// paginated export, and the pages of one document would answer different
// windows.
func TestExportAuditChain_RelativeBoundHoldsStillAcrossPages(t *testing.T) {
	s := testServerR2(t)
	seedWindowRows(t, s)
	ctx := adminCtx()

	first, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{Since: "1h", Limit: 1})
	if err != nil {
		t.Fatalf("ExportAuditChain: %v", err)
	}
	if first.RowCount != 0 {
		t.Fatalf("since=1h exported %d rows from 2026-10-03, want none", first.RowCount)
	}

	// Page two of an export whose first page was taken at 22:50Z that day: "1h"
	// then meant 21:50Z, which every seeded row is after.
	cur := exportCursor{Host: "node-3", Seq: 1, TS: "2026-10-03T22:16:30.000000001Z", ID: "w-a",
		Now: "2026-10-03T22:50:00Z"}.encode()
	got, _ := exportIDs(t, s, &pb.ExportAuditChainRequest{Since: "1h", Limit: 1, Cursor: cur})
	if fmt.Sprint(got) != "[w-b w-c]" {
		t.Fatalf("page two exported %v, want [w-b w-c]: the bound must be resolved against the first page's clock", got)
	}
}
