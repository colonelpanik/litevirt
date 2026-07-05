package grpcapi

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestPageToken_RoundTrip(t *testing.T) {
	if got := encodePageToken(); got != "" {
		t.Errorf("no parts should yield empty token, got %q", got)
	}
	tok := encodePageToken("host-b", "vm-7")
	parts, ok := decodePageToken(tok)
	if !ok || len(parts) != 2 || parts[0] != "host-b" || parts[1] != "vm-7" {
		t.Errorf("round-trip = %v (ok=%v), want [host-b vm-7]", parts, ok)
	}
	if parts, ok := decodePageToken(""); parts != nil || !ok {
		t.Error("empty token should decode to (nil, ok) — first page, not an error")
	}
	// A malformed token must be reported (ok=false), NOT silently treated as
	// first-page — otherwise a client with a corrupt cursor loops forever.
	if _, ok := decodePageToken("!!! not base64 !!!"); ok {
		t.Error("malformed token must decode to ok=false")
	}
}

func TestNormalizePageSize(t *testing.T) {
	if _, err := normalizePageSize(-1); status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative page_size = %v, want InvalidArgument", err)
	}
	if n, err := normalizePageSize(0); err != nil || n != 0 {
		t.Errorf("page_size 0 = %d,%v; want 0 (unpaginated)", n, err)
	}
	if n, err := normalizePageSize(maxPageSize + 5); err != nil || n != maxPageSize {
		t.Errorf("oversize page_size = %d,%v; want clamp to %d", n, err, maxPageSize)
	}
}

func TestPageCursor(t *testing.T) {
	// Empty token → nil parts, no error (first page).
	if parts, err := pageCursor("", 1); err != nil || parts != nil {
		t.Errorf("empty cursor = %v,%v; want nil,nil", parts, err)
	}
	// Malformed base64 → InvalidArgument, not a silent first-page restart.
	if _, err := pageCursor("@@@bad@@@", 1); status.Code(err) != codes.InvalidArgument {
		t.Errorf("malformed cursor = %v, want InvalidArgument", err)
	}
	// Wrong part count (a 2-part cursor fed to a 1-part list) → InvalidArgument.
	if _, err := pageCursor(encodePageToken("a", "b"), 1); status.Code(err) != codes.InvalidArgument {
		t.Errorf("wrong-arity cursor = %v, want InvalidArgument", err)
	}
	if parts, err := pageCursor(encodePageToken("a", "b"), 2); err != nil || len(parts) != 2 {
		t.Errorf("valid 2-part cursor = %v,%v; want 2 parts", parts, err)
	}
}

// TestListVMs_Pagination walks every VM via keyset pages and asserts full,
// in-order, non-overlapping coverage — and that page_size=0 stays unpaginated.
func TestListVMs_Pagination(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	// Insert out of order to prove ordering comes from the query, not insertion.
	for _, n := range []string{"vm-3", "vm-1", "vm-5", "vm-2", "vm-4"} {
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: n, HostName: "test-host", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", n, err)
		}
	}

	// Page through with page_size=2: expect pages of 2,2,1 then done.
	var seen []string
	token := ""
	pages := 0
	for {
		resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("ListVMs: %v", err)
		}
		pages++
		for _, vm := range resp.Vms {
			seen = append(seen, vm.Name)
		}
		if resp.NextPageToken == "" {
			break
		}
		if len(resp.Vms) != 2 {
			t.Errorf("a non-final page should be full (2), got %d", len(resp.Vms))
		}
		token = resp.NextPageToken
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	want := []string{"vm-1", "vm-2", "vm-3", "vm-4", "vm-5"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("paged order = %v, want %v (in-order, no dupes, complete)", seen, want)
	}
	if pages != 3 {
		t.Errorf("expected 3 pages (2+2+1), got %d", pages)
	}

	// page_size=0 → legacy unpaginated: all 5, no token.
	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vms) != 5 || resp.NextPageToken != "" {
		t.Errorf("unpaginated ListVMs = %d vms, token %q; want 5, empty", len(resp.Vms), resp.NextPageToken)
	}
}
