package grpcapi

import (
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestPageToken_RoundTrip(t *testing.T) {
	if got := encodePageToken(); got != "" {
		t.Errorf("no parts should yield empty token, got %q", got)
	}
	tok := encodePageToken("host-b", "vm-7")
	parts := decodePageToken(tok)
	if len(parts) != 2 || parts[0] != "host-b" || parts[1] != "vm-7" {
		t.Errorf("round-trip = %v, want [host-b vm-7]", parts)
	}
	if decodePageToken("") != nil {
		t.Error("empty token should decode to nil")
	}
	if decodePageToken("!!! not base64 !!!") != nil {
		t.Error("malformed token should decode to nil (degrade to first page)")
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
