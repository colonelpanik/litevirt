package grpcapi

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// seedProposals inserts n proposals with lexicographically ordered ids and
// proposed_at values, newest last, so a DESC read returns p-<n-1> first.
func seedProposals(t *testing.T, ctx context.Context, s *Server, n int, status string) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("p-%04d", i)
		proposedAt := fmt.Sprintf("2026-01-01T00:%02d:%02dZ", i/60, i%60)
		if err := s.db.Execute(ctx,
			`INSERT INTO rebalance_proposals
			   (id, vm_name, src_host, dst_host, policy, expected_gain, status,
			    proposed_at, expires_at, detail, updated_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			id, "vm-"+id, "src", "dst", "balance", 20.0, status,
			proposedAt, proposedAt, "", proposedAt); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
}

// A table larger than the default page must not be returned whole: the
// response is capped, flagged truncated, and reports the full match count.
// Without this the RPC grows with history until it exceeds gRPC's 4 MB limit
// and `lv rebalance list` fails with ResourceExhausted, unrecoverable from
// the CLI.
func TestListRebalanceProposals_CapsAtDefaultLimit(t *testing.T) {
	defer func(o int) { ListProposalsDefaultLimit = o }(ListProposalsDefaultLimit)
	ListProposalsDefaultLimit = 10

	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedProposals(t, ctx, s, 25, "expired")

	resp, err := s.ListRebalanceProposals(ctx, &pb.ListRebalanceProposalsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(resp.GetProposals()); got != 10 {
		t.Fatalf("returned %d proposals, want 10 (the default page size)", got)
	}
	if got := resp.GetTotalCount(); got != 25 {
		t.Fatalf("total_count = %d, want 25 (all matching rows, ignoring the page)", got)
	}
	if !resp.GetTruncated() {
		t.Fatal("truncated = false, want true (15 rows remain past this page)")
	}
	// Newest first.
	if got := resp.GetProposals()[0].GetId(); got != "p-0024" {
		t.Fatalf("first proposal = %q, want p-0024 (newest first)", got)
	}
}

// A caller asking for more than the ceiling is clamped by the server, so no
// client can talk the response past the message limit.
func TestListRebalanceProposals_ClampsRequestedLimitToCeiling(t *testing.T) {
	defer func(o int) { ListProposalsMaxLimit = o }(ListProposalsMaxLimit)
	ListProposalsMaxLimit = 5

	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedProposals(t, ctx, s, 25, "expired")

	resp, err := s.ListRebalanceProposals(ctx,
		&pb.ListRebalanceProposalsRequest{Limit: 10000})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(resp.GetProposals()); got != 5 {
		t.Fatalf("returned %d proposals for limit=10000, want 5 (clamped to the ceiling)", got)
	}
	if !resp.GetTruncated() {
		t.Fatal("truncated = false, want true")
	}
}

// Offset pages through history without changing the reported total.
func TestListRebalanceProposals_OffsetPages(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedProposals(t, ctx, s, 25, "expired")

	resp, err := s.ListRebalanceProposals(ctx,
		&pb.ListRebalanceProposalsRequest{Limit: 10, Offset: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(resp.GetProposals()); got != 5 {
		t.Fatalf("returned %d proposals at offset 20 of 25, want 5", got)
	}
	if got := resp.GetProposals()[0].GetId(); got != "p-0004" {
		t.Fatalf("first proposal at offset 20 = %q, want p-0004", got)
	}
	if got := resp.GetTotalCount(); got != 25 {
		t.Fatalf("total_count = %d, want 25", got)
	}
	if resp.GetTruncated() {
		t.Fatal("truncated = true on the last page, want false")
	}
}

// The status filter still works, and total_count counts only matching rows.
func TestListRebalanceProposals_TotalCountRespectsStatusFilter(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedProposals(t, ctx, s, 7, "expired")

	if err := s.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='pending' WHERE id IN ('p-0000','p-0001')`); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListRebalanceProposals(ctx,
		&pb.ListRebalanceProposalsRequest{StatusFilter: "pending"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(resp.GetProposals()); got != 2 {
		t.Fatalf("returned %d pending proposals, want 2", got)
	}
	if got := resp.GetTotalCount(); got != 2 {
		t.Fatalf("total_count = %d, want 2 (only rows matching the filter)", got)
	}
	if resp.GetTruncated() {
		t.Fatal("truncated = true, want false (both rows fit)")
	}
}

// A small table is returned whole and not flagged truncated — the common case
// must be unchanged for existing callers.
func TestListRebalanceProposals_SmallTableUnchanged(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedProposals(t, ctx, s, 3, "pending")

	resp, err := s.ListRebalanceProposals(ctx, &pb.ListRebalanceProposalsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(resp.GetProposals()); got != 3 {
		t.Fatalf("returned %d proposals, want all 3", got)
	}
	if got := resp.GetTotalCount(); got != 3 {
		t.Fatalf("total_count = %d, want 3", got)
	}
	if resp.GetTruncated() {
		t.Fatal("truncated = true on a 3-row table, want false")
	}
}

// expected_gain is a REAL column. Reading it through Row.Int truncates, so a
// fractional gain — which is most of them — reports as 0 in `lv rebalance
// list` and in the UI, making a real proposal look worthless.
func TestListRebalanceProposals_ExpectedGainKeepsItsFraction(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	now := "2026-01-01T00:00:00Z"
	if err := s.db.Execute(ctx,
		`INSERT INTO rebalance_proposals
		   (id, vm_name, src_host, dst_host, policy, expected_gain, status,
		    proposed_at, expires_at, detail, updated_at)
		 VALUES ('p1','vm1','src','dst','balance',0.35,'pending',?,?,'',?)`,
		now, now, now); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListRebalanceProposals(ctx, &pb.ListRebalanceProposalsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := resp.GetProposals()[0].GetExpectedGain(); got != 0.35 {
		t.Fatalf("list expected_gain = %v, want 0.35 (Row.Int truncates a REAL column)", got)
	}

	one, err := s.fetchProposal(ctx, "p1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := one.GetExpectedGain(); got != 0.35 {
		t.Fatalf("fetch expected_gain = %v, want 0.35", got)
	}
}
