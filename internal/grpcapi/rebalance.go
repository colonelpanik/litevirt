package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// Page-size bounds for ListRebalanceProposals.
var (
	// ListProposalsDefaultLimit is the page size when the caller asks for
	// none. It is what an operator running `lv rebalance list` gets.
	ListProposalsDefaultLimit = 200

	// ListProposalsMaxLimit is the hard ceiling. A caller asking for more is
	// silently clamped to it, so the response size is bounded by the server
	// regardless of what the client requests.
	ListProposalsMaxLimit = 1000
)

// ListRebalanceProposals returns a bounded page of rebalance proposals,
// newest first, optionally filtered by status.
//
// The page is bounded because the response used to be every row in the table.
// Terminal proposals accumulate (see corrosion.RebalanceProposalRetention),
// and on a cluster emitting ~1k proposals/day the response reached 11.7 MB
// against gRPC's 4 MB ceiling — at which point `lv rebalance list` fails with
// ResourceExhausted and there is no CLI path back, because approve and reject
// both need an id the operator can no longer enumerate.
//
// Retention alone would not fix that: it leaves the RPC one long outage away
// from the same failure. The bound is what makes the response size
// independent of how much history exists.
//
// TotalCount reports how many rows match the filter, ignoring the page, so a
// caller can tell a full page from the whole table; Truncated says whether
// more rows follow.
func (s *Server) ListRebalanceProposals(ctx context.Context, req *pb.ListRebalanceProposalsRequest) (*pb.ListRebalanceProposalsResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}

	limit, offset := pageBounds(int(req.GetLimit()), int(req.GetOffset()))

	// Args are shared by the count and the page so the two can never disagree
	// about which rows they are talking about.
	where, args := "", []any{}
	if req.GetStatusFilter() != "" {
		where = " WHERE status = ?"
		args = append(args, req.GetStatusFilter())
	}

	countRows, err := s.db.Query(ctx,
		`SELECT COUNT(*) AS c FROM rebalance_proposals`+where, args...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "count proposals: %v", err)
	}
	total := 0
	if len(countRows) > 0 {
		total = countRows[0].Int("c")
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, vm_name, src_host, dst_host, policy, expected_gain, status,
		        proposed_at, applied_at, expires_at, detail
		 FROM rebalance_proposals`+where+`
		 ORDER BY proposed_at DESC, id DESC
		 LIMIT ? OFFSET ?`, append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query proposals: %v", err)
	}

	out := make([]*pb.RebalanceProposal, 0, len(rows))
	for _, r := range rows {
		out = append(out, proposalFromRow(r))
	}
	return &pb.ListRebalanceProposalsResponse{
		Proposals:  out,
		TotalCount: int32(total),
		Truncated:  offset+len(out) < total,
	}, nil
}

// pageBounds resolves a requested page to one the server is willing to serve:
// an unset limit takes the default, anything above the ceiling is clamped to
// it, and a negative limit or offset is treated as unset rather than rejected
// — a client that sends one gets the first page, not an error it cannot act
// on.
func pageBounds(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = ListProposalsDefaultLimit
	}
	if limit > ListProposalsMaxLimit {
		limit = ListProposalsMaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// proposalFromRow projects one row. expected_gain is a REAL column and must be
// read with Float: Row.Int truncates, which reported every fractional gain —
// most of them — as 0.
func proposalFromRow(r corrosion.Row) *pb.RebalanceProposal {
	return &pb.RebalanceProposal{
		Id:           r.String("id"),
		VmName:       r.String("vm_name"),
		SrcHost:      r.String("src_host"),
		DstHost:      r.String("dst_host"),
		Policy:       r.String("policy"),
		ExpectedGain: r.Float("expected_gain"),
		Status:       r.String("status"),
		ProposedAt:   r.String("proposed_at"),
		AppliedAt:    r.String("applied_at"),
		ExpiresAt:    r.String("expires_at"),
		Detail:       r.String("detail"),
	}
}

// RunRebalance triggers a single rebalance evaluation cycle. Without this
// RPC the rebalancer only fires every PollInterval; this lets operators
// (and the UI) request immediate evaluation.
func (s *Server) RunRebalance(ctx context.Context, req *pb.RunRebalanceRequest) (*pb.RunRebalanceResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	r := scheduler.NewRebalancer(s.hostName, s.db)
	r.SetCapacityPolicy(s.capacity)
	before := s.countProposals(ctx)
	if err := r.RunOnce(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "run rebalance: %v", err)
	}
	after := s.countProposals(ctx)
	emitted := int32(after - before)
	if emitted < 0 {
		emitted = 0
	}
	return &pb.RunRebalanceResponse{ProposalsEmitted: emitted}, nil
}

// ApproveRebalanceProposal transitions a pending proposal to "approved". The
// leader's rebalance executor (internal/grpcapi/rebalance_executor.go) then
// claims it (approved→applying), runs the live migration, and records the
// terminal status (applied/failed), subject to the cluster rebalance budget.
func (s *Server) ApproveRebalanceProposal(ctx context.Context, req *pb.ApproveRebalanceProposalRequest) (*pb.RebalanceProposal, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`UPDATE rebalance_proposals
		 SET status = 'approved', updated_at = ?
		 WHERE id = ? AND status = 'pending'`, now, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "approve: %v", err)
	}
	return s.fetchProposal(ctx, req.Id)
}

// RejectRebalanceProposal cancels a pending proposal so it won't be
// re-suggested until cooldown elapses.
func (s *Server) RejectRebalanceProposal(ctx context.Context, req *pb.RejectRebalanceProposalRequest) (*pb.RebalanceProposal, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	detail := "rejected by operator"
	if req.Reason != "" {
		detail = "rejected: " + req.Reason
	}
	if err := s.db.Execute(ctx,
		`UPDATE rebalance_proposals
		 SET status = 'rejected', detail = ?, updated_at = ?
		 WHERE id = ? AND status = 'pending'`, detail, now, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "reject: %v", err)
	}
	return s.fetchProposal(ctx, req.Id)
}

// fetchProposal reads one proposal by id.
func (s *Server) fetchProposal(ctx context.Context, id string) (*pb.RebalanceProposal, error) {
	rs, err := s.db.Query(ctx,
		`SELECT id, vm_name, src_host, dst_host, policy, expected_gain, status,
		        proposed_at, applied_at, expires_at, detail
		 FROM rebalance_proposals WHERE id = ?`, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch: %v", err)
	}
	if len(rs) == 0 {
		return nil, status.Errorf(codes.NotFound, "proposal %q not found", id)
	}
	return proposalFromRow(rs[0]), nil
}

func (s *Server) countProposals(ctx context.Context) int {
	rs, err := s.db.Query(ctx, `SELECT COUNT(*) AS c FROM rebalance_proposals`)
	if err != nil || len(rs) == 0 {
		return 0
	}
	return rs[0].Int("c")
}
