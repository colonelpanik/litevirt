package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// ListRebalanceProposals returns all rebalance proposals, optionally
// filtered by status.
func (s *Server) ListRebalanceProposals(ctx context.Context, req *pb.ListRebalanceProposalsRequest) (*pb.ListRebalanceProposalsResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	var rows []map[string]any
	var qErr error
	if req.StatusFilter != "" {
		rs, err := s.db.Query(ctx,
			`SELECT id, vm_name, src_host, dst_host, policy, expected_gain, status,
			        proposed_at, applied_at, expires_at, detail
			 FROM rebalance_proposals WHERE status = ?
			 ORDER BY proposed_at DESC`, req.StatusFilter)
		qErr = err
		for _, r := range rs {
			rows = append(rows, map[string]any{
				"id": r.String("id"), "vm_name": r.String("vm_name"),
				"src_host": r.String("src_host"), "dst_host": r.String("dst_host"),
				"policy": r.String("policy"), "expected_gain": r.Int("expected_gain"),
				"status": r.String("status"), "proposed_at": r.String("proposed_at"),
				"applied_at": r.String("applied_at"), "expires_at": r.String("expires_at"),
				"detail": r.String("detail"),
			})
		}
	} else {
		rs, err := s.db.Query(ctx,
			`SELECT id, vm_name, src_host, dst_host, policy, expected_gain, status,
			        proposed_at, applied_at, expires_at, detail
			 FROM rebalance_proposals
			 ORDER BY proposed_at DESC`)
		qErr = err
		for _, r := range rs {
			rows = append(rows, map[string]any{
				"id": r.String("id"), "vm_name": r.String("vm_name"),
				"src_host": r.String("src_host"), "dst_host": r.String("dst_host"),
				"policy": r.String("policy"), "expected_gain": r.Int("expected_gain"),
				"status": r.String("status"), "proposed_at": r.String("proposed_at"),
				"applied_at": r.String("applied_at"), "expires_at": r.String("expires_at"),
				"detail": r.String("detail"),
			})
		}
	}
	if qErr != nil {
		return nil, status.Errorf(codes.Internal, "query proposals: %v", qErr)
	}
	out := make([]*pb.RebalanceProposal, 0, len(rows))
	for _, r := range rows {
		out = append(out, &pb.RebalanceProposal{
			Id:           r["id"].(string),
			VmName:       r["vm_name"].(string),
			SrcHost:      r["src_host"].(string),
			DstHost:      r["dst_host"].(string),
			Policy:       r["policy"].(string),
			ExpectedGain: float64(r["expected_gain"].(int)),
			Status:       r["status"].(string),
			ProposedAt:   r["proposed_at"].(string),
			AppliedAt:    r["applied_at"].(string),
			ExpiresAt:    r["expires_at"].(string),
			Detail:       r["detail"].(string),
		})
	}
	return &pb.ListRebalanceProposalsResponse{Proposals: out}, nil
}

// RunRebalance triggers a single rebalance evaluation cycle. Without this
// RPC the rebalancer only fires every PollInterval; this lets operators
// (and the UI) request immediate evaluation.
func (s *Server) RunRebalance(ctx context.Context, req *pb.RunRebalanceRequest) (*pb.RunRebalanceResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	r := scheduler.NewRebalancer(s.hostName, s.db)
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
	r := rs[0]
	return &pb.RebalanceProposal{
		Id:           r.String("id"),
		VmName:       r.String("vm_name"),
		SrcHost:      r.String("src_host"),
		DstHost:      r.String("dst_host"),
		Policy:       r.String("policy"),
		ExpectedGain: float64(r.Int("expected_gain")),
		Status:       r.String("status"),
		ProposedAt:   r.String("proposed_at"),
		AppliedAt:    r.String("applied_at"),
		ExpiresAt:    r.String("expires_at"),
		Detail:       r.String("detail"),
	}, nil
}

func (s *Server) countProposals(ctx context.Context) int {
	rs, err := s.db.Query(ctx, `SELECT COUNT(*) AS c FROM rebalance_proposals`)
	if err != nil || len(rs) == 0 {
		return 0
	}
	return rs[0].Int("c")
}
