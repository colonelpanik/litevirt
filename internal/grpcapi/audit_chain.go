// tamper-evident audit log handlers.
//
// VerifyAuditChain replays every host's hash sub-chain end-to-end and
// checks the row signatures, sequence numbers and signed chain heads on
// top of it. ExportAuditChain emits a JSON blob suitable for WORM offload.
//
// Neither RPC mutates the chain. Verify is admin-only because the
// result has compliance implications; Export is admin-only because
// it leaks every audit event ever recorded.

package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) VerifyAuditChain(ctx context.Context, _ *emptypb.Empty) (*pb.VerifyAuditChainResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	res, err := verifyChain(ctx, s)
	// Every finding is passed through, not summarised into a verdict here.
	// The client decides how to present them, and a partial result is still
	// worth returning when the verify itself failed part-way: the rows it did
	// check are evidence too.
	resp := &pb.VerifyAuditChainResponse{
		RowsChecked:      int32(res.RowsChecked),
		BrokenAtId:       res.BrokenAt,
		UnsignedRows:     int32(res.Unsigned),
		UnverifiableRows: int32(res.Unverifiable),
		BadSignature:     res.BadSignature,
		UnknownKeyId:     res.UnknownKeyID,
		SeqGaps:          res.SeqGaps,
		Laundered:        res.Laundered,
		UnattributedRows: int32(res.Unattributed),
		TruncatedHosts:   res.TruncatedHosts,
		Tampered:         res.Tampered(),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *Server) ExportAuditChain(ctx context.Context, req *pb.ExportAuditChainRequest) (*pb.ExportAuditChainResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash
		 FROM audit_log
		 WHERE (? = '' OR timestamp >= ?)
		   AND (? = '' OR timestamp <= ?)
		 ORDER BY timestamp ASC, id ASC`,
		req.Since, req.Since, req.Until, req.Until)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list audit_log: %v", err)
	}
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{
			"id":           r.String("id"),
			"timestamp":    r.String("timestamp"),
			"username":     r.String("username"),
			"host_name":    r.String("host_name"),
			"action":       r.String("action"),
			"target":       r.String("target"),
			"detail":       r.String("detail"),
			"result":       r.String("result"),
			"prev_hash":    r.String("prev_hash"),
			"content_hash": r.String("content_hash"),
		})
	}
	body, mErr := json.Marshal(map[string]any{"rows": out})
	if mErr != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", mErr)
	}
	return &pb.ExportAuditChainResponse{
		Json:     string(body),
		RowCount: int32(len(out)),
	}, nil
}

// verifyChain bridges to corrosion.VerifyAuditChain — kept in this
// package so the gRPC handler's error wrapping stays close to the
// RPC contract.
func verifyChain(ctx context.Context, s *Server) (corrosion.AuditVerifyResult, error) {
	// The result is passed through unchanged: collapsing it here would lose
	// the distinction between "rows predate signing" and "rows were edited",
	// which is the whole point of the check.
	if s == nil || s.db == nil {
		return corrosion.AuditVerifyResult{}, fmt.Errorf("server not initialised")
	}
	return verifyChainImpl(ctx, s)
}
