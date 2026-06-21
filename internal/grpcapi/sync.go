package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetStateDigest returns a lightweight fingerprint of each replicated table
// on this host. Callers can compare digests across hosts to detect drift.
func (s *Server) GetStateDigest(ctx context.Context, _ *emptypb.Empty) (*pb.StateDigestResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}

	digests, err := s.db.StateDigest(ctx)
	if err != nil {
		return nil, err
	}

	resp := &pb.StateDigestResponse{HostName: s.hostName}
	for _, d := range digests {
		resp.Tables = append(resp.Tables, &pb.TableDigest{
			Name:  d.Name,
			Count: int32(d.Count),
			Hash:  d.Hash,
		})
	}
	return resp, nil
}

// GetStateDump returns a full gzipped state dump that can be merged into
// another node's database. Used by `lv cluster sync` to force convergence.
func (s *Server) GetStateDump(ctx context.Context, _ *emptypb.Empty) (*pb.StateDumpResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}

	data := s.db.DumpStateBytes()
	return &pb.StateDumpResponse{Data: data}, nil
}

// PushMutations receives mutation entries from a peer and applies them locally
// with LWW conflict resolution. This is the primary replication path: the
// sending host reads from its mutation_log and pushes entries to each peer.
func (s *Server) PushMutations(ctx context.Context, req *pb.ReplicateRequest) (*pb.ReplicateResponse, error) {
	if s.replicator == nil {
		return nil, status.Error(codes.Unavailable, "replicator not initialized")
	}
	if req.Sender == "" {
		return nil, status.Error(codes.InvalidArgument, "sender required")
	}

	// Schema-version skew check. Sender < receiver is normal during a
	// rolling upgrade; we warn but accept (the new schema's columns are
	// supersets of the old). Sender > receiver by more than 1 version
	// means the receiver is missing migrations the sender's writes assume —
	// reject so corrupt rows don't land. The receiver-out-of-date side
	// (operator) sees it via the metric and refuses-to-replicate logs.
	if req.SenderSchemaVersion != 0 {
		gap := int(req.SenderSchemaVersion) - corrosion.CurrentSchemaVersion
		if gap > 1 {
			slog.Warn("pushMutations: schema skew too large; refusing",
				"sender", req.Sender,
				"sender_schema", req.SenderSchemaVersion,
				"local_schema", corrosion.CurrentSchemaVersion,
				"sender_version", req.SenderVersion)
			return nil, status.Errorf(codes.FailedPrecondition,
				"sender schema version %d, local %d (skew exceeds tolerance; upgrade local daemon)",
				req.SenderSchemaVersion, corrosion.CurrentSchemaVersion)
		}
		if gap != 0 {
			slog.Info("pushMutations: schema skew (within tolerance)",
				"sender", req.Sender,
				"sender_schema", req.SenderSchemaVersion,
				"local_schema", corrosion.CurrentSchemaVersion)
		}
	}

	if len(req.Entries) == 0 {
		return &pb.ReplicateResponse{AppliedUpTo: req.AfterSeq}, nil
	}

	slog.Debug("pushMutations: received", "sender", req.Sender, "entries", len(req.Entries))

	lastSeq, err := s.replicator.ApplyRemoteMutations(ctx, req.Entries)
	if err != nil {
		slog.Warn("pushMutations: apply error", "sender", req.Sender, "error", err)
		return nil, status.Errorf(codes.Internal, "apply mutations: %v", err)
	}

	slog.Debug("pushMutations: applied", "sender", req.Sender, "applied_up_to", lastSeq)
	return &pb.ReplicateResponse{AppliedUpTo: lastSeq}, nil
}

// AckMutations records that a peer has acknowledged processing mutations
// up to a given sequence number. This updates the replication_watermarks table.
func (s *Server) AckMutations(ctx context.Context, req *pb.AckRequest) (*emptypb.Empty, error) {
	if req.Sender == "" {
		return nil, status.Error(codes.InvalidArgument, "sender required")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	db := s.db.DB()
	mu := s.db.Mu()

	mu.Lock()
	_, err := db.ExecContext(ctx,
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(peer_name) DO UPDATE SET last_seq = excluded.last_seq, updated_at = excluded.updated_at`,
		req.Sender, req.AckedSeq, now)
	mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("update watermark: %w", err)
	}

	slog.Debug("ackMutations", "sender", req.Sender, "acked_seq", req.AckedSeq)
	return &emptypb.Empty{}, nil
}
