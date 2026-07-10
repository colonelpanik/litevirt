package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetStateDigest returns a lightweight fingerprint of each replicated table
// on this host. Callers can compare digests across hosts to detect drift.
func (s *Server) GetStateDigest(ctx context.Context, _ *emptypb.Empty) (*pb.StateDigestResponse, error) {
	// Dual-use: anti-entropy peers (host cert) OR an operator bearer (UI
	// diagnostics / `lv cluster sync`).
	if err := s.requirePeerOrRole(ctx, "operator"); err != nil {
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

func stateDigestResponse(hostName string, digests []corrosion.TableDigest) *pb.StateDigestResponse {
	resp := &pb.StateDigestResponse{HostName: hostName}
	for _, d := range digests {
		resp.Tables = append(resp.Tables, &pb.TableDigest{
			Name:  d.Name,
			Count: int32(d.Count),
			Hash:  d.Hash,
		})
	}
	return resp
}

// GetStateDump returns a full gzipped state dump that can be merged into
// another node's database. Used by `lv cluster sync` to force convergence.
func (s *Server) GetStateDump(ctx context.Context, _ *emptypb.Empty) (*pb.StateDumpResponse, error) {
	// Dual-use: anti-entropy peers (host cert) OR an operator bearer.
	if err := s.requirePeerOrRole(ctx, "operator"); err != nil {
		return nil, err
	}

	data := s.db.DumpStateBytes()
	return &pb.StateDumpResponse{Data: data}, nil
}

// stateDumpChunkSize bounds each StreamStateDump message well under the gRPC
// 4 MiB default, so the full dump streams regardless of total state size. A var
// (not const) so tests can shrink it to force multi-chunk behavior on small
// fixtures.
var stateDumpChunkSize = 1 << 20 // 1 MiB

// StreamStateDump streams the same gzipped state dump as GetStateDump, but in
// bounded chunks so a large cluster's dump can't exceed the gRPC max-message
// size and silently fail (the unary GetStateDump did, stalling anti-entropy
// convergence at scale). The chunks are contiguous slices of the exact blob
// GetStateDump returns, so the client reassembles and merges them identically.
// GetStateDump is kept for old peers; see the StreamStateDump RPC comment.
func (s *Server) StreamStateDump(_ *emptypb.Empty, stream grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	// Dual-use: anti-entropy peers (host cert) OR an operator bearer.
	if err := s.requirePeerOrRole(stream.Context(), "operator"); err != nil {
		return err
	}
	return streamStateDump(s.db.DumpStateBytes(), stream.Send)
}

func streamStateDump(data []byte, send func(*pb.StateDumpChunk) error) error {
	if len(data) == 0 {
		// Send a single final empty chunk so the client gets a clean,
		// unambiguous end-of-stream rather than a bare EOF.
		return send(&pb.StateDumpChunk{Final: true})
	}
	for off := 0; off < len(data); off += stateDumpChunkSize {
		end := off + stateDumpChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := send(&pb.StateDumpChunk{
			Data:  data[off:end],
			Final: end == len(data),
		}); err != nil {
			return err
		}
	}
	return nil
}

// GetSensitiveStateDigest returns fingerprints for secret-bearing tables. It
// is peer-mTLS only; operator-facing state dumps intentionally exclude these
// tables.
func (s *Server) GetSensitiveStateDigest(ctx context.Context, req *pb.SensitiveStateRequest) (*pb.StateDigestResponse, error) {
	if req.GetSender() == "" {
		return nil, status.Error(codes.InvalidArgument, "sender required")
	}
	if err := requireReplicationPeer(ctx, req.GetSender()); err != nil {
		return nil, err
	}

	digests, err := s.db.SensitiveStateDigest(ctx)
	if err != nil {
		return nil, err
	}
	return stateDigestResponse(s.hostName, digests), nil
}

// StreamSensitiveStateDump streams the peer-only sensitive repair dump. It must
// not be exposed through operator or REST surfaces.
func (s *Server) StreamSensitiveStateDump(req *pb.SensitiveStateRequest, stream grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	if req.GetSender() == "" {
		return status.Error(codes.InvalidArgument, "sender required")
	}
	if err := requireReplicationPeer(stream.Context(), req.GetSender()); err != nil {
		return err
	}
	return streamStateDump(s.db.DumpSensitiveStateBytes(), stream.Send)
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
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}

	// Schema-version skew check, keyed off DB-APPLIED schema (the columns each
	// DB actually has), not the binary const. Both sides advertise/compare their
	// effective DB schema, so after the pre-stage pass equalizes every node's DB
	// the gap is 0 throughout the rolling-binary window regardless of binary skew
	// — which is what makes a multi-version (N-step) rolling upgrade safe.
	//
	// Asymmetric: refuse ONLY when the sender's DB schema is strictly AHEAD of
	// ours (its writes may reference columns we genuinely lack). sender <= local
	// is accepted — under the additive-only invariant the sender touches a subset
	// of our columns. The runtime back-pressure net (replicator.ApplyRemoteMutations
	// + isSchemaMissingError) is the final guard if anything slips past this.
	if req.SenderSchemaVersion != 0 {
		localDB := s.db.EffectiveDBSchema()
		gap := int(req.SenderSchemaVersion) - localDB
		if gap > 0 {
			slog.Warn("pushMutations: sender DB schema ahead of ours; refusing",
				"sender", req.Sender,
				"sender_db_schema", req.SenderSchemaVersion,
				"local_db_schema", localDB,
				"sender_version", req.SenderVersion)
			return nil, status.Errorf(codes.FailedPrecondition,
				"sender DB schema version %d, local %d (receiver is missing migrations; pre-stage/upgrade this node)",
				req.SenderSchemaVersion, localDB)
		}
		if gap != 0 {
			slog.Info("pushMutations: schema skew (sender behind — accepted)",
				"sender", req.Sender,
				"sender_db_schema", req.SenderSchemaVersion,
				"local_db_schema", localDB)
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
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
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

func requireReplicationPeer(ctx context.Context, sender string) error {
	// Transport must be a trusted host cert (see requirePeerCert) — accepts a
	// forwarded-identity-promoted peer too (principalKind preserved), while the
	// CN==sender check below (CN also preserved through promotion) still pins it to
	// the claimed sender.
	if k := callerPrincipalKind(ctx); k != principalKindPeer && k != principalKindLocalRoot {
		return status.Error(codes.PermissionDenied, "replication RPC requires peer mTLS")
	}
	cn := callerMTLSCommonName(ctx)
	if cn == "" {
		return status.Error(codes.PermissionDenied, "replication RPC requires a peer certificate common name")
	}
	if cn != sender {
		return status.Errorf(codes.PermissionDenied,
			"replication sender %q does not match peer certificate %q", sender, cn)
	}
	return nil
}
