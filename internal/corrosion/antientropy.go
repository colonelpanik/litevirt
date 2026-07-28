package corrosion

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// antiEntropyCooldown debounces manual/scheduled triggers: a pass won't start if one ran
// within this window. Well under the default 60s interval (so a scheduled tick is never
// debounced) and well above a hammer loop (so `lv cluster converge --all` in a tight loop
// can't turn into a self-inflicted SQLite-lock load test).
const antiEntropyCooldown = 12 * time.Second

// AntiEntropy periodically compares state digests with peers and triggers
// a full state merge when drift is detected. This is a safety net — the
// primary replication path is the WAL-based Replicator.
type AntiEntropy struct {
	client   *Client
	pkiDir   string
	interval time.Duration

	// mu guards the trigger decision only (not the pass itself): a pass no-ops when one is
	// already running or ran within antiEntropyCooldown. It never bypasses checkPeers's
	// per-table digest-gating (merge only on mismatch) — it just decides whether to run.
	mu         sync.Mutex
	inProgress bool
	lastRan    time.Time
}

// NewAntiEntropy creates an anti-entropy checker.
func NewAntiEntropy(client *Client, pkiDir string, interval time.Duration) *AntiEntropy {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &AntiEntropy{
		client:   client,
		pkiDir:   pkiDir,
		interval: interval,
	}
}

// Start runs the anti-entropy loop until ctx is cancelled.
func (ae *AntiEntropy) Start(ctx context.Context) {
	slog.Info("anti-entropy: starting", "interval", ae.interval)
	ticker := time.NewTicker(ae.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ae.RunOnce(ctx) // debounced; scheduled ticks share the trigger guard
		}
	}
}

// RunOnce runs a single anti-entropy pass now, unless one is already in progress or ran
// within antiEntropyCooldown, in which case it no-ops. Returns true iff a pass actually ran.
// It blocks until the pass completes, so a caller (e.g. `lv cluster converge`) can read
// digests afterward knowing convergence was attempted. It ONLY schedules the existing pass —
// checkPeers still merges a table only on a digest mismatch.
func (ae *AntiEntropy) RunOnce(ctx context.Context) bool {
	ae.mu.Lock()
	if ae.inProgress || (!ae.lastRan.IsZero() && time.Since(ae.lastRan) < antiEntropyCooldown) {
		ae.mu.Unlock()
		return false
	}
	ae.inProgress = true
	ae.mu.Unlock()

	ae.checkPeers(ctx)

	ae.mu.Lock()
	ae.inProgress = false
	ae.lastRan = time.Now()
	ae.mu.Unlock()
	return true
}

func (ae *AntiEntropy) checkPeers(ctx context.Context) {
	peers := ae.client.Members()
	if len(peers) == 0 {
		return
	}

	// Get local digest.
	localDigests, err := ae.client.StateDigest(ctx)
	if err != nil {
		slog.Warn("anti-entropy: local digest error", "error", err)
		return
	}
	localMap := make(map[string]TableDigest, len(localDigests))
	for _, d := range localDigests {
		localMap[d.Name] = d
	}
	sensitiveDigests, err := ae.client.SensitiveStateDigest(ctx)
	if err != nil {
		slog.Warn("anti-entropy: local sensitive digest error", "error", err)
	}
	sensitiveMap := make(map[string]TableDigest, len(sensitiveDigests))
	for _, d := range sensitiveDigests {
		sensitiveMap[d.Name] = d
	}

	for _, peer := range peers {
		ae.checkPeer(ctx, peer.Name, localMap, sensitiveMap)
	}
}

func (ae *AntiEntropy) checkPeer(ctx context.Context, peerName string, localMap, sensitiveMap map[string]TableDigest) {
	client, conn, err := ae.peerClient(ctx, peerName)
	if err != nil {
		slog.Debug("anti-entropy: cannot reach peer", "peer", peerName, "error", err)
		return
	}
	defer conn.Close()

	resp, err := client.GetStateDigest(ctx, &emptypb.Empty{})
	if err != nil {
		slog.Debug("anti-entropy: digest RPC error", "peer", peerName, "error", err)
		return
	}

	if mismatched := digestMismatches(peerName, resp.Tables, localMap); len(mismatched) > 0 {
		slog.Info("anti-entropy: syncing from peer", "peer", peerName, "tables", mismatched)
		data, err := fetchStateDump(ctx, client)
		if err != nil {
			slog.Warn("anti-entropy: dump RPC error", "peer", peerName, "error", err)
		} else if mergeErr := ae.client.MergeStateBytesLWW(data); mergeErr != nil {
			// Operational/commit failure during merge: this cycle's convergence is incomplete.
			// The merge is per-row-idempotent and non-destructive, so the next cycle retries.
			slog.Warn("anti-entropy: merge error (will retry next cycle)", "peer", peerName, "error", mergeErr)
		} else {
			slog.Info("anti-entropy: merge complete", "peer", peerName, "bytes", len(data))
		}
	}

	ae.checkSensitivePeer(ctx, client, peerName, sensitiveMap)
}

// digestMismatches returns the tables whose digest differs from the peer.
func digestMismatches(peer string, remote []*pb.TableDigest, localMap map[string]TableDigest) []string {
	var out []string
	for _, r := range remote {
		local, exists := localMap[r.Name]
		if !exists {
			slog.Info("anti-entropy: drift detected", "peer", peer, "table", r.Name, "local_hash", "", "remote_hash", r.Hash)
			out = append(out, r.Name)
			continue
		}
		// Pairwise negotiation: compare the order-invariant v2 hash ONLY when BOTH sides
		// supplied it (⇒ both have digest_v2 enabled); otherwise compare the positional v1
		// hash. Count is always compared.
		useV2 := local.HashV2 != "" && r.GetHashV2() != ""
		var lh, rh string
		if useV2 {
			lh, rh = local.HashV2, r.GetHashV2()
		} else {
			lh, rh = local.Hash, r.Hash
		}
		if local.Count == int(r.Count) && lh == rh {
			continue // in sync
		}
		slog.Info("anti-entropy: drift detected",
			"peer", peer, "table", r.Name, "digest", map[bool]string{true: "v2", false: "v1"}[useV2],
			"local_hash", lh, "remote_hash", rh)
		out = append(out, r.Name)
	}
	return out
}

func (ae *AntiEntropy) checkSensitivePeer(ctx context.Context, client pb.LiteVirtClient, peerName string, localMap map[string]TableDigest) {
	if len(localMap) == 0 {
		return
	}
	req := &pb.SensitiveStateRequest{Sender: ae.client.HostName()}
	resp, err := client.GetSensitiveStateDigest(ctx, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Debug("anti-entropy: peer has no sensitive state digest RPC", "peer", peerName)
			return
		}
		slog.Debug("anti-entropy: sensitive digest RPC error", "peer", peerName, "error", err)
		return
	}

	mismatched := digestMismatches(peerName, resp.Tables, localMap)
	if len(mismatched) == 0 {
		return
	}

	slog.Info("anti-entropy: syncing sensitive state from peer", "peer", peerName, "tables", mismatched)
	data, err := fetchSensitiveStateDump(ctx, client, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Debug("anti-entropy: peer has no sensitive state dump RPC", "peer", peerName)
			return
		}
		slog.Warn("anti-entropy: sensitive dump RPC error", "peer", peerName, "error", err)
		return
	}
	if mergeErr := ae.client.MergeSensitiveStateBytesLWW(data); mergeErr != nil {
		slog.Warn("anti-entropy: sensitive merge error (will retry next cycle)", "peer", peerName, "error", mergeErr)
		return
	}
	slog.Info("anti-entropy: sensitive merge complete", "peer", peerName, "bytes", len(data))
}

// fetchStateDump pulls a peer's full state dump, preferring the chunked
// StreamStateDump RPC (which can't hit the gRPC max-message size) and falling
// back to the legacy unary GetStateDump when the peer is an older build that
// doesn't implement the stream. This keeps anti-entropy working in a
// mixed-version cluster in both directions.
func fetchStateDump(ctx context.Context, client pb.LiteVirtClient) ([]byte, error) {
	stream, err := client.StreamStateDump(ctx, &emptypb.Empty{})
	if err == nil {
		var buf []byte
		for {
			chunk, rerr := stream.Recv()
			if rerr == io.EOF {
				return buf, nil
			}
			if rerr != nil {
				// An old peer reports Unimplemented (usually on the first Recv,
				// so buf is still empty) — fall back to the unary RPC.
				if status.Code(rerr) == codes.Unimplemented {
					break
				}
				return nil, rerr
			}
			buf = append(buf, chunk.Data...)
		}
	} else if status.Code(err) != codes.Unimplemented {
		return nil, err
	}

	// Fallback: legacy unary full-state dump.
	dump, derr := client.GetStateDump(ctx, &emptypb.Empty{})
	if derr != nil {
		return nil, derr
	}
	return dump.Data, nil
}

func fetchSensitiveStateDump(ctx context.Context, client pb.LiteVirtClient, req *pb.SensitiveStateRequest) ([]byte, error) {
	stream, err := client.StreamSensitiveStateDump(ctx, req)
	if err != nil {
		return nil, err
	}
	var buf []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		buf = append(buf, chunk.Data...)
	}
}

func (ae *AntiEntropy) peerClient(ctx context.Context, peerName string) (pb.LiteVirtClient, *grpc.ClientConn, error) {
	target, err := resolvePeerTarget(ctx, ae.client, peerName)
	if err != nil {
		return nil, nil, err
	}
	// Raise the receive limit so the legacy unary GetStateDump fallback can
	// pull a large full-state dump from an old peer. StreamStateDump chunks
	// stay well under the 4 MiB default and don't need this.
	conn, err := pki.PeerDial(ae.pkiDir, target,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(antiEntropyMaxMsgSize)))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}

// antiEntropyMaxMsgSize bounds the legacy unary state-dump fallback's receive
// size; matches the server's grpcMaxMsgSize backstop.
const antiEntropyMaxMsgSize = 64 << 20 // 64 MiB

// The full-state merge (MergeStateBytesLWW) lives in sync.go — it is the single
// merge engine shared by all callers.
