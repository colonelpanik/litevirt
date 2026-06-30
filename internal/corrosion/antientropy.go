package corrosion

import (
	"context"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// AntiEntropy periodically compares state digests with peers and triggers
// a full state merge when drift is detected. This is a safety net — the
// primary replication path is the WAL-based Replicator.
type AntiEntropy struct {
	client   *Client
	pkiDir   string
	interval time.Duration
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
			ae.checkPeers(ctx)
		}
	}
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

	// A digest mismatch whose only delta is a known, unchanged unresolved tie is
	// INTENTIONAL divergence (kept-local by the resolver). Suppressing it here is
	// the bound that stops a stuck tie from triggering a full dump+merge every
	// cycle (the old infinite no-op resync). A real new write changes a hash and
	// invalidates the memo, so genuine drift still syncs.
	if mismatched := ae.genuineMismatches(peerName, resp.Tables, localMap); len(mismatched) > 0 {
		slog.Info("anti-entropy: syncing from peer", "peer", peerName, "tables", mismatched)
		data, err := fetchStateDump(ctx, client)
		if err != nil {
			slog.Warn("anti-entropy: dump RPC error", "peer", peerName, "error", err)
		} else {
			ae.client.MergeStateBytesLWW(data)
			slog.Info("anti-entropy: merge complete", "peer", peerName, "bytes", len(data))
			ae.updateReconciledMemo(peerName, resp.Tables, func() ([]TableDigest, error) {
				return ae.client.StateDigest(ctx)
			})
		}
	}

	ae.checkSensitivePeer(ctx, client, peerName, sensitiveMap)
}

// genuineMismatches returns the tables whose digest differs from the peer AND is
// not an already-reconciled, unchanged unresolved divergence (those are skipped).
func (ae *AntiEntropy) genuineMismatches(peer string, remote []*pb.TableDigest, localMap map[string]TableDigest) []string {
	var out []string
	for _, r := range remote {
		local, exists := localMap[r.Name]
		if exists && local.Count == int(r.Count) && local.Hash == r.Hash {
			continue // in sync
		}
		if exists && ae.client.isReconciledDivergent(peer, r.Name, local.Hash, r.Hash) {
			continue // intentional, already-reconciled divergence — don't re-pull
		}
		lh := ""
		if exists {
			lh = local.Hash
		}
		slog.Info("anti-entropy: drift detected",
			"peer", peer, "table", r.Name, "local_hash", lh, "remote_hash", r.Hash)
		out = append(out, r.Name)
	}
	return out
}

// updateReconciledMemo runs after a merge: for each table still divergent from
// the peer because of a known unresolved tie, it memoizes the (peer,table)
// digest pair so the next cycle won't re-pull; for tables that converged it
// clears any stale memo.
func (ae *AntiEntropy) updateReconciledMemo(peer string, remote []*pb.TableDigest, recompute func() ([]TableDigest, error)) {
	nl, err := recompute()
	if err != nil {
		return
	}
	nm := make(map[string]TableDigest, len(nl))
	for _, d := range nl {
		nm[d.Name] = d
	}
	for _, r := range remote {
		cur, ok := nm[r.Name]
		if ok && cur.Count == int(r.Count) && cur.Hash == r.Hash {
			ae.client.clearReconciledDivergent(peer, r.Name)
			continue
		}
		if ae.client.hasUnresolvedForTable(r.Name) {
			lh := ""
			if ok {
				lh = cur.Hash
			}
			ae.client.markReconciledDivergent(peer, r.Name, lh, r.Hash)
		}
	}
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

	mismatched := ae.genuineMismatches(peerName, resp.Tables, localMap)
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
	ae.client.MergeSensitiveStateBytesLWW(data)
	slog.Info("anti-entropy: sensitive merge complete", "peer", peerName, "bytes", len(data))
	ae.updateReconciledMemo(peerName, resp.Tables, func() ([]TableDigest, error) {
		return ae.client.SensitiveStateDigest(ctx)
	})
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
