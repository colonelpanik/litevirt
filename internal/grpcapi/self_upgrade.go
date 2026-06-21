package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// FetchBinary streams this daemon's own binary back to a peer so the peer can
// pull-and-self-upgrade. The first chunk carries the SHA-256 checksum, the
// binary version, and the schema version. Read-only; the caller authenticates
// with its host cert over mTLS (same trust boundary as the push UpgradeHost).
func (s *Server) FetchBinary(_ *pb.FetchBinaryRequest, stream grpc.ServerStreamingServer[pb.FetchBinaryChunk]) error {
	if err := RequireRole(stream.Context(), "operator"); err != nil {
		return err
	}
	data, err := os.ReadFile(s.daemonBinary())
	if err != nil {
		return status.Errorf(codes.Internal, "read binary: %v", err)
	}
	sum := sha256.Sum256(data)
	header := &pb.FetchBinaryChunk{
		Checksum:      hex.EncodeToString(sum[:]),
		Version:       s.version,
		SchemaVersion: int32(corrosion.CurrentSchemaVersion),
	}
	const chunkSize = 1 << 20
	for off := 0; off < len(data) || off == 0; off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		c := &pb.FetchBinaryChunk{Chunk: data[off:end]}
		if off == 0 { // attach the header to the first chunk
			c.Checksum, c.Version, c.SchemaVersion = header.Checksum, header.Version, header.SchemaVersion
		}
		if err := stream.Send(c); err != nil {
			return err
		}
		if len(data) == 0 {
			break
		}
	}
	return nil
}

// RunSelfUpgradeWatcher periodically checks whether this daemon is behind the
// cluster and, if so, pulls a newer binary from a peer and self-upgrades. It is
// the auto-catch-up for a host that was down during a cluster upgrade and came
// back on its old binary. Enabled via daemon config; see
// docs/self-upgrade-from-peer.md.
func (s *Server) RunSelfUpgradeWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// Let the cluster handshake / health settle after our own start before the
	// first evaluation, so a normal rolling-upgrade window isn't mistaken for a
	// persistent lag.
	select {
	case <-ctx.Done():
		return
	case <-time.After(45 * time.Second):
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.maybeSelfUpgrade(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// maybeSelfUpgrade evaluates the cluster and, if this host is behind, pulls and
// applies a newer binary then signals a re-exec.
func (s *Server) maybeSelfUpgrade(ctx context.Context) {
	// Don't race a push upgrade already in flight on this host.
	if h, _ := corrosion.GetHost(ctx, s.db, s.hostName); h != nil && h.State == "upgrading" {
		return
	}
	peer, ver, schema, ok := s.selfUpgradeTarget(ctx)
	if !ok {
		return
	}
	slog.Info("self-upgrade: behind cluster — pulling from peer",
		"peer", peer, "peerVersion", ver, "peerSchema", schema,
		"myVersion", s.version, "mySchema", corrosion.CurrentSchemaVersion)
	if err := s.pullAndApply(ctx, peer); err != nil {
		slog.Warn("self-upgrade: pull/apply failed", "peer", peer, "error", err)
		return
	}
	slog.Info("self-upgrade: binary applied, signalling re-exec", "from", peer)
	s.signalReExec()
}

// peerVersionInfo is a peer's live (version, schema) as reported by Ping.
type peerVersionInfo struct {
	host    string
	version string
	schema  int
}

// selfUpgradeTarget decides whether this host is behind and, if so, which peer
// to pull from. Two downgrade-safe signals (see docs/self-upgrade-from-peer.md):
//  1. a reachable peer at a strictly HIGHER schema_version (definitive), or
//  2. same schema, but a strict MAJORITY of {self + reachable peers} run a
//     single version that differs from ours.
//
// It never selects a peer whose schema is below ours.
func (s *Server) selfUpgradeTarget(ctx context.Context) (peer, version string, schema int, ok bool) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", "", 0, false
	}
	mySchema := corrosion.CurrentSchemaVersion
	var peers []peerVersionInfo
	for _, h := range hosts {
		if h.Name == s.hostName || h.State != "active" {
			continue
		}
		info, ok := s.pingPeerVersion(ctx, h.Name)
		if !ok {
			continue
		}
		peers = append(peers, info)
	}
	t, ok := chooseSelfUpgradeTarget(s.version, mySchema, peers)
	return t.host, t.version, t.schema, ok
}

// chooseSelfUpgradeTarget is the pure decision: given our (version, schema) and
// the reachable peers' reported (version, schema), return the peer to pull from
// (or ok=false). Downgrade-safe: never returns a peer whose schema < ours.
//   - Signal 1 (definitive): a peer at a strictly HIGHER schema.
//   - Signal 2 (majority): same schema as us, but a strict majority of
//     {self + peers} run a single version that differs from ours.
func chooseSelfUpgradeTarget(myVersion string, mySchema int, peers []peerVersionInfo) (peerVersionInfo, bool) {
	if len(peers) == 0 {
		return peerVersionInfo{}, false
	}

	// Signal 1: highest peer schema strictly above ours → catch up.
	best := peers[0]
	for _, p := range peers[1:] {
		if p.schema > best.schema {
			best = p
		}
	}
	if best.schema > mySchema {
		return best, true
	}

	// Signal 2: same-schema majority drift. Only peers at schema >= ours are
	// eligible targets (never downgrade schema).
	tally := map[string]int{}
	example := map[string]peerVersionInfo{}
	for _, p := range peers {
		if p.schema < mySchema {
			continue
		}
		tally[p.version]++
		example[p.version] = p
	}
	majority := (len(peers)+1)/2 + 1 // include self in the denominator
	for ver, n := range tally {
		if ver != myVersion && n >= majority {
			return example[ver], true
		}
	}
	return peerVersionInfo{}, false
}

// pingPeerVersion returns a peer's live (version, schema) via Ping.
func (s *Server) pingPeerVersion(ctx context.Context, host string) (peerVersionInfo, bool) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := s.peerClient(cctx, host)
	if err != nil {
		return peerVersionInfo{}, false
	}
	defer conn.Close()
	resp, err := client.Ping(cctx, &pb.PingRequest{})
	if err != nil {
		return peerVersionInfo{}, false
	}
	return peerVersionInfo{host: host, version: resp.GetVersion(), schema: int(resp.GetSchemaVersion())}, true
}

// pullAndApply fetches peer's binary, verifies it, and stages + swaps it in
// (without re-execing — the caller signals that). Guards against a schema
// downgrade and a no-op (identical version) swap.
func (s *Server) pullAndApply(ctx context.Context, peer string) error {
	client, conn, err := s.peerClient(ctx, peer)
	if err != nil {
		return fmt.Errorf("reach peer: %w", err)
	}
	defer conn.Close()
	stream, err := client.FetchBinary(ctx, &pb.FetchBinaryRequest{})
	if err != nil {
		return fmt.Errorf("open fetch: %w", err)
	}

	stagingPath := s.daemonBinary() + ".new"
	f, err := os.OpenFile(stagingPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create staging: %w", err)
	}
	hasher := sha256.New()
	w := io.MultiWriter(f, hasher)
	var checksum, peerVer string
	var peerSchema int32
	first := true
	for {
		c, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(stagingPath)
			return fmt.Errorf("recv: %w", rerr)
		}
		if first {
			checksum, peerVer, peerSchema = c.GetChecksum(), c.GetVersion(), c.GetSchemaVersion()
			first = false
		}
		if len(c.Chunk) > 0 {
			if _, werr := w.Write(c.Chunk); werr != nil {
				f.Close()
				os.Remove(stagingPath)
				return fmt.Errorf("write: %w", werr)
			}
		}
	}
	f.Close()

	if checksum == "" || hex.EncodeToString(hasher.Sum(nil)) != checksum {
		os.Remove(stagingPath)
		return fmt.Errorf("checksum mismatch from %s", peer)
	}
	// Downgrade / no-op guards.
	if int(peerSchema) < corrosion.CurrentSchemaVersion {
		os.Remove(stagingPath)
		return fmt.Errorf("refusing schema downgrade: peer schema %d < local %d", peerSchema, corrosion.CurrentSchemaVersion)
	}
	if peerVer == s.version {
		os.Remove(stagingPath)
		return fmt.Errorf("peer version equals ours (%s); nothing to do", peerVer)
	}

	if err := s.applyStagedBinary(ctx, stagingPath); err != nil {
		os.Remove(stagingPath)
		return err
	}
	return nil
}
