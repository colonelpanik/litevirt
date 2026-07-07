package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fetchBinaryMaxConcurrent caps simultaneous FetchBinary streams a node serves.
const fetchBinaryMaxConcurrent = 4

// FetchBinary streams this daemon's own binary back to a peer so the peer can
// pull-and-self-upgrade. The first chunk carries the SHA-256 checksum, the
// binary version, and the schema version.
//
// Peer-only: the caller must present a cluster host certificate over mTLS
// (requirePeerCert) — an operator's user/bearer credential cannot stream the
// daemon binary. A serving-side semaphore bounds concurrent streams so a
// fleet-wide version flip can't turn one source into a thundering-herd target.
func (s *Server) FetchBinary(_ *pb.FetchBinaryRequest, stream grpc.ServerStreamingServer[pb.FetchBinaryChunk]) error {
	if err := s.requirePeerCert(stream.Context()); err != nil {
		return err
	}
	if s.fetchBinarySem != nil {
		select {
		case s.fetchBinarySem <- struct{}{}:
			defer func() { <-s.fetchBinarySem }()
		default:
			return status.Error(codes.ResourceExhausted, "binary fetch capacity reached; retry shortly")
		}
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

// requirePeerCert authorizes an internal peer-only RPC: the caller must present
// a cluster host certificate over mTLS (CN = a known host). This is stricter
// than RequireRole("operator") — an operator's user cert (CN = username) does
// NOT pass — so a binary/secret-bearing peer RPC isn't reachable by an operator
// bearer/user credential.
func (s *Server) requirePeerCert(ctx context.Context) error {
	if callerAuthMethod(ctx) != authMethodMTLS {
		return status.Error(codes.PermissionDenied, "peer mTLS required")
	}
	cn := callerMTLSCommonName(ctx)
	if cn == "" {
		return status.Error(codes.PermissionDenied, "peer certificate common name required")
	}
	if h, _ := corrosion.GetHost(ctx, s.db, cn); h == nil {
		return status.Errorf(codes.PermissionDenied, "peer %q is not a known cluster host", cn)
	}
	return nil
}

// jitterDuration returns d randomized within [d/2, 3d/2) so a fleet that ticks
// or reboots together doesn't fan out in lockstep (the herd hazard at scale).
func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(mrand.Int63n(int64(d)))
}

// RunSelfUpgradeWatcher periodically checks whether this daemon is behind the
// cluster and, if so, pulls a newer binary from a peer and self-upgrades. It is
// the auto-catch-up for a host that was down during a cluster upgrade and came
// back on its old binary. Enabled via daemon config; see
// docs/self-upgrade-from-peer.md.
//
// Both the initial settle delay and every tick are jittered: a synchronized
// fleet reboot would otherwise herd on the first check and on each interval.
func (s *Server) RunSelfUpgradeWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// Jittered settle delay (~45s base) lets the cluster handshake / health
	// settle and desynchronizes a fleet that all started together.
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitterDuration(45 * time.Second)):
	}
	for {
		s.maybeSelfUpgrade(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitterDuration(interval)):
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
	if err := s.pullAndApply(ctx, peer, ver, schema); err != nil {
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
// to pull from. NEWEST-WINS convergence (see docs/self-upgrade-from-peer.md): pull
// the single most-advanced reachable build — highest schema_version, then (at equal
// schema) the strictly-newer semver version. No majority is required, so seeding ONE
// node flows to the whole fleet. Downgrade-safe: never selects a peer below our
// schema, and never chases an unparseable (dev / ephemeral) version.
//
// Peer (version, schema) is read from the replicated hosts table — one local
// query — instead of dialing every peer each tick (that was O(N^2) cluster-wide
// mTLS Pings). A single live Ping then CONFIRMS the chosen candidate before we
// pull, since the table is eventually consistent. It never selects a peer whose
// schema is below ours.
func (s *Server) selfUpgradeTarget(ctx context.Context) (peer, version string, schema int, ok bool) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", "", 0, false
	}
	mySchema := corrosion.CurrentSchemaVersion
	var peers []peerVersionInfo
	for _, h := range hosts {
		// Skip self, non-active peers, and rows with no reported version/schema
		// (an old peer that hasn't written schema_version yet → 0 → never a source).
		if h.Name == s.hostName || h.State != "active" || h.Version == "" {
			continue
		}
		peers = append(peers, peerVersionInfo{host: h.Name, version: h.Version, schema: h.SchemaVersion})
	}
	t, ok := chooseSelfUpgradeTarget(s.version, mySchema, peers)
	if !ok {
		return "", "", 0, false
	}
	// Spread binary-pull load: prefer an elected relay among equally-good sources.
	t = s.preferRelaySource(t, peers)

	// Confirm the candidate still reports the same (version, schema) RIGHT NOW —
	// the hosts table is eventually consistent, so a stale row (peer rolled back /
	// reimaged) must not drive a pull. Mismatch or unreachable → abort this tick;
	// re-discover next tick. This is ONE Ping, not a fan-out.
	live, lok := s.pingPeerVersion(ctx, t.host)
	if !candidateConfirmed(t, live, lok) {
		slog.Info("self-upgrade: candidate stale vs confirm-ping — aborting tick",
			"peer", t.host, "rowVersion", t.version, "rowSchema", t.schema,
			"liveVersion", live.version, "liveSchema", live.schema, "reachable", lok)
		return "", "", 0, false
	}
	return t.host, t.version, t.schema, true
}

// candidateConfirmed reports whether a live Ping confirms the candidate chosen
// from the (eventually-consistent) hosts table: it must be reachable and report
// the exact (version, schema) the table row claimed. A mismatch means the row
// was stale (peer rolled back / reimaged) and the pull must be aborted.
func candidateConfirmed(candidate, live peerVersionInfo, reachable bool) bool {
	return reachable && live.version == candidate.version && live.schema == candidate.schema
}

// preferRelaySource returns an elected relay among the peers that match the
// target's (version, schema), so a fleet-wide flip spreads binary pulls across
// the ~R relays instead of all hammering the first-sorted peer. Falls back to
// the original target when it's already a relay or none of the matches is one.
func (s *Server) preferRelaySource(target peerVersionInfo, peers []peerVersionInfo) peerVersionInfo {
	rs := corrosion.ComputeRelays(s.db.Members(), s.hostName, corrosion.RelayConfig{})
	if rs == nil || rs.IsRelay(target.host) {
		return target
	}
	for _, p := range peers {
		if p.version == target.version && p.schema == target.schema && rs.IsRelay(p.host) {
			return p
		}
	}
	return target
}

// chooseSelfUpgradeTarget is the pure decision: given our (version, schema) and
// the reachable peers' reported (version, schema), return the peer to pull from
// (or ok=false). Downgrade-safe: never returns a peer whose schema < ours.
//   - Signal 1 (definitive): a peer at a strictly HIGHER schema.
//   - Signal 2 (majority): same schema as us, but a strict majority of
//     {self + peers} run a single version that differs from ours.
func chooseSelfUpgradeTarget(myVersion string, mySchema int, peers []peerVersionInfo) (peerVersionInfo, bool) {
	// NEWEST-WINS: converge to the single most-advanced RELEASE reachable, so seeding
	// ONE node flows to the whole fleet (the only model that scales past a handful of
	// nodes). "Most advanced" = highest schema; among equal schema, the strictly-newer
	// release. STRICT + FORWARD-ONLY:
	//   - never downgrade schema (peers below our schema are skipped);
	//   - only a CLEAN TAGGED release is ever a candidate. A dev / git-describe build
	//     "vX.Y.Z-N-gHASH" IS valid semver but its "-N-gHASH" parses as a PRE-RELEASE,
	//     which semver ranks BELOW the bare release "vX.Y.Z". If such builds were
	//     orderable candidates, a peer on the release would "upgrade" a node running a
	//     NEWER dev build back to the tag — a silent DOWNGRADE — and a lone dev box
	//     could drag the fleet onto an un-blessed build. So they are filtered out here;
	//   - and we compare the best release against OUR OWN release core, so a node on a
	//     dev build is never reverted to the base release it descends from.
	var best peerVersionInfo
	found := false
	for _, p := range peers {
		if p.schema < mySchema {
			continue // never downgrade schema
		}
		if !isCleanRelease(p.version) {
			continue // never chase a dev / prerelease / unparseable build
		}
		if !found || moreAdvanced(p, best) {
			best, found = p, true
		}
	}
	if !found {
		return peerVersionInfo{}, false
	}
	// Pull only if the best release is strictly ahead of ME: a higher schema
	// (definitive, monotonic) or the same schema with a strictly-newer release than my
	// own release core (a valid semver required to compare — an unparseable local
	// version never moves on version alone, only on a higher schema).
	if best.schema > mySchema ||
		(best.schema == mySchema && semver.IsValid(myVersion) && semver.Compare(best.version, releaseCore(myVersion)) > 0) {
		return best, true
	}
	return peerVersionInfo{}, false
}

// isCleanRelease reports whether v is a valid, TAGGED release with no pre-release
// or build suffix — the only legitimate self-upgrade target. A git-describe build
// "vX.Y.Z-N-gHASH" is valid semver but carries a pre-release segment, so it is NOT a
// clean release and is never chased (nor downgraded to).
func isCleanRelease(v string) bool {
	return semver.IsValid(v) && semver.Prerelease(v) == "" && semver.Build(v) == ""
}

// releaseCore strips any pre-release / build suffix, returning the vX.Y.Z core. A
// clean release is returned unchanged; a git-describe dev build "v1.0.51-2-gHASH"
// returns "v1.0.51" — so a dev build is compared by the release it descends from and
// is never treated as older than (i.e. downgraded to) that base release.
func releaseCore(v string) string {
	if !semver.IsValid(v) {
		return v
	}
	if pre := semver.Prerelease(v); pre != "" {
		v = strings.TrimSuffix(v, pre)
	}
	if b := semver.Build(v); b != "" {
		v = strings.TrimSuffix(v, b)
	}
	return v
}

// moreAdvanced ranks two already-filtered CLEAN releases: a higher schema, or the
// same schema with a strictly-newer release version.
func moreAdvanced(a, b peerVersionInfo) bool {
	if a.schema != b.schema {
		return a.schema > b.schema
	}
	return semver.Compare(a.version, b.version) > 0
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

// verifyPulledBinary gates a streamed binary's advertised (version, schema)
// before it is swapped in: it must MATCH what the confirm-Ping promised (it
// changed under us otherwise), must NOT be a schema downgrade (the daemon
// refuses to start against a forward-migrated DB — refuse before the crash
// loop), and must NOT equal our own version (a no-op swap).
func verifyPulledBinary(peerVer string, peerSchema int, expectVer string, expectSchema, localSchema int, localVer string) error {
	if peerVer != expectVer || peerSchema != expectSchema {
		return fmt.Errorf("binary (%s/schema %d) != confirmed (%s/schema %d)", peerVer, peerSchema, expectVer, expectSchema)
	}
	if peerSchema < localSchema {
		return fmt.Errorf("refusing schema downgrade: peer schema %d < local %d", peerSchema, localSchema)
	}
	if peerVer == localVer {
		return fmt.Errorf("peer version equals ours (%s); nothing to do", peerVer)
	}
	return nil
}

// pullAndApply fetches peer's binary, verifies it, and stages + swaps it in
// (without re-execing — the caller signals that). The FetchBinary header must
// match the (version, schema) we confirmed for this peer; it also guards against
// a schema downgrade and a no-op (identical version) swap.
func (s *Server) pullAndApply(ctx context.Context, peer, expectVer string, expectSchema int) error {
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
	if err := verifyPulledBinary(peerVer, int(peerSchema), expectVer, expectSchema,
		corrosion.CurrentSchemaVersion, s.version); err != nil {
		os.Remove(stagingPath)
		return fmt.Errorf("peer %s: %w", peer, err)
	}

	if err := s.applyStagedBinary(ctx, stagingPath); err != nil {
		os.Remove(stagingPath)
		return err
	}
	return nil
}
