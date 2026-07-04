package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// newTransferToken returns a fresh, safename-valid per-transfer token used to
// name a target's internal staging repo so concurrent transfers can't collide. It
// fails if the system entropy source does — a zero/predictable token would defeat
// the per-transfer namespace isolation, so callers must abort rather than proceed.
func newTransferToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate transfer token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// pushManifestToStaging streams one container manifest (and only the chunks the
// target is missing) from a local repo into the target's per-transfer internal
// staging repo over peer mTLS, returning the token that names it. The error is
// returned verbatim so a caller can detect codes.Unimplemented (an old peer) and
// fall back to the shared-repo path.
func (s *Server) pushManifestToStaging(ctx context.Context, client pb.LiteVirtClient, srcRepo *pbsstore.Repo, name, timestamp string) (string, error) {
	m, err := srcRepo.GetManifest(name, timestamp, containerBackupDisk)
	if err != nil {
		return "", fmt.Errorf("load source manifest: %w", err)
	}
	token, err := newTransferToken()
	if err != nil {
		return "", err
	}
	sink := newRemoteRepoSink(ctx, client, &pb.RepoTarget{StagingToken: token})
	defer sink.Close()
	if _, err := pbsstore.SyncManifest(ctx, srcRepo, m, sink); err != nil {
		return "", err
	}
	return token, nil
}

// drivePeerRestore drives a container restore on a remote target over peer mTLS
// and classifies the outcome (drainRestoreStream). It is the single code path
// behind both cold migrate and failover relocation.
//
// Transport: it first tries the PR-4 push path — open the source repo (a logical
// repo NAME this daemon resolves in its OWN config), PushBackup-stream the one
// manifest into the target's internal staging repo, then RestoreContainer from
// that staging token — so NO shared NFS repo is needed. If the target is too old
// to receive a push (codes.Unimplemented) OR the source repo isn't openable here,
// it falls back to today's shared-repo path (pass the repo NAME for the target to
// re-open). A non-Unimplemented push failure is a real error (don't silently fall
// back and risk the target reading a repo it can't actually reach).
//
// mdPairs are appended to the outgoing context for the RestoreContainer call
// (migrate-from for cold migrate, relocate-token for failover) — never to the
// push, which is authenticated by the peer host cert alone.
func (s *Server) drivePeerRestore(ctx context.Context, target, repoName, name, timestamp string, start bool, proof *pb.RuntimeActionProof, mdPairs ...string) (corrosion.RestoreOutcome, error) {
	if s.migrateRestoreOverride != nil {
		// Test seam (shared by migrate + failover): return the classified outcome
		// without a second daemon.
		return s.migrateRestoreOverride(ctx, target, repoName, name, timestamp, start)
	}
	c, closeConn, err := s.dialPeer(ctx, target)
	if err != nil {
		return corrosion.RestoreNotAttempted, fmt.Errorf("dial target: %w", err)
	}
	defer closeConn()

	octx := ctx
	if len(mdPairs) > 0 {
		octx = metadata.AppendToOutgoingContext(ctx, mdPairs...)
	}

	// Open the source repo (logical name → path, resolved in THIS daemon's config)
	// so we can push from it. If it isn't openable here, we can't push — fall
	// straight through to the shared-repo path.
	var srcRepo *pbsstore.Repo
	if resolved, rerr := s.resolveBackupRepoPath(ctx, repoName); rerr == nil {
		srcRepo, _ = pbsstore.Open(resolved)
	}
	if srcRepo != nil {
		token, perr := s.pushManifestToStaging(ctx, c, srcRepo, name, timestamp)
		switch {
		case perr == nil:
			rs, e := c.RestoreContainer(octx, &pb.RestoreContainerRequest{
				StagingToken: token, Name: name, Timestamp: timestamp, HostName: target, Start: start, Proof: proof,
			})
			if e != nil {
				return corrosion.RestoreNotAttempted, e
			}
			return drainRestoreStream(rs)
		case status.Code(perr) == codes.Unimplemented:
			// Old peer: fall through to the shared-repo path below.
		default:
			return corrosion.RestoreNotAttempted, fmt.Errorf("push backup to target: %w", perr)
		}
	}

	// Shared-repo fallback: the target re-opens repoName in its own config (the
	// pre-PR-4 behavior; only works when the repo is reachable from both hosts).
	rs, e := c.RestoreContainer(octx, &pb.RestoreContainerRequest{
		RepoPath: repoName, Name: name, Timestamp: timestamp, HostName: target, Start: start, Proof: proof,
	})
	if e != nil {
		return corrosion.RestoreNotAttempted, e
	}
	return drainRestoreStream(rs)
}
