package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Isolation + reseed (§A, schema v49).
//
// IsolateHost records — from a HEALTHY PEER — that another host's state was
// produced outside the cluster's compatibility regime. ReseedHost is the only
// supported exit: it is forwarded to the isolated host, which discards its
// replicated state, pulls a full dump from a healthy peer, VERIFIES the result
// converged, and only then clears its epoch. Half a reseed is worse than none,
// so an unverified pull leaves the node isolated.

// IsolateHost is admin-gated and audited. It deliberately refuses to isolate
// the node serving the call: the epoch exists precisely so the observation
// comes from someone other than the suspect (corrosion.IsolateHost enforces
// this too — this is the operator-facing half of the same rule).
func (s *Server) IsolateHost(ctx context.Context, req *pb.IsolateHostRequest) (*pb.HostIsolationStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "host name required")
	}
	reason := req.GetReason()
	if reason == "" {
		reason = corrosion.IsolationManual
	}
	if req.GetName() == s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to isolate %q from itself — run this against a healthy peer, "+
				"which is the whole point of recording isolation in cluster state", req.GetName())
	}
	if err := corrosion.IsolateHost(ctx, s.db, s.hostName, req.GetName(), reason); err != nil {
		s.audit(ctx, "host.isolate", req.GetName(), "reason="+reason, "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	epoch, gotReason, err := corrosion.HostIsolation(ctx, s.db, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read back isolation: %v", err)
	}
	s.audit(ctx, "host.isolate", req.GetName(), fmt.Sprintf("reason=%s epoch=%d", gotReason, epoch), "ok")
	slog.Warn("host isolated — its replication is refused until a verified reseed",
		"host", req.GetName(), "epoch", epoch, "reason", gotReason, "observer", s.hostName)
	return &pb.HostIsolationStatus{
		HostName: req.GetName(), IsolationEpoch: epoch, IsolationReason: gotReason,
	}, nil
}

// ReseedHost runs ON the isolated host (forwarded there like repair-owner): it
// is the node's own state being replaced, and only it can stop its local loops
// before that happens.
func (s *Server) ReseedHost(ctx context.Context, req *pb.ReseedHostRequest) (*pb.ReseedHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "host name required")
	}
	if req.GetName() != s.hostName {
		c, conn, err := s.peerClient(ctx, req.GetName())
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward reseed to %s: %v", req.GetName(), err)
		}
		defer conn.Close()
		// The target does the dangerous half (discard + pull + VERIFY) because
		// it is its own state; WE record the clear, because the clear must be
		// peer-written for the same reason the isolation is. It also has to be:
		// the target's own pushes are refused while it is isolated, so a
		// self-written clear could never reach the cluster — the node would
		// verify convergence and stay quarantined forever.
		fwd := &pb.ReseedHostRequest{Name: req.GetName(), Source: req.GetSource(), DrivenByPeer: s.hostName}
		resp, err := c.ReseedHost(ctx, fwd)
		if err != nil {
			return nil, err
		}
		if err := corrosion.ClearHostIsolation(ctx, s.db, req.GetName(), resp.GetClearedEpoch()); err != nil {
			s.audit(ctx, "host.reseed", req.GetName(), "verified but clear failed", "error")
			return nil, status.Errorf(codes.FailedPrecondition,
				"%s converged with %s, but clearing isolation epoch %d failed — it stays isolated "+
					"(a newer isolation may have been recorded while the reseed ran; re-run): %v",
				req.GetName(), resp.GetSource(), resp.GetClearedEpoch(), err)
		}
		s.audit(ctx, "host.reseed", req.GetName(),
			fmt.Sprintf("source=%s cleared_epoch=%d", resp.GetSource(), resp.GetClearedEpoch()), "ok")
		slog.Info("peer reseeded and rejoined the compatibility regime",
			"host", req.GetName(), "source", resp.GetSource(), "cleared_epoch", resp.GetClearedEpoch(),
			"cleared_by", s.hostName)
		return resp, nil
	}
	// Running ON the isolated node: verify only. A node cannot clear its own
	// quarantine (see above), so this must be driven from a healthy peer.
	if req.GetDrivenByPeer() == "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"run reseed against a HEALTHY peer, not on %s itself: the epoch clear must be "+
				"peer-written, and this node's own writes are refused while it is isolated", s.hostName)
	}

	epoch, reason, err := corrosion.HostIsolation(ctx, s.db, s.hostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read isolation: %v", err)
	}
	if epoch == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is not isolated — reseed replaces this node's entire replicated state "+
				"and is not a general repair tool (see `lv cluster converge`)", s.hostName)
	}

	// Refuse while THIS node is still WAL-quarantined: the binary is still below
	// a token the cluster latched, so replacing its state changes nothing about
	// why it was isolated — it would re-detect and re-quarantine on the next
	// restart, and meanwhile the cleared epoch means peers stop refusing it,
	// leaving only its own self-assessment as protection. That is precisely the
	// judgement §A says cannot be relied on. Upgrade the binary first, then
	// reseed. (Found on the lab: a reseed cleared the epoch on a node still
	// running the rolled-back build.)
	if s.walQuarantinedNow() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is still WAL-quarantined: its binary remains below a capability token this "+
				"cluster latched, so a reseed would clear the isolation without fixing its cause. "+
				"Upgrade the binary first, then reseed", s.hostName)
	}

	// Refuse while this node owns RUNNING workloads. Discarding replicated
	// state under a live VM is the one way this primitive could destroy
	// something: the row that says "this VM is mine and running" would vanish
	// and come back from a peer that may disagree. Drain first — the same rule
	// the watchdog disarm path uses.
	if running, err := s.runningWorkloadCount(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "check running workloads: %v", err)
	} else if running > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s still runs %d workload(s) — drain it first (`lv host drain %s`); "+
				"reseed discards this node's replicated state, which must not happen under a live workload",
			s.hostName, running, s.hostName)
	}

	source, err := s.pickReseedSource(ctx, req.GetSource())
	if err != nil {
		return nil, err
	}
	// dialPeer rather than peerClient: production behaviour is identical (it
	// falls through to the same mTLS dial), and it is the seam that lets the
	// preflight below be tested against a source this node never had to reach.
	peer, closePeer, err := s.dialPeer(ctx, source)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reach reseed source %s: %v", source, err)
	}
	defer closePeer()

	// PREFLIGHT the source before anything is destroyed. The same check runs
	// again in verifyReseedConvergence, and the repetition is deliberate: these
	// guard different things. Here it protects this node's STATE — an unfit
	// source is refused while the local rows are still intact, so a reseed that
	// was never going to work costs nothing. There it guards the EPOCH CLEAR,
	// which is a claim about the cluster and must be re-established against the
	// source as it is at that moment, not as it was before the transfer.
	//
	// Without this the order was backwards: discard, merge from the unfit source,
	// and only then decline to certify it — leaving the node strictly worse off
	// than before it asked, and needing a repeat reseed to become usable.
	if mismatch, cerr := s.checkReseedSource(ctx, source, peer); cerr != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", cerr)
	} else if mismatch != "" {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source+" unfit="+mismatch, "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is not a usable reseed source: %s. Nothing was discarded — %s is unchanged "+
				"and still isolated at epoch %d", source, mismatch, s.hostName, epoch)
	}

	s.audit(ctx, "host.reseed", s.hostName, "source="+source+" epoch="+fmt.Sprint(epoch), "started")

	// Pull the source's full state and merge it. The merge is LWW and
	// per-row-idempotent, so a partial pull cannot corrupt — it simply fails
	// verification below and leaves the node isolated.
	dump, err := fetchPeerStateDump(ctx, peer)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Unavailable, "pull state from %s: %v", source, err)
	}
	// The sensitive lane travels with the operator one. The discard below clears
	// the secret-bearing tables too (they used to survive a reseed, which is how
	// a quarantined credential reached the whole fleet), so they have to be
	// repopulated here and not left to anti-entropy: a node with no 2FA rows has
	// no 2FA at all, because the API reads "no factors" as "no 2FA". Fetching
	// BEFORE the discard keeps the no-state window as short as it already was.
	//
	// A source on an older build has no sensitive RPC. Refuse rather than reseed
	// into a node with its secrets deleted and nothing to restore them.
	sensitiveDump, err := s.fetchPeerSensitiveDump(ctx, peer)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Unavailable,
			"pull sensitive state from %s: %v", source, err)
	}

	// DISCARD, then merge — with the dump already in hand. A merge alone is
	// additive, so the rows this node produced outside the regime (precisely
	// what the quarantine contains) would survive and be re-injected once the
	// epoch cleared. The lab proved it: a merge-only reseed failed its own
	// convergence check because the stale rows were still there.
	// MARK before the first DELETE. The three steps below cannot be one
	// transaction, and the gap between the operator merge and the sensitive merge
	// is a fail-OPEN window: users and their password hashes come back in the
	// first, user_2fa only in the second, and LocalRealm.Authenticate reads an
	// empty user_2fa as "nobody enrolled". A process that dies in between used to
	// come back authenticating every enrolled account by password alone.
	//
	// The marker is durable and local-only, so it survives both the death and the
	// discard, and the pre-session login paths refuse while it is set. It is
	// cleared once the sensitive merge has committed — not after convergence,
	// because by then the window is already shut and holding it longer would
	// refuse logins on a node whose secrets are fully restored.
	// ONE at a time in this process. Two concurrent ReseedHost calls on the same
	// node both reach BeginReseed, the second REPLACES the first's marker (the
	// row is keyed id = 1), and whichever calls FinishReseed first clears the
	// login gate while the other is still discarding — user_2fa empty, the gate
	// open, and the generation unchanged between admission and mint. See
	// reseedInFlight for why this refuses rather than represents the overlap.
	releaseReseed, admitted := s.reseeding.acquire()
	if !admitted {
		return nil, status.Error(codes.FailedPrecondition,
			"a reseed is already running on this node; wait for it to finish or fail before "+
				"starting another (two at once would clear each other's login gate)")
	}
	defer releaseReseed()

	reseedGeneration, err := s.db.BeginReseed(ctx, source)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal,
			"could not mark this node as mid-reseed, so the reseed was not started "+
				"(nothing was discarded): %v", err)
	}

	cleared, err := s.db.DiscardReplicatedStateForReseed(ctx)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal,
			"discard local state (%d tables cleared before the failure; this node now needs a "+
				"repeat reseed to be usable): %v", cleared, err)
	}
	if err := s.db.MergeStateBytesLWW(dump); err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal, "merge state from %s: %v", source, err)
	}
	if err := s.db.MergeSensitiveStateBytesLWW(sensitiveDump); err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal,
			"merge sensitive state from %s (this node's secret-bearing tables are now "+
				"EMPTY and it needs a repeat reseed before it can serve): %v", source, err)
	}

	// The window is shut: user_2fa is restored, so the login gate may lift.
	if err := s.db.FinishReseed(ctx, reseedGeneration); err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal,
			"state was restored from %s but this node could not clear its reseed marker, so it "+
				"will keep refusing logins until it does: %v", source, err)
	}

	// VERIFY convergence before clearing anything. Only a verified reseed earns
	// the epoch clear; anything else leaves the node isolated with the reason
	// intact, which is the safe direction.
	converged, mismatch, err := s.verifyReseedConvergence(ctx, source, peer)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Internal, "verify convergence: %v", err)
	}
	if mismatch != "" {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source+" mismatch="+mismatch, "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"reseed did NOT converge with %s (%s) — %s stays isolated at epoch %d (%s); "+
				"half a reseed is worse than none, so the epoch was not cleared",
			source, mismatch, s.hostName, epoch, reason)
	}

	// VERIFIED. The caller (a healthy peer) records the clear — see the
	// forwarding branch. We deliberately do NOT clear our own row: it would not
	// replicate (our pushes are refused while isolated) and would leave the
	// cluster and this node disagreeing about whether the quarantine is over.
	s.audit(ctx, "host.reseed", s.hostName,
		fmt.Sprintf("source=%s verified_epoch=%d tables=%d", source, epoch, converged), "ok")
	slog.Info("reseed converged — awaiting the peer-written epoch clear",
		"host", s.hostName, "source", source, "epoch", epoch, "tables", converged)
	return &pb.ReseedHostResponse{
		HostName: s.hostName, Source: source, ClearedEpoch: epoch, TablesConverged: int32(converged),
	}, nil
}

// runningWorkloadCount counts the live VMs and containers this host owns.
func (s *Server) runningWorkloadCount(ctx context.Context) (int, error) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, vm := range vms {
		if vm.State == "running" {
			n++
		}
	}
	cts, err := corrosion.ListContainers(ctx, s.db, s.hostName)
	if err != nil {
		return 0, err
	}
	for _, ct := range cts {
		if ct.State == "running" {
			n++
		}
	}
	return n, nil
}

// pickReseedSource resolves the peer to reseed from: the named one, or any
// HEALTHY (non-isolated, active) peer. Reseeding from another isolated node
// would copy the very state the regime exists to contain.
func (s *Server) pickReseedSource(ctx context.Context, want string) (string, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", status.Errorf(codes.Internal, "list hosts: %v", err)
	}
	for _, h := range hosts {
		if h.Name == s.hostName {
			continue
		}
		if want != "" && h.Name != want {
			continue
		}
		epoch, _, err := corrosion.HostIsolation(ctx, s.db, h.Name)
		if err != nil {
			continue
		}
		if epoch > 0 {
			if want != "" {
				return "", status.Errorf(codes.FailedPrecondition,
					"reseed source %q is itself isolated (epoch %d) — reseeding from it would copy "+
						"the state this regime exists to contain", h.Name, epoch)
			}
			continue
		}
		if h.State != "" && h.State != "active" {
			if want != "" {
				return "", status.Errorf(codes.FailedPrecondition,
					"reseed source %q is %s, not active", h.Name, h.State)
			}
			continue
		}
		return h.Name, nil
	}
	if want != "" {
		return "", status.Errorf(codes.NotFound, "reseed source %q not found", want)
	}
	return "", status.Error(codes.FailedPrecondition,
		"no healthy peer to reseed from — every other host is isolated, inactive, or unknown")
}

// reseedConvergenceExempt are tables whose digests legitimately differ between
// any two healthy nodes, so requiring them to match would make EVERY reseed
// fail verification — and therefore never clear an epoch, leaving quarantine
// with no exit. They are per-node observations and append-only evidence, not
// shared authority:
//
//   - audit_log: each host appends its OWN actions, and this reseed's own
//     "started" row is written before the check runs. Integrity here is the
//     audit chain's job (signed, independently verifiable), not digest equality.
//   - host_health / clock_skew: per-OBSERVER measurements — node A's view of
//     node C is not supposed to equal node B's.
//
// Everything else — the tables where an out-of-regime node could inject
// AUTHORITY (vms, containers, hosts, networks, operations, …) — must match.
var reseedConvergenceExempt = map[string]bool{
	"host_health": true,
	"clock_skew":  true,
	// hosts: every node self-reports its OWN row (version, capacity,
	// heartbeat), and an isolated node's self-updates cannot replicate to the
	// source by construction — its pushes are refused. So the two copies can
	// never match while it is isolated, and requiring it would make reseed
	// impossible. The one field that carries authority here, isolation_epoch,
	// is checked by the guarded clear itself (which pins the exact epoch), not
	// by digest equality.
	"hosts": true,
}

// fetchPeerSensitiveDump pulls the source's secret-bearing tables over the
// peer-mTLS lane, the same one anti-entropy repairs them on. It is a hard
// requirement of a reseed: the discard now empties these tables, so a node that
// cannot refill them would come back with no credentials, no 2FA factors and no
// recovery codes.
func (s *Server) fetchPeerSensitiveDump(ctx context.Context, peer pb.LiteVirtClient) ([]byte, error) {
	stream, err := peer.StreamSensitiveStateDump(ctx, &pb.SensitiveStateRequest{Sender: s.hostName})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, fmt.Errorf("the source has no sensitive state dump RPC (older build); " +
				"reseeding from it would delete this node's secret-bearing tables with " +
				"nothing to restore them")
		}
		return nil, err
	}
	var buf []byte
	for {
		chunk, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			return buf, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		buf = append(buf, chunk.GetData()...)
	}
}

// reseedLocalDigests returns every table digest a reseed must converge on:
// the operator set AND the peer-only sensitive set.
//
// The sensitive tables were missing, so a reseed compared the operator lane,
// declared itself verified and cleared the isolation epoch while the
// quarantined credentials, 2FA factors, recovery codes, notification targets
// and runtime action proofs were still sitting in it — and a healthy peer then
// pulled them fleet-wide. A reseed that cannot show those tables match its
// source has not converged with it.
func (s *Server) reseedLocalDigests(ctx context.Context) ([]corrosion.TableDigest, error) {
	digests, err := s.db.StateDigest(ctx)
	if err != nil {
		return nil, err
	}
	sensitive, err := s.db.SensitiveStateDigest(ctx)
	if err != nil {
		return nil, fmt.Errorf("sensitive digest: %w", err)
	}
	return append(digests, sensitive...), nil
}

// reseedRemoteDigests reads the same two sets from the source.
//
// A source on an older build without the sensitive RPC returns Unimplemented.
// That is not fatal — reseedDigestsConverged skips any table the source does
// not report, which is the existing rule for a version difference — but it is
// logged, because it means the sensitive half went unverified.
func (s *Server) reseedRemoteDigests(ctx context.Context, peer pb.LiteVirtClient) (map[string]string, error) {
	remote := map[string]string{}
	resp, err := peer.GetStateDigest(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	for _, t := range resp.GetTables() {
		remote[t.GetName()] = t.GetHash()
	}
	sens, err := peer.GetSensitiveStateDigest(ctx, &pb.SensitiveStateRequest{Sender: s.hostName})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			// The SAME capability gap fetchPeerSensitiveDump already refuses, and
			// it is refused here for the same reason. This used to warn and carry
			// on, which let a source get past the dump fetch and then skip the
			// sensitive half of the verification — the epoch cleared on the
			// operator lane alone, with the secret-bearing tables uncompared.
			// Since both RPCs shipped together, a source answering one and not the
			// other is an anomaly, not a version difference.
			return nil, fmt.Errorf("the source has no sensitive state digest RPC, so the " +
				"secret-bearing tables cannot be verified against it; a reseed that cannot " +
				"compare them must not clear a quarantine")
		}
		return nil, fmt.Errorf("sensitive digest from source: %w", err)
	}
	for _, t := range sens.GetTables() {
		remote[t.GetName()] = t.GetHash()
	}
	return remote, nil
}

// verifyReseedConvergence decides whether this node has converged with its
// source closely enough to earn an epoch clear. It returns the number of tables
// verified and a human-readable mismatch ("" when converged).
//
// Two axes, in this order. The SOURCE is checked first — schema version and its
// own quarantine self-report (reseedSourceCompatible) — because the digest
// comparison cannot see either: an unfit source reports fewer tables, and every
// one it omits is skipped as a benign version difference. Then the STATE, table
// by table, across the operator and sensitive lanes both.
//
// The comment this replaced claimed three axes, naming a capability-set
// comparison that was never implemented; reseedSourceCompatible says why
// comparing capability sets would be wrong rather than merely missing.
func (s *Server) verifyReseedConvergence(ctx context.Context, source string, peer pb.LiteVirtClient) (int, string, error) {
	if mismatch, err := s.checkReseedSource(ctx, source, peer); err != nil {
		return 0, "", err
	} else if mismatch != "" {
		return 0, mismatch, nil
	}
	local, err := s.reseedLocalDigests(ctx)
	if err != nil {
		return 0, "", err
	}
	remote, err := s.reseedRemoteDigests(ctx, peer)
	if err != nil {
		return 0, "", err
	}
	verified, mismatch := reseedDigestsConverged(local, remote)
	return verified, mismatch, nil
}

// reseedDigestsConverged is the convergence DECISION, split from the RPC so the
// rule that guards an epoch clear is directly testable: it decides whether a
// reseed earned the right to end a quarantine.
func reseedDigestsConverged(local []corrosion.TableDigest, remote map[string]string) (int, string) {
	verified := 0
	for _, t := range local {
		// Skip what the reseed deliberately KEPT (derived from corrosion's keep
		// set, so the two can never drift apart) plus the per-observer tables.
		if corrosion.ReseedKeepsTable(t.Name) || reseedConvergenceExempt[t.Name] {
			continue
		}
		r, ok := remote[t.Name]
		if !ok {
			// The source doesn't report a table we have. Not a mismatch by
			// itself (a peer on an older build has fewer tables) — skip rather
			// than block a reseed on a benign version difference.
			continue
		}
		if r != t.Hash {
			return 0, fmt.Sprintf("table %s still differs", t.Name)
		}
		verified++
	}
	// A comparison that compared NOTHING is not a convergence. Every rule above
	// skips rather than blocks — a kept table, an exempt one, a table the source
	// does not report — and each is right on its own, but together they have a
	// degenerate case: a source sharing no comparable table yields verified=0
	// with no mismatch, which the caller reads as success and clears the
	// quarantine on. The count was already computed and returned here; nothing
	// gated it. See TestReseedDigestsConverged_RefusesWhenNothingWasCompared.
	if verified == 0 {
		return 0, "the source reported none of the tables this reseed replaced"
	}
	return verified, ""
}

// checkReseedSource asks the source what build it is running and judges the
// answer. Ping is deliberately FRESH on each call rather than cached: the two
// callers are separated by the whole state transfer, and the second one exists
// to re-establish the fact rather than to remember it.
func (s *Server) checkReseedSource(ctx context.Context, source string, peer pb.LiteVirtClient) (string, error) {
	ping, err := peer.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return "", fmt.Errorf("ping reseed source %s: %w", source, err)
	}
	return reseedSourceCompatible(int32(corrosion.CurrentSchemaVersion), source, ping), nil
}

// reseedSourceCompatible decides whether a source is fit to end a quarantine,
// split from the RPC so the rule is directly testable — the same reason
// reseedDigestsConverged is.
//
// The digest comparison structurally cannot answer this. Every table the source
// does not report is skipped as a benign version difference, which is exactly
// the shape an older source produces: fewer tables, all of them skipped, and a
// reseed that verifies against a partial comparison and clears the epoch. So
// the source's build has to be checked directly, not inferred from what its
// digests happened to cover.
//
// Both directions are refused. A source BEHIND this binary cannot supply the
// state this node's schema expects; a source AHEAD holds rows this node cannot
// store, which the merge would silently drop and the digest comparison would
// then skip. Ping reports the BINARY constant (see Ping), which is the right
// question here: reseed is about which build generation the state comes from.
//
// Capability sets are deliberately NOT compared. Advertising is partly a
// function of local config — a token is withheld while its enforcement flag is
// off whenever a peer relies on it — so two nodes on one build can legitimately
// advertise different sets, and requiring equality would refuse reseeds that are
// perfectly safe. Schema version answers the question capabilities were being
// asked to answer, and answers it unambiguously.
//
// The quarantine self-report is the second check here, and it closes a real gap:
// pickReseedSource reads the RECORDED isolation row, while a node that has just
// detected its own rollback is quarantined before any peer has written that row.
// Its own Ping is the only thing that says so.
func reseedSourceCompatible(localSchema int32, source string, p *pb.PingResponse) string {
	if p.GetWalQuarantined() {
		return fmt.Sprintf("source %s reports itself WAL-quarantined; reseeding from it "+
			"would copy the state the compatibility regime exists to contain", source)
	}
	if got := p.GetSchemaVersion(); got != localSchema {
		return fmt.Sprintf("source %s is on schema %d, this node expects %d; a reseed across "+
			"a schema difference compares only the tables both happen to have and would "+
			"clear the quarantine on a partial comparison", source, got, localSchema)
	}
	return ""
}
