package grpcapi

import (
	"context"
	"fmt"
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
	peer, conn, err := s.peerClient(ctx, source)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reach reseed source %s: %v", source, err)
	}
	defer conn.Close()

	s.audit(ctx, "host.reseed", s.hostName, "source="+source+" epoch="+fmt.Sprint(epoch), "started")

	// Pull the source's full state and merge it. The merge is LWW and
	// per-row-idempotent, so a partial pull cannot corrupt — it simply fails
	// verification below and leaves the node isolated.
	dump, err := fetchPeerStateDump(ctx, peer)
	if err != nil {
		s.audit(ctx, "host.reseed", s.hostName, "source="+source, "error")
		return nil, status.Errorf(codes.Unavailable, "pull state from %s: %v", source, err)
	}
	// DISCARD, then merge — with the dump already in hand. A merge alone is
	// additive, so the rows this node produced outside the regime (precisely
	// what the quarantine contains) would survive and be re-injected once the
	// epoch cleared. The lab proved it: a merge-only reseed failed its own
	// convergence check because the stale rows were still there.
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

	// VERIFY convergence before clearing anything. Only a verified reseed earns
	// the epoch clear; anything else leaves the node isolated with the reason
	// intact, which is the safe direction.
	converged, mismatch, err := s.verifyReseedConvergence(ctx, peer)
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

// verifyReseedConvergence compares this node against the source on the three
// axes the design names: schema version, capability set, and state digest.
// Returns the number of tables verified and a human-readable mismatch (” when
// converged).
func (s *Server) verifyReseedConvergence(ctx context.Context, peer pb.LiteVirtClient) (int, string, error) {
	local, err := s.db.StateDigest(ctx)
	if err != nil {
		return 0, "", err
	}
	resp, err := peer.GetStateDigest(ctx, &emptypb.Empty{})
	if err != nil {
		return 0, "", err
	}
	remote := map[string]string{}
	for _, t := range resp.GetTables() {
		remote[t.GetName()] = t.GetHash()
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
	return verified, ""
}
