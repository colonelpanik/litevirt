package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lease-term RPCs.

// GetLeaseTermHighWater reports this node's newest live lease term for key,
// with the holder that claimed it.
//
// Read-only and side-effect free. It must NOT consult the barrier,
// gate.Enforced or any peer: it IS the barrier's input, and fanning out from
// here would turn one executor's barrier into a cluster-wide storm.
//
// Three answers, and the difference between the last two is the whole reason
// the barrier exists:
//
//   - term > 0 with a holder — this node has seen that tenure.
//   - term 0 — nothing recorded for this key. A REAL answer that counts toward
//     quorum; a fresh cluster is all zeroes and must still be able to establish
//     a threshold.
//   - Unavailable — this node cannot read its ledger. It does not know, and
//     reporting that as 0 would let a threshold be computed from nodes that
//     never answered.
//
// The key is validated against the closed set that corrosion owns. Not a
// package-local list here: the answer selects which ledger a fencing decision
// consults, so a caller must not get to choose, and the key reaches a metric
// label where unbounded peer-supplied input is what the repo's bounded-label
// discipline exists to prevent. All three real leases are answerable — a
// handler that knew only the failover key would answer 0 for a rebalancer
// proof, and 0 means "no term recorded", so the barrier would read a live
// tenure as absent.
func (s *Server) GetLeaseTermHighWater(ctx context.Context, req *pb.GetLeaseTermHighWaterRequest) (*pb.GetLeaseTermHighWaterResponse, error) {
	if err := s.requirePeerOrRole(ctx, "operator"); err != nil {
		return nil, err
	}
	key := req.GetKey()
	if !corrosion.ValidLeaseKey(key) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown lease key %q", key)
	}
	term, err := corrosion.CurrentLeaseTerm(ctx, s.db, key)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read lease term for %q: %v", key, err)
	}
	var holder string
	if term > 0 {
		// found == false is not an error here: the term row could have been
		// tombstoned between the two reads, and the caller's threshold only
		// needs the term. err is read FIRST, per LeaseTermHolder's contract —
		// its ("", false, err) is indistinguishable from a genuinely unseen
		// term.
		h, found, herr := corrosion.LeaseTermHolder(ctx, s.db, key, term)
		if herr != nil {
			return nil, status.Errorf(codes.Unavailable, "read lease term holder for %q: %v", key, herr)
		}
		if found {
			holder = h
		}
	}
	return &pb.GetLeaseTermHighWaterResponse{Key: key, Term: term, Holder: holder}, nil
}

// AcknowledgeLeaseTermTie clears a contested lease term from THIS node's
// unresolved-tie register, on the operator's statement that they have seen it.
//
// Why this needs to exist at all: leader_lease_terms rows are immutable, so the
// tie the merge raises has no remediating write to wait for and never clears.
// The register, the state digest and the ha.lww.unresolved health condition
// therefore stay dirty for as long as the two rows disagree — which is forever —
// and a daemon restart is not a way out either: the register is in-memory, so a
// restart empties it and the next anti-entropy sweep re-registers the same tie
// within seconds.
//
// It clears EVIDENCE TRACKING, not the conflict. Both claims stay in the ledger,
// and this handler writes an audit row naming the principal, the key and the
// term — the durable record that replaces the in-memory one. Nothing here picks
// a winner: no node knows which claim was legitimate, and Phase 2 must never
// imply that it does.
//
// Node-local and NOT peer-callable. The register belongs to one node, so an
// operator acknowledges on each host the health condition names; and a node
// must never be able to acknowledge its own contest, which is exactly what a
// peer-callable path would allow.
//
// Gated on cluster.lww.acknowledge, a verb that grants this and nothing else.
// It was cluster.update, which no builtin role below Admin holds — so the
// doc above was false on any RBAC cluster: the operator the condition tells
// to acknowledge got PermissionDenied. Widening cluster.update instead would
// have pre-granted Operator every cluster verb added after this one.
func (s *Server) AcknowledgeLeaseTermTie(ctx context.Context, req *pb.AcknowledgeLeaseTermTieRequest) (*pb.AcknowledgeLeaseTermTieResponse, error) {
	if err := s.RequirePerm(ctx, "/", "cluster.lww.acknowledge", "operator"); err != nil {
		return nil, err
	}
	key := req.GetKey()
	if !corrosion.ValidLeaseKey(key) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown lease key %q", key)
	}
	if req.GetTerm() <= 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"term %d is not a real lease term (allocation starts at 1)", req.GetTerm())
	}

	// The principal is recorded in the durable row as well as the audit log: the
	// audit chain answers "who acknowledged this", and the acknowledgement row
	// answers "why is this tie suppressed on this node" without a log search.
	acked, err := s.db.AcknowledgeLeaseTermTie(ctx, key, req.GetTerm(), callerUsername(ctx))
	if err != nil {
		// The acknowledgement could not be made durable, so it was not made at
		// all. Reporting success here would hand the operator a suppression that
		// silently returns on the next restart.
		return nil, status.Errorf(codes.Unavailable,
			"could not record the acknowledgement of %s term %d: %v", key, req.GetTerm(), err)
	}
	// Audited whenever this node holds an acknowledgement — the one just made,
	// or one made by an earlier call — and NOT only when this call cleared
	// something.
	//
	// The narrower version audited on acked alone, to keep one operator
	// decision from producing two records. That made a missing record
	// permanent: the suppression is durable the moment AcknowledgeLeaseTermTie
	// returns, the audit insert happens afterwards and only warns when it
	// fails (auditAs), and a retry then finds no tracked tie, answers false and
	// audited nothing. A crash in that gap left a silenced conflict with
	// nothing in the audit chain saying anyone had looked at it, and no command
	// an operator could run to repair it.
	//
	// So the trade is inverted deliberately: a retry may add a second row
	// naming one decision, which is noise an auditor can read past, whereas a
	// missing row is not recoverable at all. The detail text says which case
	// produced it.
	if reaffirmed := !acked && s.db.LeaseTermTieAcknowledged(key, req.GetTerm()); acked || reaffirmed {
		detail := fmt.Sprintf("acknowledged a contested lease term on %s; both claims remain in the ledger", s.hostName)
		if reaffirmed {
			detail = fmt.Sprintf("reaffirmed an existing acknowledgement of a contested lease term on %s; "+
				"nothing was cleared by this call", s.hostName)
		}
		s.audit(ctx, "cluster.lease_term_tie.acknowledge",
			fmt.Sprintf("%s:%d", key, req.GetTerm()), detail, "ok")
	}
	if acked {
		// The inventory feeds readiness and the digest, and both read the tie
		// counts. Without this the node reports the stale count until the cache
		// expires, so an operator's acknowledgement appears not to have worked.
		// Only when something changed: a reaffirmation moved nothing.
		s.invalidateInventoryCache()
	}
	return &pb.AcknowledgeLeaseTermTieResponse{Acknowledged: acked}, nil
}
