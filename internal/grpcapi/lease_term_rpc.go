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
func (s *Server) AcknowledgeLeaseTermTie(ctx context.Context, req *pb.AcknowledgeLeaseTermTieRequest) (*pb.AcknowledgeLeaseTermTieResponse, error) {
	if err := s.RequirePerm(ctx, "/", "cluster.update", "operator"); err != nil {
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
