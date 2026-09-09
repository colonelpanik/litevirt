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

	acked := s.db.AcknowledgeLeaseTermTie(key, req.GetTerm())
	if acked {
		// Audited only when something was actually cleared, so a retry does not
		// produce a second record of one operator decision.
		s.audit(ctx, "cluster.lease_term_tie.acknowledge",
			fmt.Sprintf("%s:%d", key, req.GetTerm()),
			fmt.Sprintf("acknowledged a contested lease term on %s; both claims remain in the ledger", s.hostName),
			"ok")
		// The inventory feeds readiness and the digest, and both read the tie
		// counts. Without this the node reports the stale count until the cache
		// expires, so an operator's acknowledgement appears not to have worked.
		s.invalidateInventoryCache()
	}
	return &pb.AcknowledgeLeaseTermTieResponse{Acknowledged: acked}, nil
}
