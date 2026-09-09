package grpcapi

import (
	"context"
	"errors"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// proofFromPB converts a carried RuntimeActionProof into a corrosion.ActionProof.
func proofFromPB(p *pb.RuntimeActionProof) corrosion.ActionProof {
	return corrosion.ActionProof{
		ID: p.GetId(), Action: p.GetAction(), TargetKind: p.GetTargetKind(),
		TargetName: p.GetTargetName(), DestHost: p.GetDestHost(), Coordinator: p.GetCoordinator(),
		LeaseHolder: p.GetLeaseHolder(), LeaseExpiresAt: p.GetLeaseExpiresAt(),
		QuorumLive: int(p.GetQuorumLive()), QuorumNeeded: int(p.GetQuorumNeeded()),
		RelocationToken: p.GetRelocationToken(), FenceEpoch: p.GetFenceEpoch(),
		OwnerEpoch: p.GetOwnerEpoch(), LeaseTerm: p.GetLeaseTerm(),
		LeaseKey: p.GetLeaseKey(),
	}
}

// claimCarriedProof validates a coordinator-minted proof carried in a direct-RPC
// request and claims it single-use on THIS host. It (1) validates the
// coordinator's assertions — exact action/target and dest_host == this host — so
// a mismatched/forged proof can't authorize a different action; (2) upserts the
// FULL proof locally (INSERT OR IGNORE — the coordinator's replicated row, if it
// arrived, wins; otherwise the carried fields seed it, with no dependence on
// replication); (3) claims it (single-holder). A terminal/held proof → refuse
// (no double-execution). Returns (id, nil) so the caller can complete/fail it.
func (s *Server) claimCarriedProof(ctx context.Context, p *pb.RuntimeActionProof, action, targetKind, targetName string) (string, error) {
	if p == nil {
		return "", nil // no proof carried — caller proceeds ungated (legacy, pre-flip)
	}
	if p.GetId() == "" {
		// A carried-but-empty proof is malformed and must FAIL CLOSED, never be treated as
		// legacy. Enforced call sites gate "proof missing" on req.Proof == nil, so a non-nil
		// empty-id proof would otherwise slip past that branch AND skip the single-use
		// lifecycle here — letting an mTLS peer drive the action through the execution gate
		// with no durable coordinator proof at all. Only a truly absent (nil) proof is legacy.
		return "", status.Error(codes.FailedPrecondition, "runtime-action proof carried with an empty id — refusing (a non-nil proof must be valid)")
	}
	if p.GetAction() != action || p.GetTargetKind() != targetKind ||
		p.GetTargetName() != targetName || p.GetDestHost() != s.hostName {
		return "", status.Errorf(codes.FailedPrecondition,
			"runtime-action proof %s does not authorize %s of %s/%s on %s (proof: %s of %s/%s on %s)",
			p.GetId(), action, targetKind, targetName, s.hostName,
			p.GetAction(), p.GetTargetKind(), p.GetTargetName(), p.GetDestHost())
	}
	// A NEGATIVE lease term is malformed input, refused here and not only where
	// enforcement compares terms.
	//
	// proofFromPB forwards a peer-supplied int64 straight into the DB, and
	// -5 marshals and unmarshals over the wire cleanly. nextLeaseTerm returns
	// COALESCE(MAX(term),0)+1, which is >= 1, so a term below zero is not
	// something allocation can produce: it is neither the 0 "minted without a
	// term" sentinel nor a real tenure, and it has no defined behaviour in
	// either enforcement arm. Contrast OwnerEpoch, which is parsed and compared
	// against the live row a few lines below.
	//
	// Refused PRE-LATCH, unlike the term comparison, because this is not a
	// legacy proof that predates stamping — it is a broken one, and accepting
	// it until a capability latches would persist a value no reader can
	// interpret. (The post-latch `term <= 0` refusal belongs to Task 6, which
	// also decides which actions it applies to.)
	if p.GetLeaseTerm() < 0 {
		return "", status.Errorf(codes.InvalidArgument,
			"runtime-action proof %s carries lease term %d; a lease term is never negative "+
				"(allocation starts at 1, and 0 means the proof was minted without one)",
			p.GetId(), p.GetLeaseTerm())
	}
	// Seed the row from the carried proof AND check it against any row already
	// present, in ONE guarded transaction.
	//
	// The order matters and used to be wrong. Seeding first with WriteActionProof
	// and comparing afterwards refused a divergent proof correctly HERE, but the
	// presented statement was already committed to mutation_log and queued for
	// every peer by then — the log records the whole batch, not only statements
	// that changed a row, so an INSERT OR IGNORE that is a local no-op still
	// relays. A peer lacking the coordinator's genuine row would apply the
	// forged one and then drop the real row on the primary key.
	//
	// The field set compared is proofBindingEqual's, shared with the writer, so
	// the two cannot disagree about which fields authorize an action. It covers
	// action/target/dest/coordinator, relocation_token (a container relocation's
	// binding key — claiming the token-A ledger row while stamping token B would
	// diverge proof from provenance), fence_epoch, owner_epoch, lease_term and
	// lease_key.
	if err := corrosion.WriteActionProofValidated(ctx, s.db, proofFromPB(p)); err != nil {
		if errors.Is(err, corrosion.ErrProofDiverges) {
			return "", status.Errorf(codes.FailedPrecondition,
				"persisted proof %s does not match the carried proof (divergent/seeded row)", p.GetId())
		}
		return "", status.Errorf(codes.Unavailable, "persist proof %s: %v", p.GetId(), err)
	}
	// VM proofs additionally bind to the current workload ownership generation.
	// A valid prepared row can outlive an A→B→A ownership cycle; without this
	// comparison it could authorize a later promotion after its decision context
	// was superseded. Container restore has no target row yet, so its executor-side
	// generation check lives on the token-bound relocate-recreate path.
	if targetKind == "vm" && p.GetOwnerEpoch() != "" {
		vm, err := corrosion.GetVM(ctx, s.db, targetName)
		if err != nil {
			return "", status.Errorf(codes.Unavailable, "read %s owner epoch for proof %s: %v", targetName, p.GetId(), err)
		}
		if vm == nil || p.GetOwnerEpoch() != strconv.FormatInt(vm.OwnerEpoch, 10) {
			return "", status.Errorf(codes.FailedPrecondition,
				"runtime-action proof %s is stale for %s owner epoch", p.GetId(), targetName)
		}
	}
	if err := corrosion.ClaimActionProof(ctx, s.db, p.GetId(), s.hostName); err != nil {
		if errors.Is(err, corrosion.ErrProofSpent) {
			return "", status.Errorf(codes.FailedPrecondition,
				"proof %s already terminal/held — refusing to re-run %s of %s", p.GetId(), action, targetName)
		}
		return "", status.Errorf(codes.Unavailable, "claim proof %s: %v", p.GetId(), err)
	}
	return p.GetId(), nil
}
