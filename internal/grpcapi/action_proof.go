package grpcapi

import (
	"context"
	"errors"

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
		RelocationToken: p.GetRelocationToken(),
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
	if err := corrosion.WriteActionProof(ctx, s.db, proofFromPB(p)); err != nil {
		return "", status.Errorf(codes.Unavailable, "persist proof %s: %v", p.GetId(), err)
	}
	// WriteActionProof is INSERT OR IGNORE: if a row with this id already existed
	// (replicated, or seeded), re-read it and require it to EXACTLY match the carried
	// proof's action/target/dest/coordinator AND relocation_token before claiming — a
	// divergent persisted row must never be claimed under a mismatched carried proof.
	// relocation_token is part of the binding: for a container relocation the caller
	// verified carried-token == the token that will be STAMPED, so a persisted row whose
	// token differs (a divergent same-id seed) must refuse — otherwise we'd claim the
	// token-A ledger row while stamping token B, diverging proof from provenance.
	if pr, ok, err := corrosion.GetActionProof(ctx, s.db, p.GetId()); err != nil {
		return "", status.Errorf(codes.Unavailable, "read proof %s: %v", p.GetId(), err)
	} else if !ok || pr.Action != p.GetAction() || pr.TargetKind != p.GetTargetKind() ||
		pr.TargetName != p.GetTargetName() || pr.DestHost != p.GetDestHost() ||
		pr.Coordinator != p.GetCoordinator() || pr.RelocationToken != p.GetRelocationToken() {
		return "", status.Errorf(codes.FailedPrecondition,
			"persisted proof %s does not match the carried proof (divergent/seeded row)", p.GetId())
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
