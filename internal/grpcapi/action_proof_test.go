package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func apServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "host-a"}
}

func TestClaimCarriedProof(t *testing.T) {
	ctx := context.Background()

	t.Run("nil proof is a no-op (unenforced)", func(t *testing.T) {
		s := apServer(t)
		id, err := s.claimCarriedProof(ctx, nil, corrosion.ActionPromote, "vm", "vm1")
		if err != nil || id != "" {
			t.Fatalf("nil proof: id=%q err=%v; want ''/nil", id, err)
		}
	})

	t.Run("non-nil empty-id proof fails closed (not legacy)", func(t *testing.T) {
		s := apServer(t)
		// A carried-but-empty proof must NOT be treated as legacy: call sites gate
		// "proof missing" on req.Proof == nil, so a non-nil empty proof would slip past
		// that AND skip the single-use claim — driving the action ungated.
		if _, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{}, corrosion.ActionPromote, "vm", "vm1"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("empty-id proof: got %v; want FailedPrecondition (fail closed)", status.Code(err))
		}
	})

	t.Run("matching proof validates + claims", func(t *testing.T) {
		s := apServer(t)
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a", Coordinator: "coord",
		}
		id, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1")
		if err != nil || id != "p1" {
			t.Fatalf("match: id=%q err=%v; want p1/nil", id, err)
		}
		pr, ok, _ := corrosion.GetActionProof(ctx, s.db, "p1")
		if !ok || pr.Status != corrosion.ProofInProgress || pr.ExecutorHost != "host-a" {
			t.Fatalf("proof after claim = %+v; want in_progress/host-a", pr)
		}
	})

	t.Run("divergent relocation_token on same-id persisted row refuses", func(t *testing.T) {
		s := apServer(t)
		// A persisted proof row (seeded / replicated) bound to relocation token A.
		if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{
			ID: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: "ct1", DestHost: "host-a", Coordinator: "coord", RelocationToken: "tokenA",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		// A carried proof with the SAME id, everything matching EXCEPT the relocation
		// token (token B). It must refuse — otherwise we'd claim the token-A ledger row
		// while a token-B container row gets stamped, diverging proof from provenance.
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: "ct1", DestHost: "host-a", Coordinator: "coord", RelocationToken: "tokenB",
		}
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionRelocate, "container", "ct1"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("divergent relocation_token must refuse; got %v", status.Code(err))
		}
		// The seeded token-A row must NOT have been claimed.
		if pr, ok, _ := corrosion.GetActionProof(ctx, s.db, "p1"); !ok || pr.Status == corrosion.ProofInProgress {
			t.Fatalf("token-A row must not be claimed under a token-B carried proof: %+v", pr)
		}
	})

	t.Run("wrong dest_host refuses", func(t *testing.T) {
		s := apServer(t)
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-b", // not us
		}
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err == nil {
			t.Fatal("a proof destined for host-b must not be claimable on host-a")
		}
	})

	t.Run("wrong target refuses", func(t *testing.T) {
		s := apServer(t)
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "other", DestHost: "host-a",
		}
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err == nil {
			t.Fatal("a proof for another VM must not authorize vm1")
		}
	})

	t.Run("terminal proof refuses (single-use)", func(t *testing.T) {
		s := apServer(t)
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a",
		}
		// First claim + complete.
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err != nil {
			t.Fatalf("first claim: %v", err)
		}
		if err := corrosion.CompleteActionProof(ctx, s.db, "p1", "host-a"); err != nil {
			t.Fatalf("complete: %v", err)
		}
		// A duplicate/replayed request with the same proof must be refused.
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err == nil {
			t.Fatal("a terminal proof must not be re-claimable (single-use)")
		}
	})
}

// Enforced direct-RPC regression: a peer driving ApplyLB with a non-nil empty-id proof
// must be REFUSED (claimCarriedProof rejects it before the execution gate), not slip
// through as legacy.
func TestApplyLB_EmptyProofFailsClosed(t *testing.T) {
	s := newPeerAuthServer(t) // hostName "self", knows peer "peer-1"
	_, err := s.ApplyLB(mtlsCtx("peer-1"), &pb.ApplyLBRequest{
		LbName: "x", Vip: "10.0.0.1/24", Proof: &pb.RuntimeActionProof{}, // non-nil, empty id
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ApplyLB with a non-nil empty-id proof must fail closed; got %v, want FailedPrecondition", status.Code(err))
	}
}
