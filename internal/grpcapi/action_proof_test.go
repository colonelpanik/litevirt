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

	t.Run("divergent owner_epoch on same-id persisted row refuses", func(t *testing.T) {
		s := apServer(t)
		if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{
			ID: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: "ct1", DestHost: "host-a", Coordinator: "coord",
			RelocationToken: "tokenA", OwnerEpoch: "6",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: "ct1", DestHost: "host-a", Coordinator: "coord",
			RelocationToken: "tokenA", OwnerEpoch: "7",
		}
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionRelocate, "container", "ct1"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("divergent owner_epoch must refuse; got %v", status.Code(err))
		}
		if pr, ok, _ := corrosion.GetActionProof(ctx, s.db, "p1"); !ok || pr.Status != corrosion.ProofPrepared {
			t.Fatalf("epoch-6 row must remain unclaimed under epoch-7 carried proof: %+v", pr)
		}
	})

	t.Run("stale VM owner_epoch refuses before claim", func(t *testing.T) {
		s := apServer(t)
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "vm1", HostName: "old-owner", Spec: "{}", State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
			t.Fatalf("seed owner epoch: %v", err)
		}
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a", Coordinator: "coord", OwnerEpoch: "6",
		}
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("proof for owner epoch 6 must not authorize epoch 7; got %v", status.Code(err))
		}
		if pr, ok, _ := corrosion.GetActionProof(ctx, s.db, "p1"); !ok || pr.Status != corrosion.ProofPrepared {
			t.Fatalf("stale proof must remain prepared/unclaimed: %+v", pr)
		}
	})

	t.Run("current VM owner_epoch claims", func(t *testing.T) {
		s := apServer(t)
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "vm1", HostName: "old-owner", Spec: "{}", State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
			t.Fatalf("seed owner epoch: %v", err)
		}
		p := &pb.RuntimeActionProof{
			Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a", Coordinator: "coord", OwnerEpoch: "7",
		}
		if id, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err != nil || id != "p1" {
			t.Fatalf("matching epoch claim: id=%q err=%v; want p1/nil", id, err)
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

// TestClaimCarriedProof_DivergentLeaseTermIsRefused: WriteActionProof is
// INSERT OR IGNORE, so a row with this id may already exist (replicated, or
// seeded by a peer). claimCarriedProof re-reads it and requires an exact match
// on the authorization-bearing fields before claiming.
//
// lease_term MUST be in that list. Omit it and a divergent same-id row carrying
// a DIFFERENT term is claimed under a matching carried proof — the term becomes
// unauthenticated, which defeats the entire column: an attacker (or a confused
// peer) supplies the term it wants enforced against.
func TestClaimCarriedProof_DivergentLeaseTermIsRefused(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // host name "host-a"

	// A row already present locally at term 3.
	if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a", LeaseTerm: 3,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A carried proof with the SAME id and every other field identical, but term 9.
	_, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
		Id: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a", LeaseTerm: 9,
	}, corrosion.ActionReschedule, "vm", "vm1")
	if err == nil {
		t.Fatal("claimed a proof whose persisted lease_term (3) differs from the carried one (9); " +
			"the term must be part of the persisted-row field match or it is unauthenticated")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

// TestClaimCarriedProof_SeedsTheCarriedLeaseTerm is the other half of the term
// binding, and the arm that DivergentLeaseTermIsRefused cannot reach.
//
// When no row exists yet — the normal case, because the coordinator's replicated
// row routinely arrives after the direct RPC that carries the proof — the carried
// fields SEED it. So proofFromPB must forward the term. Drop it there and the
// seed lands at 0 while the carried proof says 5; the field match immediately
// below then refuses a perfectly valid proof, and every proof-gated action fails
// closed the moment the coordinator starts stamping terms.
//
// DivergentLeaseTermIsRefused cannot catch that: it seeds the row itself, so the
// persisted term never comes from proofFromPB at all and the INSERT OR IGNORE is
// a no-op. Both arms are needed — one proves a wrong term is refused, this one
// proves a right term survives the round trip through the seed path.
func TestClaimCarriedProof_SeedsTheCarriedLeaseTerm(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // host name "host-a"

	id, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
		Id: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a", LeaseTerm: 5,
	}, corrosion.ActionReschedule, "vm", "vm1")
	if err != nil || id != "p1" {
		t.Fatalf("claim of a valid term-5 proof: id=%q err=%v; the carried term must reach "+
			"the seeded row, or the field match refuses the proof that just created it", id, err)
	}

	pr, ok, err := corrosion.GetActionProof(ctx, s.db, "p1")
	if err != nil || !ok {
		t.Fatalf("read seeded proof: ok=%v err=%v", ok, err)
	}
	if pr.LeaseTerm != 5 {
		t.Errorf("seeded lease_term = %d, want 5 — a proof persisted without its term is "+
			"unenforceable: the executor would read 0 and treat it as pre-term", pr.LeaseTerm)
	}
}

// TestClaimCarriedProof_ADivergentProofIsNotRelayedToPeers is the end-to-end
// form of the ordering fix: the refusal was always correct, what was wrong was
// that the forged statement had already been queued for replication by the time
// it happened.
//
// Asserting on the refusal alone cannot catch this — the old code refused too.
// The assertion has to be on what a peer would be sent.
func TestClaimCarriedProof_ADivergentProofIsNotRelayedToPeers(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // host name "host-a"

	if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a", LeaseTerm: 3,
	}); err != nil {
		t.Fatalf("seed genuine: %v", err)
	}
	rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	before := rows[0].Int("n")

	_, err = s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
		Id: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a", LeaseTerm: 9,
	}, corrosion.ActionReschedule, "vm", "vm1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition", status.Code(err), err)
	}

	rows, err = s.db.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	if after := rows[0].Int("n"); after != before {
		t.Errorf("the refused proof queued %d statement(s) for peers; the term it carries would "+
			"become the permanent record on any peer that has not yet received the genuine row",
			after-before)
	}
}
