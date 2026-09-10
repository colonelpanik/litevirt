package grpcapi

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"google.golang.org/grpc"
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

// TestClaimCarriedProof_ANegativeLeaseTermIsMalformed refuses a term below zero
// at the trust boundary, PRE-LATCH.
//
// proofFromPB forwards a peer-supplied int64 straight into the database, and
// nothing validated the range: -5 marshals and unmarshals over the wire
// cleanly. nextLeaseTerm returns COALESCE(MAX(term),0)+1, so a negative term is
// not something allocation can produce — it is neither the 0 "minted without a
// term" sentinel nor a real tenure, and it has no defined behaviour in either
// enforcement arm.
//
// Refused before any capability latches, because it is not a legacy proof that
// predates stamping; it is a broken one, and accepting it would persist a value
// no reader can interpret.
func TestClaimCarriedProof_ANegativeLeaseTermIsMalformed(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // host name "host-a"

	for _, term := range []int64{-1, math.MinInt64} {
		_, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
			Id: "p-neg", Action: corrosion.ActionReschedule, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a",
			LeaseTerm: term, LeaseKey: corrosion.LeaseKeyFailover,
		}, corrosion.ActionReschedule, "vm", "vm1")
		if err == nil {
			t.Fatalf("claimed a proof carrying lease term %d; a term below zero is malformed "+
				"input and no enforcement arm defines what it means", term)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("term %d: code = %v, want InvalidArgument (malformed input, not a stale tenure)",
				term, status.Code(err))
		}
	}

	// And nothing was persisted on the way to the refusal: the row must not
	// exist at all, or a later valid proof for this id would hit the field
	// match against a term no allocation produced.
	rows, err := s.db.Query(ctx, `SELECT id FROM runtime_action_proofs WHERE id = 'p-neg'`)
	if err != nil {
		t.Fatalf("read proofs: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("a refused negative-term proof persisted %d row(s)", len(rows))
	}
}

// TestInventoryProto_OwnershipTiesRoundTrip: runtimeInventory is explicitly the
// shared local/remote struct, so a field the proto drops makes a peer with
// several ownership ties decode as a clean one — the fail-OPEN answer, for a
// latch that never re-opens.
//
// Only the local collector feeds readiness today, which is why this was latent
// rather than broken. The field's doc comment does not mark it local-only, and
// the predicate's own header calls the latch "the fleet AND", so a cross-node
// reader is the obvious next step.
func TestInventoryProto_OwnershipTiesRoundTrip(t *testing.T) {
	in := runtimeInventory{
		Host: "host-a", UnresolvedTies: 5, OwnershipTies: 3, Complete: true,
	}
	out := inventoryFromProto(inventoryToProto(in))
	if out.OwnershipTies != 3 {
		t.Errorf("OwnershipTies = %d after a proto round-trip, want 3: a peer's ownership ties "+
			"decode as zero, which reads as a clean node", out.OwnershipTies)
	}
	if out.UnresolvedTies != 5 {
		t.Errorf("UnresolvedTies = %d, want 5", out.UnresolvedTies)
	}
}

// TestClaimCarriedProof_AnUnknownLeaseKeyIsRefused: service.proto and the
// schema's v53 history block both assert, in the present tense, that "the
// executor validates it against a CLOSED SET and refuses an unknown key:
// reading a nonexistent ledger yields MAX(term) = 0, which would pass every
// proof naming it." Nothing did that; ValidLeaseKey's only non-test caller was
// the operator acknowledgement RPC.
//
// It has to be refused on RECEIPT, not at enforcement time, because the key is
// bound: the seed path persists a peer-supplied key and replicates it, so a
// forged value becomes that row's permanent authorization record fleet-wide.
func TestClaimCarriedProof_AnUnknownLeaseKeyIsRefused(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // host name "host-a"

	// A trailing space: ValidLeaseKey matches exactly and deliberately neither
	// trims nor case-folds, so this is a different key from "failover".
	for _, key := range []string{"failover ", "not_a_lease", "FAILOVER"} {
		_, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
			Id: "p-key", Action: corrosion.ActionReschedule, TargetKind: "vm",
			TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a",
			LeaseTerm: 3, LeaseKey: key,
		}, corrosion.ActionReschedule, "vm", "vm1")
		if err == nil {
			t.Fatalf("accepted a proof naming lease key %q; enforcement would read an empty "+
				"ledger for it and pass every proof naming it", key)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("key %q: code = %v, want InvalidArgument", key, status.Code(err))
		}
	}

	// The empty key stays valid: it is the "minted without a lease" form the
	// three lease-less producers emit, and refusing it would fail LB apply,
	// container relocation and automated promotion closed.
	if _, err := s.claimCarriedProof(ctx, &pb.RuntimeActionProof{
		Id: "p-nokey", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "node-a",
	}, corrosion.ActionReschedule, "vm", "vm1"); err != nil {
		t.Errorf("refused a proof carrying no lease key: %v; that is the legacy/lease-less "+
			"form and must stay acceptable", err)
	}
}

// TestProofPB_RoundTripsEveryBoundField is the test that makes a dropped
// forward impossible to add.
//
// Four sites hand-copied corrosion.ActionProof into pb.RuntimeActionProof, and
// one of them dropped a field each time the bound set grew — fence_epoch, then
// lease_key — under a comment reading "Every field claimCarriedProof binds must
// be forwarded." The executor compares a carried proof against the row it
// persisted, so the symptom is FailedPrecondition blaming replication
// divergence, on the recovery path.
func TestProofPB_RoundTripsEveryBoundField(t *testing.T) {
	full := corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: "ct1", DestHost: "host-b", Coordinator: "node-a",
		LeaseHolder: "node-a", LeaseExpiresAt: "2026-09-08T12:00:00Z",
		QuorumLive: 3, QuorumNeeded: 2, RelocationToken: "tok1",
		FenceEpoch: "7", OwnerEpoch: "4", LeaseTerm: 9,
		LeaseKey: corrosion.LeaseKeyFailover,
	}
	got := proofFromPB(proofToPB(full))
	if !corrosion.ProofBindingEqual(got, full) {
		t.Errorf("a proof does not survive proofToPB → proofFromPB:\n got %+v\nwant %+v\n"+
			"a field missing from either direction is a dropped forward, which the executor "+
			"reports as a divergent row", got, full)
	}
}

// enforcingServer is a node with lease-term enforcement fully ON: the config
// flag set, lease_term_v1 latched, quorum held, and a peer set answering the
// given high-water terms.
func enforcingServer(t *testing.T, peerTerms map[string]int64) *Server {
	t.Helper()
	s := apServer(t) // host name "host-a"
	s.SetLeaseTermEnforce(true)
	peers := make([]string, 0, len(peerTerms))
	for p := range peerTerms {
		peers = append(peers, p)
	}
	s.SetGate(fakeServerGate{
		enforcedTok: map[string]bool{capabilities.LeaseTermV1: true},
		quorum:      health.QuorumYes,
		needed:      2,
		healthy:     peers,
	})
	s.peerClientOverride = fakePeers(peerTerms)
	return s
}

// enforcingServerWithoutQuorum enforces but cannot establish quorum.
func enforcingServerWithoutQuorum(t *testing.T) *Server {
	t.Helper()
	s := apServer(t)
	s.SetLeaseTermEnforce(true)
	s.SetGate(fakeServerGate{
		enforcedTok: map[string]bool{capabilities.LeaseTermV1: true},
		quorum:      health.QuorumUnknown,
	})
	return s
}

// carriedProof builds a reschedule proof for vm `target`, destined for this
// host, minted by `coordinator` at `term` of the failover lease.
func carriedProof(id, coordinator, target string, term int64) *pb.RuntimeActionProof {
	p := &pb.RuntimeActionProof{
		Id: id, Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: target, DestHost: "host-a", Coordinator: coordinator,
		LeaseTerm: term,
	}
	if term > 0 {
		p.LeaseKey = corrosion.LeaseKeyFailover
	}
	return p
}

// refusalRecorder captures the (action, reason) pairs noteGateRefused emits, so
// a test can assert a COUNTABLE refusal reason rather than a log line.
func refusalRecorder(s *Server) func() string {
	var last string
	s.SetGateRefusedObserver(func(_, reason string) { last = reason })
	return func() string { return last }
}

// seedFailoverTerm walks the local ledger to `term` with successive lapsed
// tenures held by `holder`, using the real allocator.
func seedFailoverTerm(t *testing.T, s *Server, term int64, holder string) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	for i := int64(1); i <= term; i++ {
		if held, got, err := corrosion.AcquireLeaseWithTerm(ctx, s.db,
			corrosion.LeaseKeyFailover, holder, 30*time.Second, now); err != nil || !held || got != i {
			t.Fatalf("seed term %d: held=%v got=%d err=%v", i, held, got, err)
		}
		now = now.Add(2 * time.Minute)
	}
}

// TestClaimCarriedProof_PreLatchEnforcementIsInert. Pre-latch behaviour must be
// EXACTLY today's, or the rollout is not safe: a term-0 proof, and a proof whose
// term is far below the ledger's maximum, both still claim.
func TestClaimCarriedProof_PreLatchEnforcementIsInert(t *testing.T) {
	ctx := context.Background()
	s := apServer(t) // flag off, gate unlatched
	seedFailoverTerm(t, s, 9, "node-a")

	for i, term := range []int64{0, 1} {
		p := carriedProof(fmt.Sprintf("p%d", i), "node-b", fmt.Sprintf("vm%d", i), term)
		if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionReschedule, "vm", fmt.Sprintf("vm%d", i)); err != nil {
			t.Errorf("term %d refused pre-latch: %v — the pre-flip path must be today's exactly", term, err)
		}
	}
}

// TestClaimCarriedProof_StaleTermIsRefusedNotLogged. The refusal must be an
// error the call site sees. A dropped-and-logged stale write is
// indistinguishable from success to the caller.
func TestClaimCarriedProof_StaleTermIsRefusedNotLogged(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 9})
	lastReason := refusalRecorder(s)
	seedFailoverTerm(t, s, 9, "node-a")

	_, err := s.claimCarriedProof(ctx,
		carriedProof("p1", "node-a", "vm1", 5),
		corrosion.ActionReschedule, "vm", "vm1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition", status.Code(err), err)
	}
	if got := lastReason(); got != health.ReasonStaleLeaseTerm {
		t.Errorf("refusal reason = %q, want %q — a countable reason, not a log line",
			got, health.ReasonStaleLeaseTerm)
	}
}

// TestClaimCarriedProof_ZeroTermIsRefusedForARequiredAction: once the cluster
// enforces, a reschedule proof carrying no term is a pre-v52 proof and cannot
// be validated. 0 must never read as a valid term.
//
// Scoped to actions whose producers all hold a lease — see
// leaseTermRequiredActions. reschedule is the only one.
func TestClaimCarriedProof_ZeroTermIsRefusedForARequiredAction(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 3})
	seedFailoverTerm(t, s, 3, "node-a")

	_, err := s.claimCarriedProof(ctx,
		carriedProof("p1", "node-a", "vm1", 0),
		corrosion.ActionReschedule, "vm", "vm1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition for a term-0 reschedule proof under enforcement",
			status.Code(err))
	}
}

// TestClaimCarriedProof_AnUnstampedLeaselessProducerStillWorks is the other
// half of that scoping, and the one an unconditional refusal broke.
//
// mintLBProof, mintRelocationProof and AutoPromoteReplica hold no lease and
// mint lease_term 0 with an empty key. Refusing those under enforcement fails
// LB apply, container cold migration and restore, and automated post-fence
// replica promotion CLOSED — the DR path broken by the feature meant to
// protect it, and blamed on a stale tenure rather than an unstamped producer.
func TestClaimCarriedProof_AnUnstampedLeaselessProducerStillWorks(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 9})
	seedFailoverTerm(t, s, 9, "node-a")

	for _, tc := range []struct{ action, kind, target string }{
		{corrosion.ActionLBApply, "lb", "lb1"},
		{corrosion.ActionPromote, "vm", "vm1"},
		{corrosion.ActionRelocate, "container", "ct1"},
	} {
		p := &pb.RuntimeActionProof{
			Id: "p-" + tc.action, Action: tc.action, TargetKind: tc.kind,
			TargetName: tc.target, DestHost: "host-a", Coordinator: "host-a",
		}
		if _, err := s.claimCarriedProof(ctx, p, tc.action, tc.kind, tc.target); err != nil {
			t.Errorf("%s refused under enforcement: %v — its producer holds no lease and has no "+
				"term to stamp, so refusing it breaks the action rather than fencing anything",
				tc.action, err)
		}
	}
}

// TestClaimCarriedProof_EqualTermChecksTheRecordedHolder — BOTH directions, or
// the arm passes vacuously.
//
// Under Phase 1's keep-local merge each node retains whichever claim to a
// contested term it recorded first, so this check refuses a competing claimant
// ONCE THAT NODE HAS THE TERM ROW. It is not the whole per-executor guarantee:
// when no row has replicated it passes vacuously, and the claim's TermFence is
// what closes that case (OneExecutorWillNotActForTwoClaimants). It does not
// make the cluster agree on a winner, and no assertion here may imply that it
// does.
func TestClaimCarriedProof_EqualTermChecksTheRecordedHolder(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		coordinator string
		wantErr     bool
	}{
		{"the recorded holder claims its own term", "node-a", false},
		{"a competing claimant at the same term", "node-z", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := enforcingServer(t, map[string]int64{"node-c": 5})
			seedFailoverTerm(t, s, 5, "node-a")

			_, err := s.claimCarriedProof(ctx,
				carriedProof("p1", tc.coordinator, "vm1", 5),
				corrosion.ActionReschedule, "vm", "vm1")
			if tc.wantErr && err == nil {
				t.Error("accepted a term-5 proof from a coordinator that is not the recorded holder")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("refused the recorded holder's own term: %v", err)
			}
		})
	}
}

// TestClaimCarriedProof_AnUnseenTermIsAcceptedAboveTheThreshold — the delicate
// case, and both halves are needed.
//
// leader_lease_terms replicates independently of the direct RPC carrying a
// proof, so a fresh valid proof routinely arrives before its own term row.
// Refusing on "I have not seen that term" would break the ordinary path.
// Accepting is safe only because the threshold arm already ran: a term at or
// above the quorum-observed maximum is not stale by any definition this phase
// can enforce. A test of only the accept half passes with the threshold arm
// deleted.
func TestClaimCarriedProof_AnUnseenTermIsAcceptedAboveTheThreshold(t *testing.T) {
	ctx := context.Background()

	t.Run("unseen and at the threshold: accepted", func(t *testing.T) {
		s := enforcingServer(t, map[string]int64{"node-c": 7})
		// Local ledger has nothing at term 7 — the peer's answer set the threshold.
		if _, err := s.claimCarriedProof(ctx,
			carriedProof("p1", "node-a", "vm1", 7),
			corrosion.ActionReschedule, "vm", "vm1"); err != nil {
			t.Errorf("refused a term this node has not seen but which is AT the quorum "+
				"threshold: %v — that is the ordinary replication-lag path", err)
		}
	})

	t.Run("unseen and below the threshold: refused", func(t *testing.T) {
		s := enforcingServer(t, map[string]int64{"node-c": 7})
		if _, err := s.claimCarriedProof(ctx,
			carriedProof("p2", "node-a", "vm2", 6),
			corrosion.ActionReschedule, "vm", "vm2"); err == nil {
			t.Error("accepted an unseen term BELOW the quorum threshold; 'not found' must not " +
				"become a pass on its own")
		}
	})
}

// TestClaimCarriedProof_UnconfirmedQuorumRefusesWithItsOwnReason. An operator
// needs to tell "I was fenced" from "I could not establish whether I was
// fenced"; the first is the mechanism working, the second is degradation.
func TestClaimCarriedProof_UnconfirmedQuorumRefusesWithItsOwnReason(t *testing.T) {
	ctx := context.Background()
	s := enforcingServerWithoutQuorum(t)
	lastReason := refusalRecorder(s)
	seedFailoverTerm(t, s, 3, "node-a")

	_, err := s.claimCarriedProof(ctx,
		carriedProof("p1", "node-a", "vm1", 3),
		corrosion.ActionReschedule, "vm", "vm1")
	if err == nil {
		t.Fatal("claimed a proof without establishing quorum; failing OPEN here presents as " +
			"protection while providing none")
	}
	if got := lastReason(); got != health.ReasonLeaseTermUnconfirmed {
		t.Errorf("refusal reason = %q, want %q", got, health.ReasonLeaseTermUnconfirmed)
	}
}

// TestClaimCarriedProof_OneExecutorWillNotActForTwoClaimants is the arm that
// makes the per-executor guarantee true rather than nearly true.
//
// The equal-term holder check cannot cover this: it fires only when the term
// row has ARRIVED, and during a partition NEITHER claimant's row has
// propagated, so a holder lookup answers "not found" for both. Both proofs then
// clear the quorum threshold (each is AT the observed maximum) and both clear
// the holder arm vacuously. Nothing in the ledger distinguishes them.
//
// Note what the fixture does NOT do: it seeds no term row at all. That is the
// whole point — seeding one would make the holder arm do the work and this test
// would pass with the fence deleted.
func TestClaimCarriedProof_OneExecutorWillNotActForTwoClaimants(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 7})
	lastReason := refusalRecorder(s)

	// node-a's proof at term 7 arrives first and is claimed.
	if _, err := s.claimCarriedProof(ctx,
		carriedProof("p-a", "node-a", "vm1", 7),
		corrosion.ActionReschedule, "vm", "vm1"); err != nil {
		t.Fatalf("first claimant at an unseen term refused: %v — that is the ordinary "+
			"replication-lag path and must still work", err)
	}

	// node-z computed the SAME term 7 on the other side of the partition.
	_, err := s.claimCarriedProof(ctx,
		carriedProof("p-z", "node-z", "vm2", 7),
		corrosion.ActionReschedule, "vm", "vm2")
	if err == nil {
		t.Fatal("one executor acted for BOTH claimants of term 7; the quorum threshold cannot " +
			"separate them (both are at the maximum) and no term row had replicated, so the " +
			"claim itself must carry the binding")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if got := lastReason(); got != health.ReasonStaleLeaseTerm {
		t.Errorf("refusal reason = %q, want %q", got, health.ReasonStaleLeaseTerm)
	}
}

// TestClaimCarriedProof_TheSameClaimantMayActRepeatedly is the other half. The
// fence binds an executor to one CLAIMANT, not to one action: a coordinator
// failing over forty VMs mints forty proofs at one term and every one must
// claim. A fence that compared only the term would fail closed on VM two.
func TestClaimCarriedProof_TheSameClaimantMayActRepeatedly(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 7})

	for i, vm := range []string{"vm1", "vm2", "vm3"} {
		if _, err := s.claimCarriedProof(ctx,
			carriedProof(fmt.Sprintf("p%d", i), "node-a", vm, 7),
			corrosion.ActionReschedule, "vm", vm); err != nil {
			t.Fatalf("%s refused for the SAME coordinator at term 7: %v — the fence binds a "+
				"claimant, not a single action", vm, err)
		}
	}
}

// perKeyPeer answers a DIFFERENT high water per lease key, which is what makes
// the ledger-redirection hazard reproducible: the three ledgers advance
// independently, so a cluster busy with failovers and idle on rebalancing has a
// high failover water and a rebalancer water of 0.
type perKeyPeer struct {
	pb.LiteVirtClient
	terms map[string]int64 // lease key → newest term this peer has seen
}

func (f *perKeyPeer) GetLeaseTermHighWater(_ context.Context, req *pb.GetLeaseTermHighWaterRequest, _ ...grpc.CallOption) (*pb.GetLeaseTermHighWaterResponse, error) {
	k := req.GetKey()
	return &pb.GetLeaseTermHighWaterResponse{Key: k, Term: f.terms[k], Holder: "node-x"}, nil
}

// enforcingServerPerKey is enforcingServer with per-key peer answers.
func enforcingServerPerKey(t *testing.T, peers []string, perKey map[string]int64) *Server {
	t.Helper()
	s := apServer(t)
	s.SetLeaseTermEnforce(true)
	s.SetGate(fakeServerGate{
		enforcedTok: map[string]bool{capabilities.LeaseTermV1: true},
		quorum:      health.QuorumYes,
		needed:      2,
		healthy:     peers,
	})
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		for _, p := range peers {
			if p == host {
				return &perKeyPeer{terms: perKey}, func() {}, nil
			}
		}
		return nil, nil, context.DeadlineExceeded
	}
	return s
}

// TestClaimCarriedProof_RefusesALeaseKeyNoProducerHolds closes the redirection
// that membership-only validation left open.
//
// ValidLeaseKey answers "is this one of the three leases", and the receipt check
// used to stop there. But the key SELECTS the ledger the threshold is computed
// from, and the three ledgers advance independently — so naming a quieter one
// moves the bar. Here the quorum answers term 7 for failover while the named
// rebalancer ledger is untouched at 0, which is exactly the shape that made the
// term check a formality: a proof at term 1 would clear a 0 high-water.
//
// Nothing in the tree produces such a proof — all three stamp sites are
// failover — so refusing it costs no real path.
func TestClaimCarriedProof_RefusesALeaseKeyNoProducerHolds(t *testing.T) {
	ctx := context.Background()
	// Failover is busy at term 7; the other two ledgers have never elected, so
	// their quorum-observed water is 0. Judged against those, ANY term clears.
	s := enforcingServerPerKey(t, []string{"node-c"}, map[string]int64{
		corrosion.LeaseKeyFailover: 7,
	})

	for _, key := range []string{corrosion.LeaseKeyRebalancer, corrosion.LeaseKeyDualRun} {
		p := carriedProof("p-"+key, "node-z", "vm-"+key, 1)
		p.LeaseKey = key
		_, err := s.claimCarriedProof(ctx, p, corrosion.ActionReschedule, "vm", "vm-"+key)
		if err == nil {
			t.Errorf("a proof naming %q at term 1 was accepted while the failover quorum stood "+
				"at 7; the term threshold can be moved by choosing which ledger to be judged "+
				"against, which makes enforcement a formality", key)
			continue
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("key %q: code = %v, want InvalidArgument — this is a malformed proof, not "+
				"a stale one, and it must not be counted as a lease-term refusal", key, status.Code(err))
		}
	}
}

// TestClaimCarriedProof_AcceptsTheKeyItsProducerHolds is the other half: the
// narrowing must not refuse the one key that IS produced.
func TestClaimCarriedProof_AcceptsTheKeyItsProducerHolds(t *testing.T) {
	ctx := context.Background()
	s := enforcingServer(t, map[string]int64{"node-c": 7})

	p := carriedProof("p-failover", "node-a", "vm1", 7)
	p.LeaseKey = corrosion.LeaseKeyFailover
	if _, err := s.claimCarriedProof(ctx, p, corrosion.ActionReschedule, "vm", "vm1"); err != nil {
		t.Fatalf("the coordinator's own key was refused: %v", err)
	}
}

// TestLeaseTermGateForPendingProof_RefusesARowWhoseKeyNoProducerHolds: the
// narrowing has to hold at the boundary VM RESCHEDULE crosses, which is not the
// one a carried proof crosses.
//
// A reschedule proof never travels over an RPC. The coordinator writes the row,
// internal/health's reconciler picks it up off replication and calls in through
// LeaseTermGateForPendingProof, and the ROW is therefore the authorization
// record. A check placed only in claimCarriedProof runs on every proof path
// except the one this phase exists for — and a row can carry a key this node's
// receipt check never saw, because a peer still on a pre-narrowing binary seeds
// one from a proof it accepted and it replicates from there.
//
// So this test starts from a persisted ProofRecord, not from a carried proto.
// The rebalancer ledger is left untouched at 0 while failover sits at 7: if the
// key were merely checked for membership, term 1 would clear a threshold of 0
// and the gate would return a fence.
func TestLeaseTermGateForPendingProof_RefusesARowWhoseKeyNoProducerHolds(t *testing.T) {
	ctx := context.Background()
	s := enforcingServerPerKey(t, []string{"node-b", "node-c"}, map[string]int64{
		corrosion.LeaseKeyFailover: 7,
	})

	pr := corrosion.ProofRecord{
		ActionProof: corrosion.ActionProof{
			ID: "p-row", Action: corrosion.ActionReschedule,
			TargetKind: "vm", TargetName: "vm1",
			DestHost: s.hostName, Coordinator: "node-a",
			LeaseTerm: 1, LeaseKey: corrosion.LeaseKeyRebalancer,
		},
		Status: corrosion.ProofPrepared,
	}

	fence, reason, err := s.LeaseTermGateForPendingProof(ctx, pr)
	if err == nil {
		t.Fatalf("a persisted row naming the rebalancer lease was judged and admitted "+
			"(fence=%+v): the reschedule boundary reads the ROW, so a key no producer "+
			"holds selects an idle ledger whose high-water is 0 and every term clears it", fence)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition: %v", got, err)
	}
	if reason == "" {
		t.Error("refusal returned no countable reason, so the reconciler cannot record it")
	}
}
