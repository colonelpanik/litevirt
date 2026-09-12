package grpcapi

import (
	"context"
	"errors"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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

// proofToPB is proofFromPB's inverse, for a caller forwarding a proof it read
// out of the database to the host that will execute it.
//
// It exists because every such site used to hand-copy the field list, and one
// of them dropped a field every time the bound set grew: fence_epoch once, then
// lease_key. The executor compares the carried proof against the row it has
// PERSISTED, so a dropped field reads as a divergent row and refuses the action
// with an error blaming replication divergence — on the recovery path, for a
// field that was simply not copied. Forward a proof through this function and
// the compiler carries new fields for you.
//
// The lifecycle fields (status, holder, timestamps) are deliberately absent:
// they are the executor's to set, are not part of ProofBindingEqual, and a
// carried value for them would be ignored at best.
func proofToPB(p corrosion.ActionProof) *pb.RuntimeActionProof {
	return &pb.RuntimeActionProof{
		Id: p.ID, Action: p.Action, TargetKind: p.TargetKind,
		TargetName: p.TargetName, DestHost: p.DestHost, Coordinator: p.Coordinator,
		LeaseHolder: p.LeaseHolder, LeaseExpiresAt: p.LeaseExpiresAt,
		QuorumLive: int32(p.QuorumLive), QuorumNeeded: int32(p.QuorumNeeded),
		RelocationToken: p.RelocationToken, FenceEpoch: p.FenceEpoch,
		OwnerEpoch: p.OwnerEpoch, LeaseTerm: p.LeaseTerm,
		LeaseKey: p.LeaseKey,
	}
}

// proofLeaseKeyProducible reports whether key is one a PROOF PRODUCER actually
// holds — a strictly narrower question than ValidLeaseKey's "is this one of the
// three leases".
//
// Membership in the three-key set is not authorization. The key SELECTS which
// ledger judgeProofLeaseTerm computes its threshold against, so a proof naming
// a different lease than the one its producer holds is judged against an
// unrelated high-water. The three ledgers advance independently, so the other
// two are routinely lower — and on a cluster whose rebalancer has never been
// elected, at 0, where any term >= 1 clears. That turns the term check into a
// formality for anything able to choose the name.
//
// The set is derived from what the tree EMITS, not from what exists: the only
// code that sets LeaseKey on a proof is the failover coordinator, at three
// sites, all corrosion.LeaseKeyFailover. The rebalancer and the dual-run
// detector hold leases but produce no proofs — the rebalancer's LeaseKey field
// configures its OWN acquisition, not a proof — so a proof naming either of
// their keys was produced by nothing in this tree.
//
// "" is handled by the caller: it is the "minted without a lease" form the
// lease-less producers emit.
//
// Widening this is deliberate, and the direction is known: container cold
// migration has producers of both kinds, so if a lease-holding producer other
// than the coordinator starts stamping, its key belongs here — and the
// equal-term holder check then becomes what distinguishes two legitimate
// producers of one action. Until then, failing closed costs nothing real.
func proofLeaseKeyProducible(key string) bool {
	return key == corrosion.LeaseKeyFailover
}

// validateProofTermStamp refuses a malformed lease-term stamp on a proof that is
// about to be PERSISTED, before it is persisted.
//
// It has to run before the write rather than at enforcement time because the
// stamp is BOUND: WriteActionProofValidated seeds these fields from the
// presented proof and relays the batch, so a forged value becomes that row's
// permanent authorization record on every peer. Enforcement afterwards reads
// whatever ledger the row now names.
//
// Factored out of claimCarriedProof because that is NOT the only path that
// persists a caller-supplied proof. promoteResolved seeds the row itself, from
// req.Proof, before the promote is relayed or executed — deliberately, so
// ErrProofDiverges can fire on the most destructive action in the tree — and
// that seed used to run with no stamp validation at all, committing and
// replicating a peer-supplied key that claimCarriedProof only rejected several
// hundred lines later, after the row had already shipped.
//
//   - A NEGATIVE term is malformed input. proofFromPB forwards a peer-supplied
//     int64 straight into the DB, and -5 marshals cleanly. nextLeaseTerm returns
//     COALESCE(MAX(term),0)+1, which is >= 1, so a term below zero is neither the
//     0 "minted without a term" sentinel nor a real tenure, and has no defined
//     behaviour in either enforcement arm. Refused PRE-LATCH, unlike the term
//     comparison, because this is not a legacy proof that predates stamping — it
//     is a broken one.
//   - A key NO PRODUCER HOLDS is refused rather than merely checked for
//     membership in the three leases. The key selects which ledger the threshold
//     is computed against; naming a quieter one moves the bar to 0 on a cluster
//     that never elected that lease. "failover " with a trailing space is enough
//     to miss the set, deliberately — the match neither trims nor folds.
//
// "" stays valid: it is the documented "minted without a lease" form the three
// lease-less producers emit, and refusing it would fail closed on LB apply,
// container relocation and automated promotion.
func validateProofTermStamp(p *pb.RuntimeActionProof) error {
	if p.GetLeaseTerm() < 0 {
		return status.Errorf(codes.InvalidArgument,
			"runtime-action proof %s carries lease term %d; a lease term is never negative "+
				"(allocation starts at 1, and 0 means the proof was minted without one)",
			p.GetId(), p.GetLeaseTerm())
	}
	if k := p.GetLeaseKey(); k != "" && !proofLeaseKeyProducible(k) {
		return status.Errorf(codes.InvalidArgument,
			"runtime-action proof %s names lease key %q, which no producer of a proof holds; "+
				"refusing to persist it (naming a quieter ledger would move the term "+
				"threshold this proof is judged against)", p.GetId(), k)
	}
	return nil
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
	// The term STAMP is validated before anything persists it. Factored out
	// because this is not the only caller that persists a caller-supplied proof:
	// see validateProofTermStamp.
	if err := validateProofTermStamp(p); err != nil {
		return "", err
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
	// The field set compared is ProofBindingEqual's, shared with the writer, so
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
	// The lease term: is the coordinator that minted this proof still the current
	// incarnation, as far as a QUORUM of this cluster can tell?
	//
	// This sits at the executor rather than only at the coordinator because it is
	// a trust boundary. The proof arrives over a direct peer RPC, so a stale or
	// misbehaving coordinator can skip its own precheck; nothing can skip this
	// one. The coordinator's precheck is an optimisation and a metric, not a
	// guarantee.
	//
	// NOT the only executor boundary, though: a VM RESCHEDULE proof never travels
	// over an RPC at all. The coordinator writes the row with a pending marker
	// and the destination's internal/health reconciler claims it off replication.
	// See leaseTermFenceFor's doc and Task 6b.
	if s.leaseTermEnforced(ctx) {
		if err := s.checkProofLeaseTerm(ctx, p, action, targetName); err != nil {
			return "", err
		}
	}
	if err := corrosion.ClaimActionProofFenced(ctx, s.db, p.GetId(), s.hostName,
		s.leaseTermFenceFor(ctx, p)); err != nil {
		if errors.Is(err, corrosion.ErrTermClaimantConflict) {
			s.noteGateRefused(action, health.ReasonStaleLeaseTerm)
			return "", status.Errorf(codes.FailedPrecondition,
				"this host has already acted at lease term %d of %q for another coordinator; "+
					"refusing proof %s from %q — one executor must not act for two claimants of "+
					"one tenure", p.GetLeaseTerm(), p.GetLeaseKey(), p.GetId(), p.GetCoordinator())
		}
		if errors.Is(err, corrosion.ErrProofSpent) {
			return "", status.Errorf(codes.FailedPrecondition,
				"proof %s already terminal/held — refusing to re-run %s of %s", p.GetId(), action, targetName)
		}
		return "", status.Errorf(codes.Unavailable, "claim proof %s: %v", p.GetId(), err)
	}
	return p.GetId(), nil
}

// leaseTermRequiredActions are the proof actions whose ONLY producer holds a
// leader lease, so a proof arriving with no term is a defect rather than a
// lease-less producer's normal output.
//
// reschedule qualifies and nothing else does. Its single mint site is
// failover/coordinator.go's WriteVMRescheduleProof call, and that coordinator
// holds the failover lease. Every other action has at least one producer that
// holds no lease at all and therefore has no term to stamp: mintLBProof
// (lb.go), mintRelocationProof (migrate_container.go) and AutoPromoteReplica
// (promote.go) all mint lease_term 0 with an empty key.
//
// This is why the term requirement is scoped rather than unconditional. An
// unconditional `term <= 0` refusal — which is what this task originally
// specified — fails LB apply, container cold migration and restore, and
// automated post-fence replica promotion CLOSED the moment the token latches,
// and blames a stale tenure rather than an unstamped producer. The DR path
// would be broken by the feature meant to protect it.
//
// RESIDUAL, deliberately recorded rather than papered over: relocate has BOTH
// kinds of producer. The failover coordinator's two mint sites now DO stamp
// (they hold the failover lease, so they always had a term to stamp), but
// mintRelocationProof has no lease and stamps nothing, so relocate stays out of
// this map — adding it would refuse every container cold migration.
//
// The consequence is narrower than it was but not gone: a relocate proof
// arriving unstamped is now either mintRelocationProof's normal output or a
// coordinator running a build older than this one, and the two are
// indistinguishable. Closing it needs a decision this phase does not get to
// make alone — either give mintRelocationProof a lease to stamp from (a design
// change; it has none today) or refuse unstamped relocates and accept that
// container cold migration then requires the coordinator.
var leaseTermRequiredActions = map[string]bool{
	corrosion.ActionReschedule: true,
}

// leaseTermFenceFor returns the claim fence for this proof, or nil for an
// unfenced claim.
//
// nil whenever enforcement is off, or the proof carries no term — an unstamped
// proof from a lease-less producer has no claimant identity to bind, and
// fencing on (key "", term 0) would bind every such producer on this host to
// whichever one claimed first, refusing all the others.
func (s *Server) leaseTermFenceFor(ctx context.Context, p *pb.RuntimeActionProof) *corrosion.TermFence {
	if !s.leaseTermEnforced(ctx) || p.GetLeaseTerm() <= 0 || p.GetLeaseKey() == "" {
		return nil
	}
	return &corrosion.TermFence{
		Key: p.GetLeaseKey(), Term: p.GetLeaseTerm(), Coordinator: p.GetCoordinator(),
	}
}

// checkProofLeaseTerm refuses a proof whose lease term is superseded, or whose
// coordinator is not the holder this node recorded at that term.
//
// Two REFUSAL REASONS, kept distinct on purpose: ReasonStaleLeaseTerm means
// fenced, ReasonLeaseTermUnconfirmed means we could not establish whether it was
// fenced. Collapsing them loses the only signal that separates the mechanism
// working from the mechanism degraded.
func (s *Server) checkProofLeaseTerm(ctx context.Context, p *pb.RuntimeActionProof, action, targetName string) error {
	reason, err := s.judgeProofLeaseTerm(ctx, p, action, targetName)
	if err != nil {
		s.noteGateRefused(action, reason)
	}
	return err
}

// judgeProofLeaseTerm is checkProofLeaseTerm's policy without the metric, and
// returns the countable reason alongside the error.
//
// Split out so a caller in ANOTHER package can count the refusal on its own
// observer. internal/health's reconciler is that caller: a VM reschedule proof
// never travels over an RPC, so it claims one off the replicated row and needs
// this exact judgment — but noting it here as well would count one refusal on
// two metrics.
func (s *Server) judgeProofLeaseTerm(ctx context.Context, p *pb.RuntimeActionProof, action, targetName string) (string, error) {
	term, key := p.GetLeaseTerm(), p.GetLeaseKey()

	// An UNSTAMPED proof: term 0 with no key. Refused only for the actions whose
	// producers all hold a lease (see leaseTermRequiredActions); otherwise it is
	// a lease-less producer's ordinary output and proceeds on the gates it
	// already had.
	if term == 0 && key == "" {
		if leaseTermRequiredActions[action] {
			return health.ReasonStaleLeaseTerm, status.Errorf(codes.FailedPrecondition,
				"runtime-action proof %s carries no lease term; refusing %s of %s "+
					"(lease_term_v1 is enforced and every producer of this action holds a lease)",
				p.GetId(), action, targetName)
		}
		return "", nil
	}

	// A HALF-stamped proof is malformed however it got that way: a term without
	// a key cannot be judged against any ledger, and a key without a term names
	// a ledger with nothing to compare. Neither is something a producer emits.
	//
	// The key is checked for PRODUCIBILITY, not mere membership, and it has to be
	// checked HERE rather than only where a carried proof is received. This is
	// the boundary VM reschedule crosses — the action the whole phase exists for
	// — and it never sees a carried proto: internal/health's reconciler picks the
	// row off replication and calls in through LeaseTermGateForPendingProof. So
	// the row IS the authorization record, and a row can carry a key this node's
	// receipt check never saw: a peer still on a pre-narrowing binary seeds one
	// from a proof it accepted, and it replicates from there. Judging such a row
	// against the ledger it names is the whole hole — the rebalancer's high-water
	// is 0 on a cluster that never rebalanced, so any term clears it.
	if term <= 0 || !proofLeaseKeyProducible(key) {
		return health.ReasonStaleLeaseTerm, status.Errorf(codes.FailedPrecondition,
			"runtime-action proof %s carries lease term %d for key %q, which is not a judgeable "+
				"pair; refusing %s of %s", p.GetId(), term, key, action, targetName)
	}

	verdict, threshold := s.leaseTermBarrier(ctx, key, term)
	switch verdict {
	case leaseTermUnconfirmed:
		return health.ReasonLeaseTermUnconfirmed, status.Errorf(codes.Unavailable,
			"cannot establish the quorum-observed lease term for %q; refusing %s of %s rather than "+
				"acting on this node's own possibly-stale replica", key, action, targetName)
	case leaseTermStale:
		return health.ReasonStaleLeaseTerm, status.Errorf(codes.FailedPrecondition,
			"runtime-action proof %s is at lease term %d, below the quorum-observed %d; refusing %s of %s",
			p.GetId(), term, threshold, action, targetName)
	}

	// Equal-term arm. A term at the threshold can still be a losing concurrent
	// claim: two partitioned nodes both compute MAX+1 and both name themselves.
	//
	// found == false is NOT a refusal. The ledger replicates independently of the
	// RPC carrying this proof, so a fresh valid proof routinely outruns its own
	// term row. It is safe to proceed only because the threshold arm above already
	// ran against quorum-observed history — and the claim's TermFence is what
	// covers the case this arm cannot see.
	holder, found, err := corrosion.LeaseTermHolder(ctx, s.db, key, term)
	if err != nil {
		return health.ReasonLeaseTermUnconfirmed, status.Errorf(codes.Unavailable,
			"read the holder of lease term %d for %q: %v", term, key, err)
	}
	if found && holder != p.GetCoordinator() {
		// Compared against Coordinator, not LeaseHolder: leaseSnapshot returns ""
		// on a read error by design ("an honesty record must not FABRICATE a
		// holder"), so LeaseHolder can be empty on a perfectly valid proof.
		return health.ReasonStaleLeaseTerm, status.Errorf(codes.FailedPrecondition,
			"runtime-action proof %s claims lease term %d of %q as %q, but this node recorded that "+
				"term to %q; refusing %s of %s",
			p.GetId(), term, key, p.GetCoordinator(), holder, action, targetName)
	}
	return "", nil
}

// LeaseTermGateForPendingProof is the executor-side lease-term gate for a proof
// read off the REPLICATED ROW rather than received over an RPC.
//
// It exists because claimCarriedProof is not the only executor trust boundary,
// which the plan for this phase assumed it was. A VM reschedule proof — the
// action this whole regime exists for — never travels over an RPC: the
// coordinator writes the row with a pending marker and the DESTINATION's
// internal/health reconciler picks it up from replication, validates it inline
// and claims it itself. A check added only to claimCarriedProof therefore runs
// on every proof path EXCEPT failover.
//
// The judgment is not duplicated for that caller. internal/grpcapi imports
// internal/health, so health cannot import back; the daemon injects this method
// into the reconciler instead. Everything policy-shaped stays here, in the one
// place it is already tested.
//
// Returns the fence to claim with (nil = unfenced), and on refusal a countable
// reason plus the error. The reason is returned rather than counted here so the
// reconciler counts it on its own observer — one refusal, one metric.
func (s *Server) LeaseTermGateForPendingProof(ctx context.Context, pr corrosion.ProofRecord) (*corrosion.TermFence, string, error) {
	if !s.leaseTermEnforced(ctx) {
		return nil, "", nil
	}
	p := proofToPB(pr.ActionProof)
	if reason, err := s.judgeProofLeaseTerm(ctx, p, pr.Action, pr.TargetName); err != nil {
		return nil, reason, err
	}
	return s.leaseTermFenceFor(ctx, p), "", nil
}
