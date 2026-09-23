package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// leaseTermMinVotingHosts is the smallest cluster on which lease-term
// enforcement may latch.
//
// The number to reason about is not the majority itself but the SLACK between
// the answers the barrier can gather and the answers it needs, AFTER the host
// loss — because the coordinator persists the failed host fenced/offline before
// it stamps the reschedule proof, so the barrier can only ever draw on this node
// plus the survivors:
//
//	hosts  denom  needed  canAnswer  slack
//	    2      1       1          1      0
//	    3      2       2          2      0   <- every survivor mandatory
//	    4      3       2          3      1   <- first size that tolerates one
//	    5      4       3          4      1
//
// An earlier version of this comment claimed three was "survivable" and two was
// not. That reasoning counted hosts BEFORE the loss. At three hosts the slack is
// zero: every survivor's answer is mandatory for every accepted proof, which is
// the same position two hosts are in. Four is the smallest cluster where one
// slow or silent peer still leaves a quorum.
//
// Note that `needed` is 2 for both two and three voting hosts (2/2+1 = 2/2+1),
// so the fenced host leaving the denominator is NOT what makes the three-host
// case tight — and reading it that way inverts its effect. The exclusion is what
// makes FOUR work: keep a fenced host in the denominator and four hosts are
// slack-0 as well (denom 4, needed 3, canAnswer 3), pushing the first tolerant
// size out to five. health.VotingEligible is load-bearing in the safe direction.
//
// Three is kept anyway, and the trade is explicit:
//
//   - Raising the floor to 4 would leave the minimum supported cluster with no
//     lease-term enforcement whatsoever. A three-host cluster is where a
//     partitioned coordinator double-starting a VM on shared storage is least
//     likely to be noticed, so trading the regime away there costs more than a
//     mandatory peer answer does.
//   - A missed answer is recoverable. A peer that misses leaseBarrierBudget
//     yields leaseTermUnconfirmed, which refuses THIS attempt; the reconciler
//     returns without touching VM state, so the VM stays pending and the next
//     tick retries. Added latency on a three-host failover, not a stranded
//     workload.
//   - This floor gates whether enforcement ever turns on. Readiness is evaluated
//     at advertisement time and health.Enforced latches one-way, so it is not
//     re-checked mid-incident — and could not be, without letting enforcement
//     switch itself off during exactly the event it exists for.
//
// health.TestQuorumProof_PostFenceSlackAcrossClusterSizes is the arithmetic, so
// a future reader checks it rather than re-deriving it.
const leaseTermMinVotingHosts = 3

// LeaseTermReadiness evaluates this node's lease_term_v1 readiness. The
// capability latches only when EVERY node advertises it, so each node proves its
// own slice of the requirement.
//
// It is called from advertisedCapabilities, which runs inside the Ping handler.
// Every predicate here MUST therefore be a local read: no peer Ping, no
// gate.Enforced, no quorum barrier. Anything that fans out from here recurses
// through Ping (see hardwareV2Ready's comment for the same hazard). That is why
// the split-brain dependency below is checked with Latched — a cheap in-memory
// read — rather than Enforced, which may fresh-Ping.
//
// DELIBERATELY ABSENT: the "no unresolved LWW ties" predicate that
// OwnerEpochReadiness applies. A contested (key, term) is the fault the term
// ledger exists to record, and Phase 1's keep-local merge flags it as a ledger
// conflict that no write ever converges — the row is immutable, so the tie
// stands until an operator acknowledges it. Withholding on it would disable
// enforcement the first time two nodes claimed one tenure, which is the moment
// enforcement matters most. Do not add it.
func (s *Server) LeaseTermReadiness(ctx context.Context) (bool, string) {
	// The ledger must be readable: a node that cannot read its own terms cannot
	// refuse a stale one, and must not let the fleet latch across it.
	if _, err := corrosion.CurrentLeaseTerm(ctx, s.db, corrosion.LeaseKeyFailover); err != nil {
		return false, "lease term ledger unreadable: " + err.Error()
	}

	// split_brain_gate_v1 is a PREREQUISITE, not an unrelated token.
	//
	// Lease-term enforcement lives inside claimCarriedProof, whose first
	// statement returns early for a nil proof — so a proofless call is not
	// gated by this regime at all. Whether a proofless call is refused is
	// decided by that other token (`automated && req.Proof == nil &&
	// s.gateActive(ctx)`). Advertising lease_term_v1 without it would let the
	// fleet latch across a node that reports the regime as active while
	// accepting every proofless protected RPC ungated.
	//
	// In practice split_brain_gate_v1 has no config flag and latches on
	// advertisement alone, so this is cheap insurance rather than a real
	// obstacle — but it is the difference between a documented dependency and
	// an accidental one.
	if s.gate == nil {
		return false, "no capability gate wired"
	}
	if !s.gate.Latched(capabilities.SplitBrainGateV1) {
		return false, fmt.Sprintf(
			"%s has not latched; lease-term enforcement gates only PROOF-BEARING calls, so "+
				"without it a proofless protected RPC is still accepted ungated",
			capabilities.SplitBrainGateV1)
	}

	// lease_term_ledger_v1 must be DURABLY latched, because until it is this node
	// mints no term at all (corrosion.SetLeaseTermLedgerGate). Advertising
	// readiness to enforce ON terms while producing none would latch the fleet
	// into refusing every reschedule: the executor refuses term 0, and term 0 is
	// all this node can hand it. Durable rather than in-memory for the same
	// reason the mint gate is: a restart that reloads no marker would silently
	// stop minting under a latched enforcement regime.
	//
	// Also a local in-memory read, so it is safe on the Ping path.
	//
	// This checks that the node CAN MINT, which is not the same as its producers
	// STAMPING, and no runtime predicate here can check the latter — whether a
	// proof literal populates LeaseTerm is a property of the build, not of any
	// state this function can read. Three reviewers independently read this
	// predicate as covering stamping; it does not, and the gap was real: the mint
	// gate worked correctly while every reschedule proof went out with term 0,
	// which would have refused every VM failover in the cluster the moment
	// lease_term_v1 latched.
	//
	// What makes stamping safe to rely on cluster-wide is advertisement, not this
	// check: a build that does not stamp does not advertise lease_term_v1, so the
	// latch cannot form across one. The stamping itself is pinned by
	// failover.TestVMRescheduleProofCarriesLeaseTerm.
	if !s.db.MayMintLeaseTerm() {
		return false, fmt.Sprintf(
			"%s has not durably latched; this node mints no lease term yet, so enforcing on "+
				"terms would refuse every reschedule it coordinates",
			capabilities.LeaseTermLedgerV1)
	}

	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return false, "cannot read host table: " + err.Error()
	}
	voting := 0
	for _, h := range hosts {
		if health.VotingEligible(h.State) {
			voting++
		}
	}
	if voting < leaseTermMinVotingHosts {
		return false, fmt.Sprintf(
			"%d voting-eligible host(s); lease-term enforcement needs at least %d "+
				"(below that a majority is every host, so one peer outage refuses every "+
				"protected action)",
			voting, leaseTermMinVotingHosts)
	}
	return true, ""
}
