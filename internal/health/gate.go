package health

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Split-brain safety gate (Phase 1).
//
// Every dangerous runtime-ownership action must fail closed without quorum. The
// gate is composed of two independent checks so per-host and coordinator-driven
// actions aren't wrongly subjected to leader-only rules:
//
//   - DecisionGate  — QuorumProof.Yes && the local host is COORDINATOR-eligible
//     (fully in service to *initiate* failover). Witnesses pass (they vote and
//     may decide/forward) but an upgrading/draining/warming host does not.
//   - ExecutionGate — QuorumProof.Yes && the local host is an ACTIVE WORKER
//     (localHostIsActiveWorker; witnesses never execute a workload).
//
// Callers in internal/failover additionally require holdLease() at the *decide*
// site. The lease alone is never sufficient: a CRDT lease can be "held" on both
// sides of a partition, so decide-site safety is holdLease() && DecisionGate.OK.
//
// QuorumProof is derived from THIS daemon's own probe results (c.peers), not from
// arbitrary replicated host_health rows, which freeze-but-look-fresh for a probe
// window after a partition and would let both sides believe they have quorum.

// QuorumState is the tri-state result of a local quorum computation.
type QuorumState int

const (
	// QuorumUnknown means the daemon has not completed its first probe cycle and
	// the startup grace has not elapsed: neither positive proof nor confirmed
	// loss. Callers must neither claim/act nor (for Phase 2) demote on Unknown.
	QuorumUnknown QuorumState = iota
	// QuorumNo means quorum is not currently held (fail closed).
	QuorumNo
	// QuorumYes means a live voting majority is reachable from this daemon.
	QuorumYes
)

// startupGrace bounds the QuorumUnknown warmup window. After it elapses without a
// completed probe cycle, Unknown is treated as No (fail closed).
const startupGrace = 20 * time.Second

// Gate refusal reasons — a CLOSED vocabulary shared with the
// litevirt_runtime_action_refused_total{reason} metric (wired in Phase 1 gate
// insertion). This is the plan's closed reason set PLUS the Phase-1/2 additions that
// postdate the plan's original list, each kept distinct for observability:
//   - ReasonWarmup — QuorumProof is Unknown (the tri-state warmup window): "can't
//     confirm quorum YET", kept separate from a confirmed no_quorum.
//   - ReasonProofClaimError — a TRANSIENT DB error while claiming a proof, distinct
//     from a spent/terminal proof (proof_terminal).
//   - ReasonSelfFenced — this node has self-fenced and refuses all decide/execute
//     during the fence-timeout window (doomed, waiting to reboot).
//
// Adding a reason here is safe (the metric CounterVec accepts any label value); keep
// this list and the documented plan vocabulary in sync.
const (
	ReasonNoQuorum              = "no_quorum"
	ReasonMissingWitness        = "missing_witness"
	ReasonLeaseLost             = "lease_lost"
	ReasonLocalNotActiveWorker  = "local_not_active_worker"
	ReasonNotCoordinatorElig    = "not_coordinator_eligible"
	ReasonPeerUnreachable       = "peer_unreachable"
	ReasonActivationUnconfirm   = "activation_unconfirmed"
	ReasonUnsupportedCapability = "unsupported_capability"
	ReasonProofMissing          = "proof_missing"
	ReasonProofInProgress       = "proof_in_progress"
	ReasonProofTerminal         = "proof_terminal"
	ReasonProofConflict         = "proof_conflict"
	ReasonProofClaimError       = "proof_claim_error" // transient DB error claiming a proof (not a spent/terminal proof)
	ReasonStaleEpoch            = "stale_epoch"       // Phase 5 (fence/owner epoch staleness)
	ReasonFenceUnproven         = "fence_unproven"
	ReasonDemotionFailed        = "demotion_failed"
	ReasonVIPReleaseUnconfirmed = "vip_release_unconfirmed"
	ReasonStorageUnverified     = "storage_unverified"
	ReasonWarmup                = "warmup"
	ReasonSelfFenced            = "self_fenced" // this node self-fenced; refuses decide/execute until it reboots
)

// GateResult is the outcome of a gate check. Reason is set (from the closed
// vocabulary above) only when !OK.
type GateResult struct {
	OK     bool
	Reason string
}

func gateOK() GateResult         { return GateResult{OK: true} }
func gateNo(r string) GateResult { return GateResult{OK: false, Reason: r} }

// votingEligible mirrors failover.countLiveHosts' predicate exactly: a host is a
// live voting member iff its state is not offline/maintenance/fenced (witnesses
// included, since countLiveHosts counts them in the denominator). The self-count
// predicate and the quorum denominator MUST be identical or quorum skews.
func votingEligible(state string) bool {
	switch state {
	case "offline", "maintenance", "fenced":
		return false
	}
	return true
}

// QuorumProof computes whether this daemon currently sees a live voting majority,
// using its OWN probe results. Returns the tri-state plus the live/needed counts
// for observability. `needed = liveVotingHosts/2 + 1`; `live` counts self (if
// voting-eligible) plus each voting-eligible peer this daemon has probed healthy.
func (c *Checker) QuorumProof(ctx context.Context) (state QuorumState, live, needed int) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		// Can't read the host table → UNKNOWN, not No. For gates this still fails closed
		// (Unknown refuses). But the VIPDemoter treats sustained No as a TRIGGER to demote
		// local VIPs (and, only if that demote can't be confirmed on a node with a verified
		// watchdog, to self-fence); mapping a transient local DB error (e.g. anti-entropy
		// lock contention) to No would stand a healthy, quorum-holding node's VIP down.
		// Unknown = "neither proof nor loss" → no action, no loss-clock.
		return QuorumUnknown, 0, 0
	}

	c.mu.Lock()
	probed := c.probedOnce
	started := c.startedAt
	healthy := make(map[string]bool, len(c.peers))
	for name, ps := range c.peers {
		// Count a peer toward quorum ONLY on a restart-local fresh probe success.
		// peerState.status/failures are seeded from the host_health DB row at
		// bootstrap (checker.go), so a just-restarted isolated node would otherwise
		// read a peer as "healthy" from a STALE pre-restart row and briefly regain
		// quorum until suspectThreshold fresh failures accrue — exactly the stale-row
		// quorum Phase 1 removes. lastHealthyAt is a local monotonic anchor, zero
		// until THIS run probes the peer healthy at least once, so it can't be
		// credited across a restart.
		healthy[name] = ps.status == "healthy" && !ps.lastHealthyAt.IsZero()
	}
	c.mu.Unlock()

	denom := 0
	selfEligible := false
	for _, h := range hosts {
		if !votingEligible(h.State) {
			continue
		}
		denom++
		if h.Name == c.hostName {
			selfEligible = true
		}
	}
	needed = denom/2 + 1

	if selfEligible {
		live++
	}
	for _, h := range hosts {
		if h.Name == c.hostName || !votingEligible(h.State) {
			continue
		}
		if healthy[h.Name] {
			live++
		}
	}

	// Warmup: before the first probe cycle, c.peers is empty/partial, so a
	// multi-node cluster would read as No purely from missing probes. Report
	// Unknown (neither proof nor loss) until a probe cycle completes or the
	// startup grace elapses (then fall through to the fail-closed Yes/No count).
	if !probed && time.Since(started) < startupGrace {
		return QuorumUnknown, live, needed
	}
	if live >= needed {
		return QuorumYes, live, needed
	}
	return QuorumNo, live, needed
}

// ExecutionGate is the universal runtime gate: quorum held AND this host is an
// active worker (never a witness). Used at execute sites (startPendingVM,
// doPromoteLocal, container re-key, ApplyLB, owner-assert).
func (c *Checker) ExecutionGate(ctx context.Context) GateResult {
	if c.isSelfFenced() {
		return gateNo(ReasonSelfFenced)
	}
	switch state, _, _ := c.QuorumProof(ctx); state {
	case QuorumUnknown:
		return gateNo(ReasonWarmup)
	case QuorumNo:
		return gateNo(ReasonNoQuorum)
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return gateNo(ReasonNoQuorum)
	}
	if !localHostIsActiveWorker(hosts, c.hostName) {
		return gateNo(ReasonLocalNotActiveWorker)
	}
	return gateOK()
}

// DecisionGate is the coordinator gate: quorum held AND this host is
// coordinator-eligible (fully in service to initiate failover — active, warmed;
// witnesses allowed). For a TWO-worker cluster with no live witness, HA decisions are
// blocked (a 1-1 split can't be safely arbitrated — each side is 1-of-2, neither a
// majority). Callers must also hold the failover lease.
func (c *Checker) DecisionGate(ctx context.Context) GateResult {
	if c.isSelfFenced() {
		return gateNo(ReasonSelfFenced)
	}
	switch state, _, _ := c.QuorumProof(ctx); state {
	case QuorumUnknown:
		return gateNo(ReasonWarmup)
	case QuorumNo:
		return gateNo(ReasonNoQuorum)
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return gateNo(ReasonNoQuorum)
	}

	// Coordinator-eligible: local host present + state=="active" (stricter than the
	// voting predicate — a draining/upgrading/maintenance host votes but must not
	// initiate ownership changes) + past warmup.
	var self *corrosion.HostRecord
	for i := range hosts {
		if hosts[i].Name == c.hostName {
			self = &hosts[i]
			break
		}
	}
	c.mu.Lock()
	probed := c.probedOnce
	c.mu.Unlock()
	if self == nil || self.State != "active" || !probed {
		return gateNo(ReasonNotCoordinatorElig)
	}

	// Two workers, no live witness → block automated HA (a 1-1 split is unarbitrable). This
	// is scoped to EXACTLY two workers, not any even count: for 4/6/… workers quorum math
	// already disambiguates a clean split (a 2-2 of four needs 3 to act, so neither side
	// does), so a broader `workers%2==0` block adds NO safety there while permanently
	// stopping the rebalance executor (decideGate) on a healthy even cluster.
	workers, witnesses := 0, 0
	for i := range hosts {
		if !votingEligible(hosts[i].State) {
			continue
		}
		if hosts[i].IsWitness() {
			witnesses++
		} else {
			workers++
		}
	}
	if workers == 2 && witnesses == 0 {
		return gateNo(ReasonMissingWitness)
	}
	return gateOK()
}
