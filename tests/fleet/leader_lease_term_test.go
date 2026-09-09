// Fleet scenarios for leader-lease fencing terms.
//
// Every failure the term ledger exists to catch is multi-node, and the
// single-package tests structurally cannot reach any of them: they run one
// Client, so they can drive the anti-entropy merge OR the WAL apply path but
// never both against two real nodes with separate DBs. Four defects reached
// review in exactly that blind spot — the two paths resolving a contested term
// to different holders, a merge loser minting a higher term on its next renewal,
// a reseed regressing the allocation high-water mark, and the same-holder double
// mint.
//
// These scenarios run the real spine: separate per-node DBs, statements carried
// over real gRPC + mTLS + applyStatementLWW, and the real anti-entropy dump.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

const leaseTermKey = "failover"

// leaseRowFor reads a node's own leader_election row for the lease key. holder
// is "" when the row is absent, which is how a node that never received a
// peer's upsert sees the key.
func leaseRowFor(t *testing.T, n *Node) (holder, expiresAt string, err error) {
	t.Helper()
	rows, qerr := n.DB.Query(context.Background(),
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, leaseTermKey)
	if qerr != nil {
		return "", "", qerr
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	return rows[0].String("holder"), rows[0].String("expires_at"), nil
}

func leaseTermHolderAt(t *testing.T, n *Node, term int64) (string, bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = ? AND deleted_at IS NULL`,
		leaseTermKey, term)
	if err != nil {
		t.Fatalf("read term %d on %s: %v", term, n.Name, err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("holder"), true
}

// TestFleet_LeaseTerm_BothPathsAgreeOnAContestedHolder is the scenario the
// review's headline finding lived in.
//
// Two partitioned nodes each compute MAX(term)+1 = 1 and each name themselves
// holder. One node then learns the other's claim over the WAL, and a second
// pair learns the identical claim by anti-entropy repair. Before the fix the WAL
// path (INSERT OR IGNORE, first-writer-wins) and the dump path (LWW on
// updated_at, last-writer-wins) produced DIFFERENT holders — so the executor's
// (term, holder) check refused opposite claimants depending on which path
// delivered, and a WAL-converged node silently flipped its own answer on its
// next repair cycle.
//
// The property: whichever path delivers, a node keeps the claim it already had.
func TestFleet_LeaseTerm_BothPathsAgreeOnAContestedHolder(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// Both nodes acquire term 1 for the same key while partitioned — each sees
	// an empty ledger and an unheld lease.
	c.Partition(a, b)
	heldA, termA, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, 30*time.Second, now)
	if err != nil || !heldA {
		t.Fatalf("%s acquire: held=%v err=%v", a.Name, heldA, err)
	}
	heldB, termB, err := corrosion.AcquireLeaseWithTerm(ctx, b.DB, leaseTermKey, b.Name, 30*time.Second, now)
	if err != nil || !heldB {
		t.Fatalf("%s acquire: held=%v err=%v", b.Name, heldB, err)
	}
	if termA != 1 || termB != 1 {
		t.Fatalf("partitioned nodes got terms %d and %d; both must compute 1 for this "+
			"scenario to be the contested case", termA, termB)
	}
	c.Heal(a, b)

	// Path 1: b learns a's claim over the WAL.
	pumpMutations(t, c, a, b)
	// Path 2: a learns b's claim by anti-entropy repair.
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy b→a: %v", err)
	}
	// And in the OTHER direction too. Doing only one is not enough: a merge that
	// converges by comparing encoded rows keeps whichever holder sorts lower, so
	// a single direction passes or fails purely on how the two node names happen
	// to sort. Merging both ways means one direction always has the local row
	// sorting higher, where a converging merge would adopt the incoming holder.
	if err := b.DB.MergeStateBytesLWW(a.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy a→b: %v", err)
	}

	holderA, okA := leaseTermHolderAt(t, a, 1)
	holderB, okB := leaseTermHolderAt(t, b, 1)
	if !okA || !okB {
		t.Fatalf("term 1 missing after exchange: a=%v b=%v", okA, okB)
	}
	if holderA != a.Name {
		t.Errorf("%s resolved term 1 to %q after ANTI-ENTROPY delivery, want its own claim %q. "+
			"The dump path must not rewrite an existing term row, or it disagrees with the "+
			"WAL path about who held the tenure", a.Name, holderA, a.Name)
	}
	if holderB != b.Name {
		t.Errorf("%s resolved term 1 to %q, want its own claim %q", b.Name, holderB, b.Name)
	}

	// The disagreement must be RAISED, not merely preserved. This is the
	// assertion that separates "kept local and flagged" from "converged
	// deterministically": a converging merge also leaves one node holding its
	// own claim, but records a tie-break rather than an unresolved conflict, so
	// nothing tells the operator two nodes claimed one tenure.
	if a.DB.UnresolvedTieCount() == 0 && b.DB.UnresolvedTieCount() == 0 {
		t.Error("neither node flagged an unresolved tie for the contested term. " +
			"litevirt_lww_tie_unresolved_current is the signal docs/operating-model.md " +
			"sends operators to; a merge that silently elects a winner leaves them nothing")
	}
}

// TestFleet_LeaseTerm_MergeLoserDoesNotMintAHigherTerm: a node whose ledger
// learns a peer's competing claim must not respond by minting a term ABOVE it.
//
// leader_election is anti-entropy excluded while leader_lease_terms is
// replicated, so "our lease row still names us, but the ledger's newest term
// names a peer" is reachable in ordinary operation — not just under partition.
// Reading that as "no term recorded yet" and falling through to acquisition
// promoted the node that lost the term race above the winner, inverting fencing.
func TestFleet_LeaseTerm_MergeLoserDoesNotMintAHigherTerm(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// a holds the lease and term 1.
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, 30*time.Second, now); err != nil || !held {
		t.Fatalf("%s acquire: held=%v err=%v", a.Name, held, err)
	}
	// b, partitioned, takes what it believes is a free lease and mints term 2
	// (it has already seen term 1 by repair, so it allocates above it).
	if err := b.DB.MergeStateBytesLWW(a.DB.DumpStateBytes()); err != nil {
		t.Fatalf("seed b's ledger: %v", err)
	}
	// b's own lease row: it never received a's, so b sees the key as unheld.
	// Nothing to clear — assert that, so the scenario cannot silently degrade
	// into "b renewed its own lease".
	if holder, _, err := leaseRowFor(t, b); err != nil {
		t.Fatalf("read %s lease row: %v", b.Name, err)
	} else if holder != "" {
		t.Fatalf("%s already sees holder %q; this scenario needs b to view the lease as "+
			"unheld so its acquisition is genuine", b.Name, holder)
	}
	heldB, termB, err := corrosion.AcquireLeaseWithTerm(ctx, b.DB, leaseTermKey, b.Name, 30*time.Second, now)
	if err != nil {
		t.Fatalf("%s acquire: %v", b.Name, err)
	}
	if !heldB || termB <= 1 {
		t.Fatalf("%s must take a term above 1 for this scenario: held=%v term=%d", b.Name, heldB, termB)
	}

	// a now learns b's higher claim by repair, while a's OWN leader_election row
	// still names a (that table is anti-entropy excluded).
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy b→a: %v", err)
	}
	before, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("threshold: %v", err)
	}

	// a's next ordinary renewal tick.
	held, term, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name,
		30*time.Second, now.Add(time.Second))
	if err != nil {
		t.Fatalf("%s renewal: %v", a.Name, err)
	}
	if held && term > before {
		t.Errorf("%s was superseded (threshold %d) and its renewal minted term %d — the "+
			"node that LOST the term race now owns MAX(term), which inverts fencing",
			a.Name, before, term)
	}
	if held {
		t.Errorf("%s reported holding the lease with term %d after a peer's newer term "+
			"superseded it; it must fail closed", a.Name, term)
	}
	after, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("threshold after: %v", err)
	}
	if after != before {
		t.Errorf("the rejection threshold moved %d -> %d on a superseded node's renewal",
			before, after)
	}
}

// TestFleet_LeaseTerm_ReseedDoesNotRegressTheHighWaterMark: a reseed must not
// hand out a term number a previous incarnation already used.
//
// A reseed discards local replicated state and re-merges from one peer, so the
// terms an isolated node minted are precisely the ones the peer never received.
// With the ledger discarded, MAX(term) regressed and the next acquisition reused
// a number — and because a term row is immutable, peers holding the old row
// IGNORE the reallocated one, so the two incarnations' (term, holder) mapping
// diverges permanently.
func TestFleet_LeaseTerm_ReseedDoesNotRegressTheHighWaterMark(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// a mints several terms while b hears nothing about them.
	c.Partition(a, b)
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * time.Hour) // each lapse ends a tenure
		if _, _, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, time.Second, at); err != nil {
			t.Fatalf("%s acquire %d: %v", a.Name, i, err)
		}
	}
	c.Heal(a, b)

	high, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("high-water: %v", err)
	}
	if high < 3 {
		t.Fatalf("expected at least 3 terms minted while partitioned, got %d", high)
	}

	// a reseeds from b, which has none of those terms.
	if _, err := a.DB.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("reseed discard: %v", err)
	}
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("reseed merge: %v", err)
	}

	after, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("high-water after reseed: %v", err)
	}
	if after < high {
		t.Errorf("the allocation high-water mark regressed %d -> %d across a reseed. The "+
			"terms this node minted are exactly the ones its reseed source never received, "+
			"so the next acquisition reuses a number a prior incarnation already holds — "+
			"and an immutable term row means peers IGNORE the reallocation, diverging "+
			"permanently", high, after)
	}
}

// ---------------------------------------------------------------------------
// Phase 2 enforcement scenarios.
//
// The single-package tests structurally cannot reach any of these. testServer
// points pkiDir at a nonexistent path, so every peer dial fails before network
// I/O and the barrier's peer arm is dead code — a single-package suite stays
// green with the entire fan-out stubbed out. What follows drives the real
// barrier: a real peer answering GetLeaseTermHighWater from its OWN ledger over
// real mTLS, with the executor's own replica deliberately disagreeing.
// ---------------------------------------------------------------------------

// MUTATION RESULTS. Each scenario below was confirmed to KILL a mutation of the
// property it claims, because a fleet scenario that passes for an incidental
// reason is worse than none — it reports coverage it does not have.
//
//	barrier ignores its peers' answers (counts them, discards the term)
//	  -> APeerHigherTermBeatsTheLocalReplica: the stale proof is ACCEPTED
//	quorum shortfall treated as no objection
//	  -> MinorityExecutorRefusesRatherThanActs: accepted with no peer reachable
//	equal-term holder check removed
//	  -> TwoExecutorsOneContestedTerm: BOTH nodes accept the displaced claimant
//	leaseTermEnforced returns true unconditionally
//	  -> PreLatchIsInertAcrossTheFleet: refuses mid-roll
//	emit-side shape gate removed (always emit the widened insert)
//	  -> ARollingUpgradeKeepsReplicating: the un-latched node emits the wide shape
//	mint gate moved back BELOW the ledger classification
//	  -> AMixedGateClusterKeepsLeasesMoving: renewal 1 reports the lease lost
//	partition stops dropping GetLeaseTermHighWater
//	  -> MinorityExecutorRefusesRatherThanActs: accepted, because the
//	     "partitioned" executor still reached its peers
//
// TWO RECORDED NON-KILLS, both honest rather than gaps.
//
// Removing `proof_insert_pre_lease_term_v51` from the historical ledger no
// longer kills ARollingUpgradeKeepsReplicating, and that is a STRENGTHENING: the
// narrow shape is now a live emitter too, so its fingerprint sits in the
// generated ledger as well and one removal no longer un-registers it. The
// emit-side mutation above is what discriminates now.
//
// The receive-side half cannot be isolated by any fleet scenario, and it is
// worth being explicit about why: this harness runs ONE binary, so sender and
// receiver share a ledger. The historical entry exists for a shape only a
// DIFFERENT, older binary emits, which no in-repo test can instantiate. It is
// held by TestHistoricalLedgerComplete and the frozen compatibility digest
// instead — not by anything here.

// startCheckers runs each node's real health checker and waits for every node
// to hold quorum.
//
// The barrier refuses unless gate.QuorumProof reports QuorumYes, and a Checker
// only counts a peer once THIS run has probed it healthy (lastHealthyAt is a
// restart-local anchor, deliberately, so a stale host_health row cannot buy
// quorum back). checkInterval is 2s and the first probe lands on the first
// tick, so this waits rather than assuming.
func startCheckers(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, n := range c.Nodes {
		go gates[n.Name].Start(ctx)
	}
	for _, n := range c.Nodes {
		node := n
		eventually(t, 20*time.Second, "quorum on "+node.Name, func() bool {
			state, _, _ := gates[node.Name].QuorumProof(context.Background())
			return state == health.QuorumYes
		})
	}
	// Stop probing the moment quorum is established. The scenarios need the
	// RESULT, not an ongoing loop: QuorumProof reads the peer state the probe
	// cycle already recorded, and CapabilityActive drives the pinger directly
	// rather than through this loop, so latching still works with it stopped.
	//
	// Left running, these are the first background goroutines this package has
	// ever had, and they probe every peer every 2s over real mTLS for the rest
	// of the test binary's run. Neighbouring timing-sensitive scenarios — the
	// hardware_v2 latch tests lean on `eventually` against a 3s negative-cache
	// TTL — were observed tipping over under that added load while passing in
	// isolation. A test suite that makes its neighbours flaky has a cost even
	// when its own assertions are sound.
	cancel()
}

// latchLeaseTerm brings the whole fleet to a latched lease_term_v1.
//
// Order matters and is the production order. LeaseTermReadiness withholds
// lease_term_v1 until split_brain_gate_v1 has latched (this regime gates
// proof-bearing calls only, so without it a proofless protected RPC is still
// accepted ungated) and until lease_term_ledger_v1 is DURABLY latched (until
// then the node mints no term at all, and enforcing on terms while producing
// none refuses every reschedule it coordinates).
func latchLeaseTerm(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		node := n
		node.Server.SetLeaseTermEnforce(true)
		node.Server.SetLeaseTermReady(func() bool {
			ready, _ := node.Server.LeaseTermReadiness(context.Background())
			return ready
		})
	}
	for _, tok := range []string{capabilities.SplitBrainGateV1, capabilities.LeaseTermLedgerV1} {
		for _, n := range c.Nodes {
			if !gates[n.Name].Enforced(ctx, tok) {
				t.Fatalf("%s: %s failed to latch across the fleet", n.Name, tok)
			}
		}
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.LeaseTermV1) {
			ready, reason := n.Server.LeaseTermReadiness(ctx)
			t.Fatalf("%s: lease_term_v1 failed to latch (readiness=%v reason=%q)",
				n.Name, ready, reason)
		}
	}
}

// seedTermOn writes one term row into ONE node's ledger, so a scenario can make
// the executor's own replica disagree with its peers'.
//
// The write does land in that node's mutation_log, but this harness does not run
// the replicator's background loop — mutations travel only when a scenario calls
// pumpMutations — so it stays local until asked for. That is the property these
// scenarios need: divergence the fleet has genuinely not converged on yet.
func seedTermOn(t *testing.T, n *Node, term int64, holder string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := n.DB.Execute(context.Background(),
		`INSERT OR IGNORE INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		leaseTermKey, term, holder, ts, ts, n.DB.NowTS()); err != nil {
		t.Fatalf("seed term %d on %s: %v", term, n.Name, err)
	}
}

// rescheduleProofAt builds the proof record an executor judges. reschedule is
// the action whose every producer holds a lease, so it is the one the term
// requirement applies to.
func rescheduleProofAt(term int64, coordinator string) corrosion.ProofRecord {
	return corrosion.ProofRecord{
		ActionProof: corrosion.ActionProof{
			ID:     "p-" + coordinator + "-" + time.Now().Format("150405.000000000"),
			Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm1",
			DestHost: "dest", Coordinator: coordinator,
			LeaseTerm: term, LeaseKey: leaseTermKey,
		},
		Status: corrosion.ProofPrepared,
	}
}

// TestFleet_LeaseTerm_APeerHigherTermBeatsTheLocalReplica is the single case the
// whole barrier exists for, and the one a single-package test cannot express: it
// needs a real peer answering a real RPC over real mTLS while the executor's own
// ledger disagrees.
//
// The executor's replica says 4. Two quorum peers say 6. A term-5 proof must be
// refused as stale — judged against the QUORUM-observed high water, not against
// whatever this node happens to have received.
//
// Acting on the local replica alone is precisely the split the ledger exists to
// stop: leader_election is anti-entropy EXCLUDED while leader_lease_terms is
// replicated, so a lagging executor reading only itself is a reachable state in
// ordinary operation, not a partition-only curiosity.
func TestFleet_LeaseTerm_APeerHigherTermBeatsTheLocalReplica(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	exec, peer1, peer2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	gates := gateAll(t, c)
	startCheckers(t, c, gates)
	latchLeaseTerm(t, c, gates)

	// The executor has only seen up to term 4; the rest of the fleet is at 6.
	seedTermOn(t, exec, 4, peer1.Name)
	for _, n := range []*Node{peer1, peer2} {
		seedTermOn(t, n, 4, peer1.Name)
		seedTermOn(t, n, 6, peer2.Name)
	}

	fence, reason, err := exec.Server.LeaseTermGateForPendingProof(ctx, rescheduleProofAt(5, peer1.Name))
	if err == nil {
		t.Fatalf("a term-5 proof was ACCEPTED (fence=%v) while a quorum of peers reports term 6. "+
			"The executor judged against its own lagging replica, which is the stale-leader "+
			"write the ledger exists to fence", fence)
	}
	if reason != health.ReasonStaleLeaseTerm {
		t.Errorf("refusal reason = %q, want %q. %q means FENCED and %q means could-not-establish; "+
			"conflating them tells an operator the wrong thing about a real split",
			reason, health.ReasonStaleLeaseTerm,
			health.ReasonStaleLeaseTerm, health.ReasonLeaseTermUnconfirmed)
	}

	// And the same proof AT the observed high water is accepted, so the refusal
	// above is the barrier discriminating rather than refusing everything.
	if _, reason, err := exec.Server.LeaseTermGateForPendingProof(ctx, rescheduleProofAt(6, peer2.Name)); err != nil {
		t.Errorf("a term-6 proof from the recorded holder was refused (%q: %v); the barrier must "+
			"fence a stale term, not every term", reason, err)
	}
}

// TestFleet_LeaseTerm_MinorityExecutorRefusesRatherThanActs: an executor that
// cannot establish the quorum-observed term must refuse, and must say
// UNCONFIRMED rather than STALE.
//
// Failing open here would present as protection while providing none — the
// partitioned minority is exactly where a stale coordinator's proof arrives.
// And the two reasons are not interchangeable: stale means fenced, unconfirmed
// means the mechanism could not run, and an operator debugging a refused
// failover needs to know which.
func TestFleet_LeaseTerm_MinorityExecutorRefusesRatherThanActs(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	exec, peer1, peer2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	gates := gateAll(t, c)
	startCheckers(t, c, gates)
	latchLeaseTerm(t, c, gates)

	seedTermOn(t, exec, 5, exec.Name)
	for _, n := range []*Node{peer1, peer2} {
		seedTermOn(t, n, 5, exec.Name)
	}

	// Sever the executor from both peers. The barrier's quorum read travels the
	// same link as replication, so it gets no answers and cannot establish a
	// threshold — with only its own ledger, which is exactly what it must not
	// act on.
	c.Partition(exec, peer1)
	c.Partition(exec, peer2)

	_, reason, err := exec.Server.LeaseTermGateForPendingProof(ctx, rescheduleProofAt(5, exec.Name))
	if err == nil {
		t.Fatal("a proof was ACCEPTED by an executor that could reach no peer. With one replica " +
			"and no quorum it cannot tell a current term from a superseded one, so accepting " +
			"is the failure this barrier exists to prevent")
	}
	if reason != health.ReasonLeaseTermUnconfirmed {
		t.Errorf("refusal reason = %q, want %q. This node was not fenced — it could not "+
			"establish WHETHER it was, and reporting %q would send an operator hunting a "+
			"split-brain that never happened",
			reason, health.ReasonLeaseTermUnconfirmed, health.ReasonStaleLeaseTerm)
	}
}

// TestFleet_LeaseTerm_TwoExecutorsOneContestedTerm is the honest §1b property.
//
// Two partitioned nodes both mint term 5 and both name themselves. After the
// exchange each executor accepts only the claimant IT recorded and refuses the
// other, and neither accepts both. That is what the equal-term holder check
// buys: a term at the observed high water can still be a LOSING concurrent
// claim, so the threshold arm alone is not enough.
//
// It deliberately does NOT assert that the cluster agrees on a winner. Under
// keep-local it does not, and an assertion that it does would be a test of a
// guarantee this phase does not provide — the disagreement is surfaced as an
// unresolved tie for an operator, not silently elected away.
func TestFleet_LeaseTerm_TwoExecutorsOneContestedTerm(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	a, b, wit := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	gates := gateAll(t, c)
	startCheckers(t, c, gates)
	latchLeaseTerm(t, c, gates)

	// Each node records term 5 naming itself — the contested tenure. The witness
	// gets neither claim, so it answers 0 and contributes an answer without
	// contributing a holder.
	seedTermOn(t, a, 5, a.Name)
	seedTermOn(t, b, 5, b.Name)

	for _, tc := range []struct {
		exec      *Node
		recorded  string
		displaced string
	}{
		{a, a.Name, b.Name},
		{b, b.Name, a.Name},
	} {
		if _, reason, err := tc.exec.Server.LeaseTermGateForPendingProof(
			ctx, rescheduleProofAt(5, tc.recorded)); err != nil {
			t.Errorf("%s refused the claimant it RECORDED at term 5 (%q: %v). The legitimate "+
				"holder's own work must proceed", tc.exec.Name, reason, err)
		}
		if _, _, err := tc.exec.Server.LeaseTermGateForPendingProof(
			ctx, rescheduleProofAt(5, tc.displaced)); err == nil {
			t.Errorf("%s ACCEPTED %q at term 5 while it recorded %q as the holder. Both nodes "+
				"claimed one tenure, so accepting either claimant is how two coordinators "+
				"both act on one lease — the threshold arm cannot see this, only the "+
				"holder check can", tc.exec.Name, tc.displaced, tc.recorded)
		}
	}
	_ = wit
}

// TestFleet_LeaseTerm_PreLatchIsInertAcrossTheFleet: with the token unlatched, a
// proof that enforcement WOULD refuse passes exactly as it does today.
//
// This is the rollout contract. The fleet spends the whole of an upgrade in this
// state, and a token that started refusing before it latched would break
// failover on every cluster mid-roll.
func TestFleet_LeaseTerm_PreLatchIsInertAcrossTheFleet(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	defer c.Stop()
	exec, peer1, peer2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	gates := gateAll(t, c)
	startCheckers(t, c, gates)
	// Deliberately NOT latchLeaseTerm.

	// A ledger state the latched fleet refuses on: the executor is at 4 while a
	// quorum reports 6, so a term-5 proof is stale. Seeded so this scenario is
	// discriminating rather than vacuously green.
	seedTermOn(t, exec, 4, peer1.Name)
	for _, n := range []*Node{peer1, peer2} {
		seedTermOn(t, n, 6, peer2.Name)
	}

	fence, reason, err := exec.Server.LeaseTermGateForPendingProof(ctx, rescheduleProofAt(5, peer1.Name))
	if err != nil {
		t.Errorf("a stale-term proof was REFUSED with lease_term_v1 unlatched (%q: %v). Every "+
			"cluster is in this state for the whole of an upgrade, so refusing here breaks "+
			"failover fleet-wide mid-roll", reason, err)
	}
	if fence != nil {
		t.Errorf("an unlatched fleet returned a claim fence %+v; the claim must stay exactly "+
			"today's unfenced claim until the token latches", fence)
	}

	// Now latch it and confirm the same proof IS refused — which is what proves
	// the assertion above was about the latch and not about the fixture.
	latchLeaseTerm(t, c, gates)
	if _, _, err := exec.Server.LeaseTermGateForPendingProof(ctx, rescheduleProofAt(5, peer1.Name)); err == nil {
		t.Error("the same stale-term proof was still accepted AFTER lease_term_v1 latched, so " +
			"the pre-latch assertion above proves nothing about the gate")
	}
}

// TestFleet_LeaseTerm_ARollingUpgradeKeepsReplicating: a node that has not
// latched the ledger token emits the PREVIOUS RELEASE's proof shape, and a node
// that has latched must keep applying it.
//
// This is the mixed-version window, driven as a real cross-node apply rather
// than as a local ledger lookup. Widening the proof insert with lease_term and
// lease_key moved its fingerprint, and a fingerprint is a property of the
// BINARY: a receiver that stopped recognising the narrow form would not degrade,
// it would reject the apply, roll the batch back and stall that peer's
// replication watermark — head-of-line blocking the stream into it.
//
// The two directions are not symmetric and only this one is safe, which is why
// the emitter is gated: the narrow shape is understood by BOTH builds, the wide
// one only by the new build.
func TestFleet_LeaseTerm_ARollingUpgradeKeepsReplicating(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	old, upgraded := c.Nodes[0], c.Nodes[1]

	// `old` stands for a node whose lease_term_ledger_v1 has not latched — a
	// host mid-roll, or one held back. Its writes must stay on the shape every
	// build can resolve.
	old.DB.SetLeaseTermLedgerGate(func() bool { return false })

	proof := corrosion.ActionProof{
		ID: "p-rolling", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: upgraded.Name, Coordinator: old.Name,
	}
	if err := corrosion.WriteActionProof(ctx, old.DB, proof); err != nil {
		t.Fatalf("write a proof on the un-latched node: %v", err)
	}

	// The statement it put on the wire must not name the term columns, or the
	// peer cannot resolve its fingerprint.
	rows, err := old.DB.Query(ctx, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read the emitted mutation: rows=%d err=%v", len(rows), err)
	}
	stmts := rows[0].String("stmts")
	if strings.Contains(stmts, "lease_term") || strings.Contains(stmts, "lease_key") {
		t.Fatalf("the un-latched node emitted the WIDENED proof insert:\n%s\nA peer holding "+
			"only the previous fingerprint fails its apply closed and stalls its whole "+
			"replication stream", stmts)
	}

	// And the upgraded node must apply it.
	pumpMutations(t, c, old, upgraded)

	got, found, err := corrosion.GetActionProof(ctx, upgraded.DB, "p-rolling")
	if err != nil {
		t.Fatalf("read the replicated proof on %s: %v", upgraded.Name, err)
	}
	if !found {
		t.Fatal("the upgraded node did not apply the previous release's proof shape. Its apply " +
			"fails CLOSED, so the batch rolls back and the sending peer's watermark stalls — " +
			"every later statement on that stream is head-of-line blocked")
	}
	if got.LeaseTerm != 0 || got.LeaseKey != "" {
		t.Errorf("the applied proof carries term %d key %q, want 0/\"\" — the omitted columns "+
			"must take their DEFAULTs, which are the minted-without-a-term sentinels",
			got.LeaseTerm, got.LeaseKey)
	}
}

// TestFleet_LeaseTerm_AMixedGateClusterKeepsLeasesMoving: a node that cannot
// mint must still take and KEEP the lease, including over a term another node
// recorded.
//
// This is the state a gate-closed takeover lands in, and it is reachable
// without any fault: per-node marker files mean the latch forms per node, so
// during any roll some nodes mint and some do not. The previous holder minted a
// term while its own gate was open, then let the lease lapse.
//
// The renewals are the property, not the takeover — the takeover always worked.
// A classification that fails closed on "a peer's term is newer than ours" is
// right when this node can mint, because minting there would promote the loser
// of a term race above its winner. A node that mints NOTHING has no escalation
// to prevent, and refusing there reported the lease lost while its own
// leader_election row still named it — so the lease was neither renewed nor
// transferable, and failover, rebalancing and dual-run detection all stood down
// for most of every TTL, indefinitely.
//
// Only a fleet test reaches this: it needs one node's ledger to carry another
// node's term, which is a replicated fact.
func TestFleet_LeaseTerm_AMixedGateClusterKeepsLeasesMoving(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	minter, gateClosed := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// The minting node takes the lease and records term 1.
	held, term, err := corrosion.AcquireLeaseWithTerm(ctx, minter.DB, leaseTermKey, minter.Name, 30*time.Second, now)
	if err != nil || !held || term != 1 {
		t.Fatalf("%s acquire: held=%v term=%d err=%v", minter.Name, held, term, err)
	}
	// Its claim reaches the other node, whose own gate has not latched.
	pumpMutations(t, c, minter, gateClosed)
	if holder, ok := leaseTermHolderAt(t, gateClosed, 1); !ok || holder != minter.Name {
		t.Fatalf("%s did not receive term 1 (holder=%q ok=%v); the rest of this scenario is "+
			"vacuous", gateClosed.Name, holder, ok)
	}
	gateClosed.DB.SetLeaseTermLedgerGate(func() bool { return false })

	// The minter's lease lapses and the gate-closed node takes it over.
	lapsed := now.Add(2 * time.Minute)
	held, term, err = corrosion.AcquireLeaseWithTerm(ctx, gateClosed.DB, leaseTermKey, gateClosed.Name, 30*time.Second, lapsed)
	if err != nil || !held {
		t.Fatalf("gate-closed takeover: held=%v err=%v", held, err)
	}
	if term != 0 {
		t.Errorf("gate-closed takeover reported term %d, want 0 — this node cannot record a "+
			"tenure, so it has no term to claim", term)
	}

	for i, at := range []time.Time{
		lapsed.Add(time.Second), lapsed.Add(2 * time.Second), lapsed.Add(3 * time.Second),
	} {
		held, term, err = corrosion.AcquireLeaseWithTerm(ctx, gateClosed.DB, leaseTermKey, gateClosed.Name, 30*time.Second, at)
		if err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
		if !held {
			t.Fatalf("renewal %d reported the lease LOST while %s still holds the row and the "+
				"ledger's newest term names %s. Nothing can take it either — the upsert "+
				"needs it expired or its own — so all three consumers stop until it lapses",
				i+1, gateClosed.Name, minter.Name)
		}
		if term != 0 {
			t.Errorf("renewal %d reported term %d; %s's term is not this node's to report",
				i+1, term, minter.Name)
		}
	}

	// Nothing was written to the ledger: the gate withholds the mint, not the lease.
	if holder, ok := leaseTermHolderAt(t, gateClosed, 2); ok {
		t.Errorf("a gate-closed node minted term 2 (holder %q); its statement shape is one a "+
			"previous-release peer cannot resolve", holder)
	}
}
