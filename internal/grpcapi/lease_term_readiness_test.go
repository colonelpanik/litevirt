package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedVotingHosts inserts n active hosts, which is what QuorumProof and the
// readiness threshold both count.
//
// Through corrosion.InsertHost rather than a hand-written INSERT: the hosts
// table has NOT NULL columns a hand-written one silently omits (address, for
// one), and a fixture that spells the schema itself drifts from it.
func seedVotingHosts(t *testing.T, db *corrosion.Client, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name:    fmt.Sprintf("node-%d", i),
			Address: fmt.Sprintf("10.0.0.%d", i+1),
			State:   "active",
		}); err != nil {
			t.Fatalf("seed host %d: %v", i, err)
		}
	}
}

// leaseTermServer is a node whose lease-term readiness is satisfied except for
// whatever the caller breaks: three voting hosts, a readable ledger, and the
// split-brain gate latched.
func leaseTermServer(t *testing.T, votingHosts int) *Server {
	t.Helper()
	s := inventoryServer(t)
	seedVotingHosts(t, s.db, votingHosts)
	s.SetGate(fakeServerGate{
		enforcedTok: map[string]bool{capabilities.SplitBrainGateV1: true},
	})
	return s
}

// forceUnresolvedTie contests one (key, term) so immutableMergeKeepLocalRow
// records a ledger conflict — the same shape two partitioned nodes produce.
//
// It needs no new corrosion API. Two partitioned nodes each acquiring the lease
// is just two Clients calling the real AcquireLeaseWithTerm: a fresh Client has
// an empty ledger, so both compute term 1 and name themselves holder. The
// repair that follows is the real anti-entropy merge, so this exercises
// immutableMergeKeepLocalRow rather than asserting against a hand-built row
// shape that can drift from it.
func forceUnresolvedTie(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	if held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, db, corrosion.LeaseKeyFailover, "node-a", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	peer := peerClient(t)
	if held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, peer, corrosion.LeaseKeyFailover, "node-b", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("peer acquire: held=%v term=%d err=%v", held, term, err)
	}
	if err := db.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy peer→local: %v", err)
	}
}

// TestLeaseTermReadiness_WithholdsBelowThreeVotingHosts.
//
// With quorum at liveHosts/2+1, a 2-host cluster needs BOTH hosts, so one peer
// down refuses every protected action — and failover exists for exactly that
// case. Latching on 2 hosts makes failover non-functional the first time it is
// needed, so that configuration must not be reachable. A 1-host cluster
// self-satisfies quorum and gains nothing, so one rule covers both.
func TestLeaseTermReadiness_WithholdsBelowThreeVotingHosts(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		hosts     int
		wantReady bool
	}{{1, false}, {2, false}, {3, true}, {4, true}} {
		s := leaseTermServer(t, tc.hosts)
		ready, reason := s.LeaseTermReadiness(ctx)
		if ready != tc.wantReady {
			t.Errorf("%d voting hosts: ready=%v (%s), want %v", tc.hosts, ready, reason, tc.wantReady)
		}
	}
}

// TestLeaseTermReadiness_DoesNotWithholdOnUnresolvedTies is the one predicate
// that must NOT be copied from OwnerEpochReadiness, and it needs a test because
// its ABSENCE reads as an oversight a future reader will helpfully "fix".
//
// A contested lease term is the fault this table exists to record. Phase 1's
// keep-local merge flags it via trackUnresolved, and because the row never
// converges and is never rewritten, the tie persists until an operator
// acknowledges it. Withholding on it would disable enforcement at the exact
// moment two nodes claimed one tenure.
func TestLeaseTermReadiness_DoesNotWithholdOnUnresolvedTies(t *testing.T) {
	ctx := context.Background()
	s := leaseTermServer(t, 3)
	forceUnresolvedTie(t, s.db)

	if n := s.db.UnresolvedTieCount(); n == 0 {
		t.Fatal("the fixture did not produce an unresolved tie; the test would pass vacuously")
	}
	ready, reason := s.LeaseTermReadiness(ctx)
	if !ready {
		t.Errorf("readiness withheld with an unresolved tie outstanding (%s). A contested term is "+
			"the event this regime exists to surface; withholding on it disables enforcement "+
			"exactly when it is needed", reason)
	}
}

// TestLeaseTermReadiness_WithholdsWhenTheLedgerIsUnreadable: a node that cannot
// read its own ledger cannot enforce against it, and must not let the fleet
// latch across it.
func TestLeaseTermReadiness_WithholdsWhenTheLedgerIsUnreadable(t *testing.T) {
	ctx := context.Background()
	s := leaseTermServer(t, 3)
	if err := s.db.Execute(ctx, `DROP TABLE leader_lease_terms`); err != nil {
		t.Fatalf("drop ledger: %v", err)
	}
	if ready, reason := s.LeaseTermReadiness(ctx); ready {
		t.Errorf("readiness advertised with an unreadable lease ledger (reason=%q)", reason)
	}
}

// TestLeaseTermReadiness_WithholdsWithoutTheSplitBrainLatch pins a dependency
// that was invisible, and was found by review rather than by design.
//
// Lease-term enforcement lives inside claimCarriedProof, whose first statement
// is `if p == nil { return "", nil }` — a proofless call is not gated there at
// all. Whether a proofless call is refused is decided by a DIFFERENT token:
// `automated && req.Proof == nil && s.gateActive(ctx)`, which is
// split_brain_gate_v1. So on a node without that latch, lease_term_v1 would
// advertise and "enforce" while every protected RPC arriving without a proof
// sailed through ungated — the node reporting a regime it was not providing.
//
// Checked with Latched, NOT Enforced: readiness runs inside the Ping handler
// and Enforced may fresh-Ping, which recurses (see hardwareV2Ready).
func TestLeaseTermReadiness_WithholdsWithoutTheSplitBrainLatch(t *testing.T) {
	ctx := context.Background()
	s := leaseTermServer(t, 3)
	s.SetGate(fakeServerGate{}) // nothing latched

	ready, reason := s.LeaseTermReadiness(ctx)
	if ready {
		t.Error("readiness advertised without the split-brain latch; a proofless call is refused " +
			"by THAT token, so this node would report enforcement it does not provide")
	}
	if !stringsContains(reason, capabilities.SplitBrainGateV1) {
		t.Errorf("withhold reason = %q, want it to name %s", reason, capabilities.SplitBrainGateV1)
	}
}

// TestLeaseTermReadiness_WithholdsWithNoGate: no gate wired means nothing can
// confirm the dependency above, which fails closed like every other unknown.
func TestLeaseTermReadiness_WithholdsWithNoGate(t *testing.T) {
	s := leaseTermServer(t, 3)
	s.gate = nil
	if ready, _ := s.LeaseTermReadiness(context.Background()); ready {
		t.Error("readiness advertised with no gate wired")
	}
}

// TestLeaseTermEnforced_RequiresBothFlagAndLatch pins the reversible model: the
// latch is one-way, so the config flag is the operator's only way out of a
// cluster that has shrunk below three hosts after latching.
func TestLeaseTermEnforced_RequiresBothFlagAndLatch(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ flag, latch, want bool }{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, true},
	} {
		s := inventoryServer(t)
		s.SetLeaseTermEnforce(tc.flag)
		s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.LeaseTermV1: tc.latch}})
		if got := s.leaseTermEnforced(ctx); got != tc.want {
			t.Errorf("flag=%v latch=%v → %v, want %v", tc.flag, tc.latch, got, tc.want)
		}
	}
}

// TestAdvertisedCapabilities_WithholdsLeaseTermUntilFlagAndReady: the token is
// what makes the fleet latch, so advertising it before this node can honour it
// is how a cluster latches across a member that will refuse recovery.
func TestAdvertisedCapabilities_WithholdsLeaseTermUntilFlagAndReady(t *testing.T) {
	advertises := func(s *Server) bool {
		for _, c := range s.advertisedCapabilities() {
			if c == capabilities.LeaseTermV1 {
				return true
			}
		}
		return false
	}

	// Flag off, readiness satisfied.
	s := leaseTermServer(t, 3)
	s.SetLeaseTermReady(func() bool { return true })
	if advertises(s) {
		t.Error("advertised lease_term_v1 with enforcement.lease_term off; the latch requires " +
			"config uniformity, or the cluster enforces across a node that opted out")
	}

	// Flag on, readiness withheld.
	s = leaseTermServer(t, 3)
	s.SetLeaseTermEnforce(true)
	s.SetLeaseTermReady(func() bool { return false })
	if advertises(s) {
		t.Error("advertised lease_term_v1 while readiness was withheld")
	}

	// Flag on, no probe wired at all — nil must not read as ready.
	s = leaseTermServer(t, 3)
	s.SetLeaseTermEnforce(true)
	if advertises(s) {
		t.Error("advertised lease_term_v1 with no readiness probe wired; nil must fail closed")
	}

	// Both satisfied.
	s = leaseTermServer(t, 3)
	s.SetLeaseTermEnforce(true)
	s.SetLeaseTermReady(func() bool { return true })
	if !advertises(s) {
		t.Error("withheld lease_term_v1 with the flag on and readiness satisfied; the fleet could " +
			"never latch")
	}
}

// TestTokenEnabled_KnowsLeaseTerm: tokenEnabled is what the HA monitor's
// latch-driver consults to decide which tokens to drive, so a token missing
// from its switch is a token that never latches — and it defaults to false
// silently.
func TestTokenEnabled_KnowsLeaseTerm(t *testing.T) {
	s := inventoryServer(t)
	if s.tokenEnabled(capabilities.LeaseTermV1) {
		t.Error("tokenEnabled reported lease_term_v1 enabled with the flag off")
	}
	s.SetLeaseTermEnforce(true)
	if !s.tokenEnabled(capabilities.LeaseTermV1) {
		t.Error("tokenEnabled does not know lease_term_v1, so the latch-driver would never " +
			"drive it and the token could never activate")
	}
}

// TestLeaseTermReadiness_WithholdsWhileTheLedgerGateIsClosed: enforcement
// decides ON terms, so a node that mints none must not advertise readiness to
// enforce. If it did, the fleet would latch and then refuse every reschedule
// this node coordinates — the executor refuses term 0, and term 0 is all a
// node with a closed mint gate can produce.
//
// The predicate reads the mint gate itself (corrosion.MayMintLeaseTerm) rather
// than re-deriving DurablyLatched, so readiness cannot drift from what the
// writer actually does.
func TestLeaseTermReadiness_WithholdsWhileTheLedgerGateIsClosed(t *testing.T) {
	s := leaseTermServer(t, 3)
	s.db.SetLeaseTermLedgerGate(func() bool { return false })

	ready, reason := s.LeaseTermReadiness(context.Background())
	if ready {
		t.Fatal("ready while the term ledger is not writable; the fleet would latch " +
			"enforcement onto a node that mints nothing to enforce on")
	}
	if !strings.Contains(reason, capabilities.LeaseTermLedgerV1) {
		t.Errorf("reason = %q; it must name %s so an operator knows the roll is what "+
			"is outstanding, not the config", reason, capabilities.LeaseTermLedgerV1)
	}
}

// TestLeaseTermReadiness_ReadyOnceTheLedgerGateOpens is the positive half: the
// gate is the ONLY thing the test above changes, so a green result here proves
// the refusal came from that predicate and not from an incidentally broken
// fixture.
func TestLeaseTermReadiness_ReadyOnceTheLedgerGateOpens(t *testing.T) {
	s := leaseTermServer(t, 3)
	s.db.SetLeaseTermLedgerGate(func() bool { return true })

	if ready, reason := s.LeaseTermReadiness(context.Background()); !ready {
		t.Fatalf("not ready with the ledger gate open: %s", reason)
	}
}

// TestLeaseTermLedgerToken_HasNoKillSwitch: the ledger token must report enabled
// with no config flag set. activateOneUnlatched skips an UNLATCHED token whose
// tokenEnabled is false, so a flag-gated ledger token would never latch, no term
// would ever be minted, and the whole mechanism would sit inert with nothing in
// the logs to say why.
func TestLeaseTermLedgerToken_HasNoKillSwitch(t *testing.T) {
	s := testServer(t)
	if !s.tokenEnabled(capabilities.LeaseTermLedgerV1) {
		t.Fatal("tokenEnabled(lease_term_ledger_v1) = false on a server with no enforcement " +
			"flags set; the latch would never be driven and terms would never be minted")
	}
}
