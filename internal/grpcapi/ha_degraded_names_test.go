package grpcapi

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// tokensOf reduces the degraded list to its token names, for the assertions that
// are about membership rather than cause.
func tokensOf(cs []degradedCapability) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Token)
	}
	return out
}

// causeOf returns the cause recorded for one token, or "" if absent.
func causeOf(cs []degradedCapability, token string) string {
	for _, c := range cs {
		if c.Token == token {
			return c.Cause
		}
	}
	return ""
}

// TestEvaluateHADegraded_NamesTheDegradedTokens pins that the evaluation says
// WHICH capability is unconfirmed, not merely that one is.
//
// Every configured-to-enforce token collapses into the single reason string
// `unsupported_member`, and the remedies behind it have nothing in common —
// finish a rollout, re-enable a flag, reseed a rolled-back peer. A reason with
// no token is an alert that tells an operator to go and find out what it means.
//
// The fixture is a POST-LATCH regression deliberately: a token that latched and
// then had a peer stop advertising it. That case reads latched=1, so it is the
// one an operator cannot recover from the existing config/latch gauges.
func TestEvaluateHADegraded_NamesTheDegradedTokens(t *testing.T) {
	ctx := context.Background()
	g := &recordingGate{}
	// Both configured-on tokens are already latched; lww's peer support then
	// regressed, so Latched stays true while the freshness check reports false.
	g.latched = map[string]bool{
		capabilities.SplitBrainGateV1: true,
		capabilities.LWWSkewGuardV1:   true,
	}
	g.enforcedTok = map[string]bool{
		capabilities.SplitBrainGateV1: true,
		capabilities.LWWSkewGuardV1:   false, // regressed: a peer stopped advertising
	}
	s := testServer(t)
	s.gate = g
	s.SetEnforcementConfig(false, true, false, false, false, false) // lww configured-on

	for i := 0; i < 4; i++ {
		s.driveCapabilityActivation(ctx)
		s.checkOneCapabilityHealth(ctx)
	}

	reasons, degraded := s.evaluateHADegraded(ctx)
	tokens := tokensOf(degraded)
	if !reasons[haUnsupportedMember] {
		t.Fatalf("fixture did not reach the degraded state; reasons %v", reasons)
	}
	if !slices.Contains(tokens, capabilities.LWWSkewGuardV1) {
		t.Errorf("unsupported_member is raised but %s is not named: %v — the operator is "+
			"told something is unconfirmed and left to work out what",
			capabilities.LWWSkewGuardV1, tokens)
	}
	// A token this node does not enforce must never appear: it is not degraded,
	// it is switched off, and naming it would send an operator after a
	// non-problem.
	if slices.Contains(tokens, capabilities.HLCLwwV1) {
		t.Errorf("a token this node is not configured to enforce is named as degraded: %v", tokens)
	}
	if !slices.IsSorted(tokens) {
		t.Errorf("token list is unsorted (%v), so an unchanged set can compare unequal "+
			"between cycles and republish forever", tokens)
	}
}

// TestHADegradedDetail_NamesTokens pins the operator-facing string. The event is
// what reaches a webhook and the event stream, so this is where the token names
// have to land to be useful.
func TestHADegradedDetail_NamesTokens(t *testing.T) {
	tokens := []degradedCapability{
		{Token: capabilities.LWWSkewGuardV1, Cause: "activation_pending"},
		{Token: capabilities.SafeFenceDefaultV1, Cause: health.ReasonUnsupportedCapability},
	}
	got := haDegradedDetail(haUnsupportedMember, "kvm001", tokens)
	for _, want := range []string{haUnsupportedMember, "kvm001", capabilities.LWWSkewGuardV1,
		capabilities.SafeFenceDefaultV1, "activation_pending", health.ReasonUnsupportedCapability} {
		if !strings.Contains(got, want) {
			t.Errorf("detail %q does not name %q", got, want)
		}
	}

	// Other reasons are single conditions and carry no token list; appending an
	// empty one would leave a dangling "()" in the alert text.
	// THE row this test was missing. It only ever passed nil for a non-capability
	// reason, which exercises the len()==0 branch — so deleting the
	// `reason != haUnsupportedMember ||` guard left the whole package green.
	// That guard is the only thing stopping the call site, which hands the live
	// list to every reason, from attaching capability tokens to vip_no_holder —
	// one of the two reasons that DOES raise a notify page at SevError.
	if got := haDegradedDetail(haVIPNoHolder, "kvm001", tokens); strings.Contains(got, capabilities.LWWSkewGuardV1) {
		t.Errorf("a VIP-outage page names unrelated capability tokens: %q", got)
	}
	if got := haDegradedDetail(haVIPNoHolder, "", nil); got != "HA degraded: "+haVIPNoHolder {
		t.Errorf("non-capability reason detail = %q, want the plain form", got)
	}
	// unsupported_member with nothing to name must degrade to the plain form too,
	// rather than printing empty parentheses.
	if got := haDegradedDetail(haUnsupportedMember, "", nil); strings.Contains(got, "(") {
		t.Errorf("empty token list still rendered parentheses: %q", got)
	}
}

// TestDegradedSetChanged pins when an already-degraded reason is republished.
//
// Without this, a second capability going degraded while the first still is
// changes nothing observable: the gauge is already 1 and the on-edge has passed,
// so the second incident lands silently in the middle of the first — exactly
// when someone is already looking at the wrong capability.
func TestDegradedSetGrew(t *testing.T) {
	cap := func(tok string) degradedCapability {
		return degradedCapability{Token: tok, Cause: "activation_pending"}
	}
	a := []degradedCapability{cap(capabilities.LWWSkewGuardV1)}
	b := []degradedCapability{cap(capabilities.SafeFenceDefaultV1)}
	ab := []degradedCapability{cap(capabilities.LWWSkewGuardV1), cap(capabilities.SafeFenceDefaultV1)}

	for _, tc := range []struct {
		name             string
		reason           string
		on, was          bool
		cur, prev        []degradedCapability
		want             bool
		whyItWouldMatter string
	}{
		{"a second token joins", haUnsupportedMember, true, true, ab, a, true,
			"the new incident is invisible during the old one"},
		// The row whose absence made this test vacuous. Every other row changes
		// LENGTH, so `len(cur) != len(prev)` passed all of them — and a
		// constant-size swap is the routine case, since the one-token-per-cycle
		// round-robin regularly flips one token healthy and another degraded
		// inside the same window. Under a length comparison the standing alert
		// keeps naming the recovered token while the newly-degraded one is
		// unnamed: the exact silent second incident this function prevents.
		{"one token swaps for another at the same size", haUnsupportedMember, true, true, b, a, true,
			"the alert keeps naming the token that recovered and never names the one that broke"},
		{"a token recovers, one remains", haUnsupportedMember, true, true, a, ab, false,
			"a shrinking set is ordinary progress; a fresh node latching a dozen tokens " +
				"one per cycle would walk a staircase of events down to zero"},
		{"same set, nothing new", haUnsupportedMember, true, true, a, a, false,
			"republishing every cycle turns a durable alert into a stream"},
		{"not yet degraded", haUnsupportedMember, true, false, a, nil, false,
			"the plain on-edge already publishes this; both would double-fire"},
		{"recovered", haUnsupportedMember, false, true, nil, a, false,
			"the recovery branch owns this transition"},
		{"another reason entirely", haVIPNoHolder, true, true, ab, a, false,
			"single-condition reasons have no token set; republishing them is noise"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := degradedSetGrew(tc.reason, tc.on, tc.was, tc.cur, tc.prev); got != tc.want {
				t.Errorf("degradedSetGrew = %v, want %v — %s", got, tc.want, tc.whyItWouldMatter)
			}
		})
	}
}

// starvationGate models the state the old priority rule could not survive: a
// configured token that never latches, alongside one that does. It records the
// freshness checks so a test can prove they still happen.
type starvationGate struct {
	fakeServerGate
	mu          sync.Mutex
	latched     map[string]bool
	neverLatch  map[string]bool
	freshChecks []string
}

func (g *starvationGate) Enforced(_ context.Context, token string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.neverLatch[token] {
		return false // a peer that will not support it — pending, not broken
	}
	if g.latched == nil {
		g.latched = map[string]bool{}
	}
	g.latched[token] = true
	return true
}

func (g *starvationGate) Latched(token string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.latched[token]
}

func (g *starvationGate) CapabilityActiveForHealth(_ context.Context, token string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.freshChecks = append(g.freshChecks, token)
	return true, ""
}

func (g *starvationGate) checks() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.freshChecks)
}

// TestSpendOnePeerOp_PendingTokenCannotStarveTheFreshnessCheck pins the fairness
// rule, and it is not a hypothetical: enabling a capability against a peer that
// does not yet support it is the ordinary mid-rollout state.
//
// The two duties share one peer op per cycle. Giving activation unconditional
// priority reads as an obvious ordering — latch first, verify later — but
// driveCapabilityActivation returns "I spent the budget", not "I succeeded". So
// a token that never latches spends every cycle forever, the freshness check
// never runs, and a post-latch REGRESSION on any other token becomes
// undetectable — disabling the one check that exists to catch what the one-way
// durable latch cannot.
func TestSpendOnePeerOp_PendingTokenCannotStarveTheFreshnessCheck(t *testing.T) {
	ctx := context.Background()
	g := &starvationGate{neverLatch: map[string]bool{capabilities.LWWSkewGuardV1: true}}
	s := testServer(t)
	s.gate = g
	// lww configured on and never able to latch; split_brain is mandatory and latches.
	s.SetEnforcementConfig(false, true, false, false, false, false)

	freshnessTurn := false
	for i := 0; i < 6; i++ {
		freshnessTurn = s.spendOnePeerOp(ctx, freshnessTurn)
	}

	if got := g.checks(); len(got) == 0 {
		t.Errorf("six cycles with one permanently-pending token produced no freshness check at all; "+
			"a regression on any already-latched token would be invisible for as long as the "+
			"rollout takes (checks=%v)", got)
	}
	if !g.Latched(capabilities.SplitBrainGateV1) {
		t.Error("alternating starved activation instead: the latchable token never latched")
	}
}

// TestHAMonitorMetrics_DegradedFallsToZeroWhenATokenIsSwitchedOff pins the write
// discipline the gauge depends on.
//
// evaluateHADegraded skips tokens this node does not enforce, so writing the
// gauge from inside it left a feature that was degraded and then disabled
// reading 1 forever — a stuck alert about a feature nobody is running. The write
// therefore belongs with SetEnforcement, over every SUPPORTED token.
func TestHAMonitorMetrics_DegradedFallsToZeroWhenATokenIsSwitchedOff(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &recordingGate{}
	g.latched = map[string]bool{capabilities.SplitBrainGateV1: true}
	g.enforcedTok = map[string]bool{capabilities.SplitBrainGateV1: true}
	s.gate = g
	s.SetEnforcementConfig(false, true, false, false, false, false) // lww on, unlatched

	_, degraded := s.evaluateHADegraded(ctx)
	unsupported := tokensOf(degraded)
	if !slices.Contains(unsupported, capabilities.LWWSkewGuardV1) {
		t.Fatalf("fixture: %s should be degraded (configured on, not latched); got %v",
			capabilities.LWWSkewGuardV1, unsupported)
	}

	// Switch it off, as an operator standing the feature down would.
	s.SetEnforcementConfig(false, false, false, false, false, false)
	_, degraded = s.evaluateHADegraded(ctx)
	unsupported = tokensOf(degraded)
	if slices.Contains(unsupported, capabilities.LWWSkewGuardV1) {
		t.Errorf("a switched-off token is still reported degraded: %v", unsupported)
	}
	// The gauge is written from the monitor loop over Supported(), so a token
	// leaving the degraded set is written false rather than simply skipped. The
	// metrics-side contract is pinned by TestSetDegraded_SeparatesRegressionFromRollout.
}

// TestEvaluateHADegraded_QuarantinedNodeDoesNotBlameItsPeers is the other half of
// TestEvaluateHADegraded_ReportsAQuarantinedNode, and naming the tokens is what
// made it necessary.
//
// The capability sweep asks itself through a self short-circuit: PeerCapabilities
// returns advertisedCapabilities for host == self, and a WAL-quarantined node
// advertises NOTHING. So every configured token reads unconfirmed, and
// unsupported_member would fire naming the node's whole capability set — "a peer
// is on an old binary, finish your rollout" — in the same cycle as the
// rolled_back_latch that says the true thing. haReasons puts unsupported_member
// first, so the wrong alert arrives first and with names attached.
//
// The named tokens would be exactly the ones no member is failing to support:
// they are the ones THIS node stopped advertising, and the fix is a reseed.
func TestEvaluateHADegraded_QuarantinedNodeDoesNotBlameItsPeers(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &recordingGate{}
	s.gate = g
	s.SetEnforcementConfig(false, true, false, false, false, false) // lww configured on, unlatched

	reasons, degraded := s.evaluateHADegraded(ctx)
	if !reasons[haUnsupportedMember] || len(degraded) == 0 {
		t.Fatalf("fixture: a healthy node with an unlatched configured token should raise "+
			"unsupported_member; reasons=%v degraded=%v", reasons, tokensOf(degraded))
	}

	s.SetWALQuarantined(func() bool { return true })
	reasons, degraded = s.evaluateHADegraded(ctx)

	if !reasons[haRolledBackLatch] {
		t.Errorf("a quarantined node stopped reporting %s", haRolledBackLatch)
	}
	if reasons[haUnsupportedMember] {
		t.Errorf("a quarantined node also raises unsupported_member, which reads as version " +
			"skew on its PEERS and arrives before rolled_back_latch in haReasons")
	}
	if got := tokensOf(degraded); len(got) != 0 {
		t.Errorf("a quarantined node names %v as unsupported; no member is failing to support "+
			"them — they are the tokens this node stopped advertising, and the fix is a reseed "+
			"of this node, not anything on a peer", got)
	}
}

// TestDegradedCause pins the three answers apart, which is the whole point of
// carrying a cause: they demand different actions, and naming the wrong one is
// worse than naming nothing.
func TestDegradedCause(t *testing.T) {
	for _, tc := range []struct {
		name     string
		latched  bool
		recorded string
		want     string
		remedy   string
	}{
		{"not latched yet", false, "", "activation_pending",
			"normal mid-rollout; nothing to do but wait"},
		// An unlatched token reports pending even with a stale recorded cause:
		// the freshness check only runs once everything has latched, so a
		// left-over cause describes a question nobody is asking yet.
		{"not latched, stale cause recorded", false, health.ReasonUnsupportedCapability, "activation_pending",
			"a cause from an earlier cycle would describe a question nobody is asking"},
		{"latched, a peer does not advertise it", true, health.ReasonUnsupportedCapability,
			health.ReasonUnsupportedCapability, "finish the rollout on that peer"},
		{"latched, the sweep could not tell", true, health.ReasonActivationUnconfirm,
			health.ReasonActivationUnconfirm, "usually a host that is down; not a capability problem"},
		{"latched, nothing recorded", true, "", health.ReasonActivationUnconfirm,
			"absence of a reason is not evidence of support"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := degradedCause(tc.latched, tc.recorded); got != tc.want {
				t.Errorf("degradedCause(latched=%v, recorded=%q) = %q, want %q — the operator's "+
					"next step is %q", tc.latched, tc.recorded, got, tc.want, tc.remedy)
			}
		})
	}
}
