package grpcapi

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// recordingGate records the tokens Enforced() was called with and models the durable
// latch: once Enforced confirms a token it stays Latched (mirroring health.Checker).
// Only the methods driveCapabilityActivation exercises are meaningful; the rest come
// from the embedded fakeServerGate.
type recordingGate struct {
	fakeServerGate
	mu       sync.Mutex
	enforced []string
	latched  map[string]bool
}

func (g *recordingGate) Enforced(_ context.Context, token string) bool {
	g.mu.Lock()
	g.enforced = append(g.enforced, token)
	if g.latched == nil {
		g.latched = map[string]bool{}
	}
	g.latched[token] = true
	g.mu.Unlock()
	return true
}

func (g *recordingGate) Latched(token string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.latched[token]
}

// DurablyLatched mirrors Latched: this fake models the durable latch directly
// (see the type comment), so once Enforced confirms a token it is both
// latched and durable.
func (g *recordingGate) DurablyLatched(token string) bool { return g.Latched(token) }

func (g *recordingGate) drivenUnique() map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]bool{}
	for _, t := range g.enforced {
		out[t] = true
	}
	return out
}

// TestDriveCapabilityActivation_FlagAwareBoundedDriver covers the monitor-as-latch-driver:
// it drives Enforced (the only latching path) for the mandatory token and any config-on
// optional token, never for an advertised-but-disabled token, and at most one still-
// unlatched token per cycle (bounded pre-latch fan-out).
func TestDriveCapabilityActivation_FlagAwareBoundedDriver(t *testing.T) {
	// (a) all flags off → only the tokens with NO kill switch are ever driven; a
	// flag-off advertised token is NEVER driven, so it never latches (advertised ≠
	// enforcing). Run many cycles to be sure.
	//
	// The flag-less set is deliberately spelled out rather than derived from
	// tokenEnabled: deriving it would make this assertion a tautology that passes
	// however many tokens quietly become mandatory. Adding one here is a decision
	// to be made once, in the open — each entry drives a latch on every cluster
	// with no operator opt-in.
	mandatory := map[string]bool{
		capabilities.SplitBrainGateV1: true,
		// lease_term_ledger_v1 has no flag because it states a fact about the
		// BINARY — "this build can decode the term ledger's statement shapes" —
		// which no operator should be able to misreport. See its comment in
		// internal/capabilities.
		capabilities.LeaseTermLedgerV1: true,
	}

	g := &recordingGate{}
	s := &Server{gate: g}
	for i := 0; i < 10; i++ {
		s.driveCapabilityActivation(context.Background())
	}
	got := g.drivenUnique()
	for tok := range mandatory {
		if !got[tok] {
			t.Errorf("kill-switch-free token %q was never driven; it must latch with all flags off", tok)
		}
	}
	for _, tok := range capabilities.Supported() {
		if mandatory[tok] {
			continue
		}
		if got[tok] {
			t.Errorf("flag-off token %q was driven — it must not latch until configured-on", tok)
		}
	}

	// (b) lww flag on → split_brain (first unlatched in order) latches cycle 1; the
	// one-unlatched-per-cycle bound means lww latches only by cycle 2.
	g2 := &recordingGate{}
	s2 := &Server{gate: g2}
	s2.SetEnforcementConfig(false /*safeFence*/, true /*lww*/, false /*hlcLww*/, false /*vipSelfDemote*/, false /*vipProofReclaim*/, false /*sharedStorageFence*/)

	s2.driveCapabilityActivation(context.Background())
	if !g2.Latched(capabilities.SplitBrainGateV1) {
		t.Error("split_brain_gate_v1 should latch on cycle 1")
	}
	if g2.Latched(capabilities.LWWSkewGuardV1) {
		t.Error("lww latched on cycle 1 — the one-unlatched-per-cycle bound was violated")
	}
	s2.driveCapabilityActivation(context.Background())
	if !g2.Latched(capabilities.LWWSkewGuardV1) {
		t.Error("lww should latch by cycle 2 (one interval per unlatched token)")
	}
}

// stubbornGate is recordingGate where the named tokens never confirm: Enforced
// records the attempt and returns false, leaving them unlatched forever. That is
// not a fault — a config-uniformity token switched on here but not yet on one
// peer behaves exactly this way for the whole of a staged rollout.
type stubbornGate struct {
	recordingGate
	stuck map[string]bool
}

func (g *stubbornGate) Enforced(ctx context.Context, token string) bool {
	if g.stuck[token] {
		g.mu.Lock()
		g.enforced = append(g.enforced, token)
		g.mu.Unlock()
		return false
	}
	return g.recordingGate.Enforced(ctx, token)
}

// TestActivateOneUnlatched_AStuckTokenDoesNotStarveTheOnesAfterIt: the drive
// must rotate.
//
// It used to restart at index 0 every cycle and take the first unlatched
// enabled token it found, so a token that cannot currently confirm absorbed
// every cycle and nothing after it in Supported() was ever driven. The only
// caller of Enforced for lease_term_ledger_v1 is this drive — the mint gate and
// readiness both read DurablyLatched, which never latches anything — so a
// starved token means no term is ever minted, on a cluster that looks healthy
// and logs nothing about it. split_brain_gate_v1 was immune only by being first
// in the slice.
func TestActivateOneUnlatched_AStuckTokenDoesNotStarveTheOnesAfterIt(t *testing.T) {
	g := &stubbornGate{stuck: map[string]bool{capabilities.SplitBrainGateV1: true}}
	s := &Server{gate: g}

	// Generously more cycles than Supported() is long, so a rotating drive
	// reaches everything and a restarting one still reaches only the first.
	for i := 0; i < 4*len(capabilities.Supported()); i++ {
		s.activateOneUnlatched(context.Background())
	}

	if !g.Latched(capabilities.LeaseTermLedgerV1) {
		t.Errorf("lease_term_ledger_v1 never latched across %d cycles while %q sat unconfirmable. "+
			"It is 21st in Supported() behind ten flag-gated tokens, and this drive is its "+
			"only activation path — starved, the ledger stays unwritable forever with "+
			"nothing in the logs", 4*len(capabilities.Supported()), capabilities.SplitBrainGateV1)
	}
	if g.Latched(capabilities.SplitBrainGateV1) {
		t.Error("the stuck token latched; the fixture is not reproducing an unconfirmable token")
	}
}

// TestSpendCapabilityPeerOp_FreshnessRunsWhileActivationIsStuck: the freshness
// axis must not be starved by the activation axis.
//
// checkOneCapabilityHealth used to run only when activation had nothing to
// drive. That held while the only flag-less token was split_brain_gate_v1,
// which latches on any homogeneous fleet, so the drive reached a fixed point.
// A mandatory token that cannot latch until the last host is upgraded makes the
// drive claim every cycle for the whole roll — and permanently on a cluster
// deliberately held with one host back, which the operating model blesses as
// by-design. checkOneCapabilityHealth is the ONLY post-latch regression
// detector, so a peer that rolls back or stops advertising an already-latched
// token went undetected, and capHealthLast stayed empty long enough that
// evaluateHADegraded's `latched && (!checked || lastOK)` degenerated to
// `latched`.
func TestSpendCapabilityPeerOp_FreshnessRunsWhileActivationIsStuck(t *testing.T) {
	g := &stubbornGate{stuck: map[string]bool{capabilities.SplitBrainGateV1: true}}
	s := &Server{gate: g}

	for i := 0; i < 2*capFreshnessReserveEvery; i++ {
		s.spendCapabilityPeerOp(context.Background())
	}

	s.capHealthMu.Lock()
	checked := len(s.capHealthLast)
	s.capHealthMu.Unlock()

	if checked == 0 {
		t.Errorf("no capability freshness check ran in %d cycles while activation was stuck; "+
			"post-latch regression detection is off for the whole roll, and "+
			"evaluateHADegraded then treats `latched` alone as healthy",
			2*capFreshnessReserveEvery)
	}
}

// TestDriveCapabilityActivation_LatchedRetriesDespiteFlagOff proves the reorder that makes canonical
// registry acceptance become DURABLE: an ALREADY-latched token is driven (Enforced → retry marker
// persistence) even when its config flag is now OFF, so a marker that hasn't persisted yet still
// sticks. An UNlatched flag-off token is still never driven.
func TestDriveCapabilityActivation_LatchedRetriesDespiteFlagOff(t *testing.T) {
	// canonical_registry_v1 already latched in memory; its config flag is OFF.
	g := &recordingGate{latched: map[string]bool{capabilities.CanonicalRegistryV1: true}}
	s := &Server{gate: g} // enfCanonicalRegistry defaults false ⇒ tokenEnabled(canonical_registry_v1)=false
	for i := 0; i < 3; i++ {
		s.driveCapabilityActivation(context.Background())
	}
	got := g.drivenUnique()
	if !got[capabilities.CanonicalRegistryV1] {
		t.Error("an already-latched token must be driven (retry persist) even with its flag off")
	}
	if got[capabilities.CanonicalIdentityV1] {
		t.Error("an unlatched flag-off token must not be driven")
	}
}
