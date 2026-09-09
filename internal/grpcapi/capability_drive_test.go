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
