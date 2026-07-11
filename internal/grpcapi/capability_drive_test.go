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
	// (a) all flags off → only the mandatory split_brain_gate_v1 is ever driven; a
	// flag-off advertised token is NEVER driven, so it never latches (advertised ≠
	// enforcing). Run many cycles to be sure.
	g := &recordingGate{}
	s := &Server{gate: g}
	for i := 0; i < 10; i++ {
		s.driveCapabilityActivation(context.Background())
	}
	got := g.drivenUnique()
	if !got[capabilities.SplitBrainGateV1] {
		t.Error("mandatory split_brain_gate_v1 must be driven even with all flags off")
	}
	for _, tok := range capabilities.Supported() {
		if tok == capabilities.SplitBrainGateV1 {
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
	s2.SetEnforcementConfig(false /*safeFence*/, true /*lww*/, false /*vipSelfDemote*/, false /*vipProofReclaim*/)

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
