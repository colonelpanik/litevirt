package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCheckOneCapabilityHealth_DetectsPostLatchRegression proves the bounded freshness
// check surfaces a regression the one-way durable latch cannot: a token latched locally
// whose peer support later disappears. Latched stays true, but CapabilityActiveForHealth
// now returns false → evaluateHADegraded must raise unsupported_member.
func TestCheckOneCapabilityHealth_DetectsPostLatchRegression(t *testing.T) {
	ctx := context.Background()
	g := &recordingGate{}
	// Both configured-on tokens already latched; split_brain still confirms active,
	// but lww's peer support regressed (CapabilityActiveForHealth → false).
	g.latched = map[string]bool{
		capabilities.SplitBrainGateV1: true,
		capabilities.LWWSkewGuardV1:   true,
	}
	g.enforcedTok = map[string]bool{
		capabilities.SplitBrainGateV1: true,  // still active
		capabilities.LWWSkewGuardV1:   false, // regressed: a peer stopped advertising
	}
	s := testServer(t) // real db so evaluateHADegraded's stranded-pending query is safe
	s.gate = g
	s.SetEnforcementConfig(false, true, false, false) // lww configured-on

	// Nothing to latch (all latched) ⇒ each cycle spends its peer op on a freshness
	// check; round-robin covers both configured tokens within a few cycles.
	for i := 0; i < 4; i++ {
		if s.driveCapabilityActivation(ctx) {
			t.Fatal("no unlatched token should be driven when all are latched")
		}
		s.checkOneCapabilityHealth(ctx)
	}
	if got := s.evaluateHADegraded(ctx); !got[haUnsupportedMember] {
		t.Fatalf("a post-latch regression on lww must raise unsupported_member; got %v", got)
	}
}
