package grpcapi

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// recordingGate records the tokens Enforced() was called with. Only the methods
// exercised by driveCapabilityActivation are meaningful; the rest satisfy serverGate.
type recordingGate struct {
	fakeServerGate
	mu       sync.Mutex
	enforced []string
}

func (g *recordingGate) Enforced(_ context.Context, token string) bool {
	g.mu.Lock()
	g.enforced = append(g.enforced, token)
	g.mu.Unlock()
	return true
}

// TestDriveCapabilityActivation_DrivesEverySupportedToken proves the fix for the
// lww_skew_guard_v1 activation gap: the HA monitor drives Enforced (the latching path)
// for every supported token, so a token whose only consumer reads the cheap
// Latched() still gets its first-time activation driven.
func TestDriveCapabilityActivation_DrivesEverySupportedToken(t *testing.T) {
	g := &recordingGate{}
	s := &Server{gate: g}
	s.driveCapabilityActivation(context.Background())

	g.mu.Lock()
	defer g.mu.Unlock()
	got := map[string]bool{}
	for _, tok := range g.enforced {
		got[tok] = true
	}
	for _, want := range capabilities.Supported() {
		if !got[want] {
			t.Errorf("Enforced was not driven for supported token %q (activation would never latch)", want)
		}
	}
	if len(capabilities.Supported()) > 0 && len(g.enforced) == 0 {
		t.Fatal("no tokens driven")
	}
}
