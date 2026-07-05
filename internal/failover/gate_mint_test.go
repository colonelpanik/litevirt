package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// fakeFailoverGate is a configurable FailoverGate: DecisionGate/QuorumProof/Enforced
// all report "healthy + enforced" so a test can isolate the PeerSupports (mint-site
// destination) decision.
type fakeFailoverGate struct {
	supports map[string]bool
	// enforced maps token → enforcement decision. A nil map means "all enforced"
	// (back-compat for tests that only exercise the mint-site PeerSupports path).
	enforced map[string]bool
}

func (f fakeFailoverGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (f fakeFailoverGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 2, 2
}
func (f fakeFailoverGate) Enforced(_ context.Context, token string) bool {
	if f.enforced == nil {
		return true
	}
	return f.enforced[token]
}
func (f fakeFailoverGate) PeerSupportsFresh(_ context.Context, peer, _ string) bool {
	return f.supports[peer]
}

// destAdvertisesGate is the fail-closed pre-mint check (Phase 1): the coordinator
// stamps a proof for a destination ONLY when a fresh Ping confirms it advertises
// the gate. A regressed/replaced target that no longer advertises is refused, and a
// nil gate fails closed — so a latched coordinator can never stamp a proof a target
// can't honor.
func TestDestAdvertisesGate(t *testing.T) {
	ctx := context.Background()
	c := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{supports: map[string]bool{"node-b": true}}}

	if !c.destAdvertisesGate(ctx, "node-b") {
		t.Fatal("a peer advertising the gate must pass")
	}
	if c.destAdvertisesGate(ctx, "node-c") {
		t.Fatal("a peer NOT advertising the gate must be refused (fail closed)")
	}
	// A nil gate fails closed.
	if (&Coordinator{hostName: "node-a"}).destAdvertisesGate(ctx, "node-b") {
		t.Fatal("nil gate must fail closed")
	}
	// A self-fenced coordinator never reports ITSELF as gate-capable (it de-advertises),
	// so it can't stamp a self-targeted proof — even if this build advertised the token.
	fenced := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{}, SelfFenced: func() bool { return true }}
	if fenced.destAdvertisesGate(ctx, "node-a") {
		t.Fatal("a self-fenced node must not report itself gate-capable")
	}
}
