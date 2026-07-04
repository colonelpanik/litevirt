package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeDemoterGate is a controllable demoterGate.
type fakeDemoterGate struct {
	state QuorumState
}

func (f *fakeDemoterGate) QuorumProof(context.Context) (QuorumState, int, int) { return f.state, 0, 0 }

// newTestDemoter wires a VIPDemoter with a controllable clock and records demote /
// self-fence / HA-degraded calls. enabled models "vip_demote_v1 enforced cluster-wide"
// (NO watchdog gate). Whether a demotion FAILURE self-fences is driven separately by
// calls.armed (the verified-watchdog predicate).
func newTestDemoter(gate *fakeDemoterGate, enabled bool, demoteAfter time.Duration) (*VIPDemoter, *demoteCalls, *time.Time) {
	calls := &demoteCalls{}
	clock := time.Now()
	clockp := &clock
	d := NewVIPDemoter(gate, demoteAfter)
	d.now = func() time.Time { return *clockp }
	d.SetEnabled(func(context.Context) bool { return enabled })
	d.SetDemoteLocalVIPs(func(context.Context) (bool, error) {
		calls.demotes++
		return calls.held, calls.demoteErr
	})
	d.SetSelfFence(func() { calls.fences++ })
	d.SetArmed(func() bool { return calls.armed })
	d.SetDemotionUnfencedObserver(func(on bool) {
		calls.unfenced = on
		if on {
			calls.unfencedTrue++
		}
	})
	return d, calls, clockp
}

type demoteCalls struct {
	demotes      int
	fences       int
	held         bool
	armed        bool // verified watchdog present (drives self-fence-on-failure)
	demoteErr    error
	unfenced     bool // last value passed to the demotion-unfenced observer
	unfencedTrue int  // count of true (HA-degraded raised) calls
}

func TestVIPDemoter_InertUntilEnabled(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo} // enabled=false below
	d, calls, clock := newTestDemoter(g, false, 12*time.Second)
	calls.held = true

	// Even after a long sustained "No", nothing happens while the token is de-advertised.
	d.evaluate(context.Background())
	*clock = clock.Add(time.Hour)
	d.evaluate(context.Background())
	if calls.demotes != 0 || calls.fences != 0 {
		t.Fatalf("inert-until-enforced violated: demotes=%d fences=%d", calls.demotes, calls.fences)
	}
}

// After a self-demotion, regaining quorum must trigger the LB re-apply (recover the
// dropped VIP) exactly once — and a heal WITHOUT a prior demote must not.
func TestVIPDemoter_ReappliesOnHealAfterDemote(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true
	reapplies := 0
	d.SetOnQuorumRestored(func(context.Context) { reapplies++ })

	// Sustained loss → demote.
	d.evaluate(context.Background())     // starts the loss clock
	*clock = clock.Add(20 * time.Second) // past demoteAfter
	d.evaluate(context.Background())     // demotes
	if calls.demotes != 1 {
		t.Fatalf("expected a demote; demotes=%d", calls.demotes)
	}
	// Quorum returns → re-apply once.
	g.state = QuorumYes
	d.evaluate(context.Background())
	if reapplies != 1 {
		t.Fatalf("heal after demote must re-apply LBs once; got %d", reapplies)
	}
	// A second healthy tick (no new demote) must not re-apply again.
	d.evaluate(context.Background())
	if reapplies != 1 {
		t.Fatalf("re-apply must fire only on heal-after-demote; got %d", reapplies)
	}
}

// A heal with no prior demotion must not re-apply.
func TestVIPDemoter_NoReapplyWithoutDemote(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumYes}
	d, _, _ := newTestDemoter(g, true, 12*time.Second)
	reapplies := 0
	d.SetOnQuorumRestored(func(context.Context) { reapplies++ })
	d.evaluate(context.Background())
	if reapplies != 0 {
		t.Fatalf("no demote → no re-apply; got %d", reapplies)
	}
}

func TestVIPDemoter_WarmupNeverDemotes(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumUnknown}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true

	d.evaluate(context.Background())
	*clock = clock.Add(time.Hour)
	d.evaluate(context.Background())
	if calls.demotes != 0 || calls.fences != 0 {
		t.Fatalf("warmup must never demote/fence: demotes=%d fences=%d", calls.demotes, calls.fences)
	}
}

func TestVIPDemoter_SubThresholdBlipNoAction(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true

	d.evaluate(context.Background()) // starts the loss clock
	*clock = clock.Add(11 * time.Second)
	d.evaluate(context.Background()) // still under threshold
	if calls.demotes != 0 {
		t.Fatalf("sub-threshold blip must not demote: demotes=%d", calls.demotes)
	}
	// Quorum returns before the threshold → clock resets, no demote ever.
	g.state = QuorumYes
	d.evaluate(context.Background())
	*clock = clock.Add(time.Hour)
	g.state = QuorumNo
	d.evaluate(context.Background()) // restarts the clock fresh
	if calls.demotes != 0 {
		t.Fatalf("recovered blip must not demote: demotes=%d", calls.demotes)
	}
}

func TestVIPDemoter_SustainedLossDemotesOnce(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true

	d.evaluate(context.Background()) // loss clock starts
	*clock = clock.Add(13 * time.Second)
	d.evaluate(context.Background()) // sustained → demote
	d.evaluate(context.Background()) // already demoted → no repeat
	if calls.demotes != 1 {
		t.Fatalf("sustained loss should demote exactly once, got %d", calls.demotes)
	}
	if calls.fences != 0 {
		t.Fatalf("successful demote must not self-fence, got %d", calls.fences)
	}
}

// With a VERIFIED watchdog armed, an unconfirmable demotion self-fences (the majority can
// then safely reclaim). It does NOT raise the HA-degraded "unfenced" surface — the node
// is going down.
func TestVIPDemoter_DemoteFailureSelfFencesWhenArmed(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true
	calls.armed = true // verified watchdog present
	calls.demoteErr = errors.New("keepalived stuck")

	d.evaluate(context.Background())
	*clock = clock.Add(13 * time.Second)
	d.evaluate(context.Background()) // sustained → demote fails → self-fence
	if calls.fences != 1 {
		t.Fatalf("unconfirmed demote with an armed watchdog must self-fence exactly once, got %d", calls.fences)
	}
	if calls.unfencedTrue != 0 {
		t.Fatalf("armed self-fence path must not raise the unfenced HA-degraded surface, got %d", calls.unfencedTrue)
	}
}

// DECOUPLE (PR 1): with NO verified watchdog, an unconfirmable demotion must NOT
// self-fence. The node stays up, keeps retrying the demote every tick (never latches
// demoted), and raises the durable HA-degraded "demotion_unfenced" surface — the majority
// then stays in the safe gap (it won't reclaim without a release/fence proof, so the VIP
// stays down rather than dual-mastering). This is the safe-gap-not-inert behavior.
func TestVIPDemoter_DemoteFailureNoWatchdog_SafeGapNoFence(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true
	calls.armed = false // no verified watchdog
	calls.demoteErr = errors.New("keepalived stuck")

	d.evaluate(context.Background())
	*clock = clock.Add(13 * time.Second)
	d.evaluate(context.Background()) // sustained → demote fails → NO fence, HA-degraded
	d.evaluate(context.Background()) // still failing → retries, still HA-degraded
	if calls.fences != 0 {
		t.Fatalf("no verified watchdog: a demote failure must NOT self-fence, got %d", calls.fences)
	}
	if !calls.unfenced || calls.unfencedTrue < 2 {
		t.Fatalf("must raise + keep raising the unfenced HA-degraded surface each failing tick; last=%v trueCount=%d", calls.unfenced, calls.unfencedTrue)
	}
	if calls.demotes < 2 {
		t.Fatalf("must keep RETRYING the demote each tick (safe gap), got %d attempts", calls.demotes)
	}
	if d.demoted {
		t.Fatal("a failed demote must not latch demoted (keeps retrying)")
	}

	// Recovery: the demote finally succeeds → clear the HA-degraded surface, latch demoted.
	calls.demoteErr = nil
	d.evaluate(context.Background())
	if calls.unfenced {
		t.Fatal("a successful demote must clear the unfenced HA-degraded surface")
	}
	if !d.demoted {
		t.Fatal("a successful demote must latch demoted")
	}
}

// After an unfenced failure, regaining quorum clears the HA-degraded surface.
func TestVIPDemoter_UnfencedClearsOnHeal(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true
	calls.armed = false
	calls.demoteErr = errors.New("keepalived stuck")

	d.evaluate(context.Background())
	*clock = clock.Add(13 * time.Second)
	d.evaluate(context.Background()) // fails → HA-degraded raised
	if !calls.unfenced {
		t.Fatal("expected the unfenced surface raised after a failed demote")
	}
	g.state = QuorumYes
	d.evaluate(context.Background()) // heal → clear
	if calls.unfenced {
		t.Fatal("quorum heal must clear the unfenced HA-degraded surface")
	}
}

func TestVIPDemoter_NoLocalVIPsNoFence(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = false // this host runs no VIPs

	d.evaluate(context.Background())
	*clock = clock.Add(13 * time.Second)
	d.evaluate(context.Background()) // sustained, but nothing to demote
	if calls.fences != 0 {
		t.Fatalf("a host with no VIPs must not self-fence, got %d", calls.fences)
	}
	// held=false is not latched as demoted → it keeps checking (cheap) but never fences.
	if d.demoted {
		t.Fatal("no-VIP host must not latch demoted")
	}
}

// QuorumUnknown clears the loss clock (per QuorumProof's "no loss-clock" contract): a
// No → Unknown → No sequence must require a FULL contiguous quorum_loss_demote_after of
// confirmed No before demoting — not demote based on time that spanned an Unknown blip.
func TestVIPDemoter_UnknownResetsLossClock(t *testing.T) {
	g := &fakeDemoterGate{state: QuorumNo}
	d, calls, clock := newTestDemoter(g, true, 12*time.Second)
	calls.held = true
	ctx := context.Background()

	d.evaluate(ctx)                      // No: loss clock starts at t0
	*clock = clock.Add(10 * time.Second) // 10s of No (< 12)
	g.state = QuorumUnknown
	d.evaluate(ctx) // Unknown: must CLEAR the loss clock
	g.state = QuorumNo
	d.evaluate(ctx)                      // No again: clock restarts at t1
	*clock = clock.Add(10 * time.Second) // 10s since t1 (< 12) — total No time > 12 but not contiguous
	d.evaluate(ctx)
	if calls.demotes != 0 {
		t.Fatalf("Unknown must reset the loss clock — no demote before a full contiguous threshold; got %d", calls.demotes)
	}
	*clock = clock.Add(3 * time.Second) // now 13s of CONTIGUOUS No since t1
	d.evaluate(ctx)
	if calls.demotes != 1 {
		t.Fatalf("expected one demote after a full contiguous No period; got %d", calls.demotes)
	}
}
