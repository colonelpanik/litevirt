package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// bestEffortFencer models fence.Execute's best-effort behavior: a lenient SSH
// fence reports Success=true even when the poweroff never landed, so the
// coordinator's !fr.Success guard is skipped — only the safe-fence policy gates it.
func bestEffortFencer() Fencer {
	return func(ctx context.Context, h fence.HostConfig) fence.Result {
		return fence.Result{Method: "best-effort-ssh", Detail: "SSH failed, proceeding anyway", Success: true}
	}
}

func gateEnforcing(tokens ...string) fakeFailoverGate {
	m := map[string]bool{}
	for _, t := range tokens {
		m[t] = true
	}
	return fakeFailoverGate{enforced: m}
}

// TestSafeFenceRequiresProof covers the policy predicate in isolation.
func TestSafeFenceRequiresProof(t *testing.T) {
	ctx := context.Background()
	host := &corrosion.HostRecord{Name: "bad"}
	optOut := &corrosion.HostRecord{Name: "bad", Labels: map[string]string{corrosion.LabelUnsafeAutoFailover: "true"}}

	// nil gate → never requires proof (policy is a strict addition on top of the gate).
	if (&Coordinator{}).safeFenceRequiresProof(ctx, host) {
		t.Error("nil gate must not require proof")
	}
	// gate present but token NOT enforced → legacy behavior.
	notEnforced := &Coordinator{SafeFenceEnforce: true, Gate: gateEnforcing()}
	if notEnforced.safeFenceRequiresProof(ctx, host) {
		t.Error("token not enforced must not require proof (pre-flip mixed-version safe)")
	}
	// KILL-SWITCH: config flag OFF but capability latched → still no proof required
	// (the flag short-circuits the latch, so enforcement can be disabled without a
	// redeploy or marker deletion).
	flagOff := &Coordinator{SafeFenceEnforce: false, Gate: gateEnforcing(capabilities.SafeFenceDefaultV1)}
	if flagOff.safeFenceRequiresProof(ctx, host) {
		t.Error("config flag off must disable enforcement even when the capability is latched")
	}
	// flag ON + token enforced, no opt-out → requires proof.
	enforced := &Coordinator{SafeFenceEnforce: true, Gate: gateEnforcing(capabilities.SafeFenceDefaultV1)}
	if !enforced.safeFenceRequiresProof(ctx, host) {
		t.Error("enforced policy must require proof for a best-effort host")
	}
	// flag ON + token enforced but host opted into legacy proceed-anyway → no proof.
	if enforced.safeFenceRequiresProof(ctx, optOut) {
		t.Error("unsafe-auto-failover opt-out must restore legacy proceed-anyway")
	}
}

// TestFailover_BestEffort_LegacyProceedsPreFlip: with the policy NOT enforced, a
// failed best-effort fence still reschedules (today's behavior) — no refusal.
func TestFailover_BestEffort_LegacyProceedsPreFlip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := NewCoordinator("coordinator", db)
	c.SetFencer(bestEffortFencer())
	c.Gate = gateEnforcing() // gate present, SafeFenceDefaultV1 NOT enforced
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 0 {
		t.Errorf("pre-flip best-effort must NOT be refused, got refusal count %d", got)
	}
}

// TestFailover_BestEffort_RefusedUnderPolicy: with SafeFenceDefaultV1 enforced and
// no operator confirmation, a failed best-effort fence is refused (the safety win).
func TestFailover_BestEffort_RefusedUnderPolicy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := NewCoordinator("coordinator", db)
	c.SetFencer(bestEffortFencer())
	c.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
	c.SafeFenceEnforce = true
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 1 {
		t.Errorf("best-effort under policy must be refused pending confirm, got %d (attempts=%v)", got, fm.attempts)
	}
}

// TestFailover_EmptyAndUnknownStrategy_RefusedUnderPolicy: fence_strategy "" and
// an unrecognized value both resolve to lenient best-effort in fence.Execute, so
// the safe-fence policy must gate them too (not only the literal "best-effort").
func TestFailover_EmptyAndUnknownStrategy_RefusedUnderPolicy(t *testing.T) {
	for _, strategy := range []string{"", "typo-strategy"} {
		t.Run("strategy="+strategy, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: "active", FenceStrategy: strategy,
			}); err != nil {
				t.Fatal(err)
			}
			downObservers(t, db, "bad", "h1", "h2", "h3")

			c := NewCoordinator("coordinator", db)
			c.SetFencer(bestEffortFencer())
			c.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
			c.SafeFenceEnforce = true
			fm := newFakeMetrics()
			c.Metrics = fm
			c.run(ctx)

			if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 1 {
				t.Errorf("strategy %q must be gated under policy, got refusal count %d", strategy, got)
			}
		})
	}
}

// TestFailover_BestEffort_OptOutProceedsUnderPolicy: the host label restores
// legacy proceed-anyway even with the policy enforced.
func TestFailover_BestEffort_OptOutProceedsUnderPolicy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	// Labels are persisted via SetHostLabel (InsertHost doesn't write them), matching
	// how an operator sets the opt-out in production.
	if err := corrosion.SetHostLabel(ctx, db, "bad", corrosion.LabelUnsafeAutoFailover, "true"); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := NewCoordinator("coordinator", db)
	c.SetFencer(bestEffortFencer())
	c.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
	c.SafeFenceEnforce = true
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 0 {
		t.Errorf("opt-out host must proceed under policy, got refusal count %d", got)
	}
}
