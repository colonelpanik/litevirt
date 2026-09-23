package firewall

import (
	"context"
	"testing"
	"time"
)

// countingRunner records every ruleset actually handed to nft.
type countingRunner struct {
	applied []string
}

func (c *countingRunner) Apply(_ context.Context, ruleset string) (string, error) {
	c.applied = append(c.applied, ruleset)
	return "", nil
}

func (c *countingRunner) Flush(_ context.Context) (string, error) { return "", nil }

// TestApplier_ResyncsAfterTheWindow is the #187 regression.
//
// The Reconciler's own doc claims "A periodic re-apply self-heals out-of-band
// drift (e.g. a sysadmin ran `nft flush` to debug)" on the line above "Cache
// short-circuit on the Applier means most ticks are free". The two cannot both
// be true: Apply returned early whenever the rendered bytes matched lastSent,
// so after an out-of-band flush the reconciler rendered the same ruleset, never
// invoked nft, and stamped a fresh LastTick. Status read healthy with no rules
// in the kernel — on an isolated bridge, the `iifname br-iso-x drop` rule was
// simply gone.
//
// Applier.Reset exists for exactly this and had NO production caller anywhere
// in internal/ or cmd/.
func TestApplier_ResyncsAfterTheWindow(t *testing.T) {
	run := &countingRunner{}
	a := NewApplier(run)

	now := time.Unix(1_700_000_000, 0)
	a.SetClock(func() time.Time { return now })
	a.SetResyncInterval(5 * time.Minute)

	p := Plan{}
	if _, err := a.Apply(context.Background(), p); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if len(run.applied) != 1 {
		t.Fatalf("first apply sent %d rulesets, want 1", len(run.applied))
	}

	// Within the window an unchanged plan must stay free.
	now = now.Add(30 * time.Second)
	if changed, err := a.Apply(context.Background(), p); err != nil || changed {
		t.Fatalf("tick inside the window: changed=%v err=%v", changed, err)
	}
	if len(run.applied) != 1 {
		t.Fatalf("an unchanged plan inside the window re-sent: %d applies", len(run.applied))
	}

	// Past the window the identical plan must reach nft again, so a ruleset
	// flushed out-of-band comes back.
	now = now.Add(6 * time.Minute)
	changed, err := a.Apply(context.Background(), p)
	if err != nil {
		t.Fatalf("resync apply: %v", err)
	}
	if len(run.applied) != 2 {
		t.Fatalf("the ruleset was not re-sent after the resync window: %d applies", len(run.applied))
	}
	// The BYTES did not change, so the caller must not be told they did —
	// otherwise every resync emits a spurious firewall-changed event.
	if changed {
		t.Error("a resync of identical bytes reported changed=true")
	}
}

// A changed plan still applies immediately, window or no window.
func TestApplier_ChangedPlanAppliesImmediately(t *testing.T) {
	run := &countingRunner{}
	a := NewApplier(run)
	now := time.Unix(1_700_000_000, 0)
	a.SetClock(func() time.Time { return now })
	a.SetResyncInterval(time.Hour)

	if _, err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	changed, err := a.Apply(context.Background(), Plan{DefaultDeny: true})
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if !changed {
		t.Error("a genuinely different plan must report changed=true")
	}
	if len(run.applied) != 2 {
		t.Errorf("applies = %d, want 2", len(run.applied))
	}
}

// Reset remains the explicit "reality drifted" lever, and must force the very
// next apply through regardless of the window. `lv firewall reload` is an
// operator saying exactly that.
func TestApplier_ResetForcesTheNextApply(t *testing.T) {
	run := &countingRunner{}
	a := NewApplier(run)
	now := time.Unix(1_700_000_000, 0)
	a.SetClock(func() time.Time { return now })
	a.SetResyncInterval(time.Hour)

	if _, err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	a.Reset()
	if _, err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("apply after Reset: %v", err)
	}
	if len(run.applied) != 2 {
		t.Errorf("Reset did not force a re-send: applies = %d, want 2", len(run.applied))
	}
}

// A zero resync interval keeps the old cache-only behaviour, so a caller that
// wants it can still have it explicitly.
func TestApplier_ZeroResyncIntervalIsCacheOnly(t *testing.T) {
	run := &countingRunner{}
	a := NewApplier(run)
	now := time.Unix(1_700_000_000, 0)
	a.SetClock(func() time.Time { return now })
	a.SetResyncInterval(0)

	if _, err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	now = now.Add(24 * time.Hour)
	if _, err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(run.applied) != 1 {
		t.Errorf("resync=0 must never re-send: applies = %d, want 1", len(run.applied))
	}
}

// TestReconciler_ForceResendsWithinTheWindow is the other half of #187:
// `lv firewall reload` routed through the same Reconcile and hit the same
// cache, so the one command an operator runs when they believe the kernel has
// drifted did nothing at all.
func TestReconciler_ForceResendsWithinTheWindow(t *testing.T) {
	run := &countingRunner{}
	a := NewApplier(run)
	now := time.Unix(1_700_000_000, 0)
	a.SetClock(func() time.Time { return now })
	a.SetResyncInterval(time.Hour) // far longer than this test

	loader := func(context.Context) (Plan, error) { return Plan{}, nil }
	r := NewReconciler(loader, a, time.Minute)

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if len(run.applied) != 1 {
		t.Fatalf("first reconcile sent %d rulesets, want 1", len(run.applied))
	}
	// An ordinary tick inside the window stays free.
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(run.applied) != 1 {
		t.Fatalf("an unchanged tick re-sent: %d applies", len(run.applied))
	}
	// The operator asks for a reload. That must reach nft.
	if err := r.ReconcileForce(context.Background()); err != nil {
		t.Fatalf("force reconcile: %v", err)
	}
	if len(run.applied) != 2 {
		t.Errorf("`firewall reload` did not re-send the ruleset: %d applies", len(run.applied))
	}
}
