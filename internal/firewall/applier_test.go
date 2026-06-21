package firewall

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeNft records every Apply call. Useful for asserting the cache
// hit/miss behaviour of Applier.
type fakeNft struct {
	mu        sync.Mutex
	applies   []string
	flushes   int32
	failNext  error
}

func (f *fakeNft) Apply(_ context.Context, ruleset string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return "", err
	}
	f.applies = append(f.applies, ruleset)
	return "", nil
}
func (f *fakeNft) Flush(_ context.Context) (string, error) {
	atomic.AddInt32(&f.flushes, 1)
	return "", nil
}

// TestApplier_FirstApplyHits and second-apply-with-same-plan misses
// the runner — the cache short-circuit is the whole point.
func TestApplier_CacheShortCircuit(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	plan := Plan{HostRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept}}}

	changed, err := a.Apply(context.Background(), plan)
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	changed, err = a.Apply(context.Background(), plan)
	if err != nil || changed {
		t.Fatalf("second apply (cached): changed=%v err=%v", changed, err)
	}
	if len(f.applies) != 1 {
		t.Errorf("runner was called %d times, want 1", len(f.applies))
	}
}

// TestApplier_DiffPlanSendsAgain — changing any field invalidates the cache.
func TestApplier_DiffPlanSendsAgain(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	_, _ = a.Apply(context.Background(), Plan{DefaultDeny: false})
	_, _ = a.Apply(context.Background(), Plan{DefaultDeny: true})
	if len(f.applies) != 2 {
		t.Errorf("runner was called %d times, want 2 (policy change)", len(f.applies))
	}
}

// TestApplier_RenderError doesn't touch the runner.
func TestApplier_RenderErrorShortCircuits(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	_, err := a.Apply(context.Background(), Plan{
		NICs: []NICBinding{{NICDev: "tap0", SecurityGroups: []string{"missing"}}},
	})
	if err == nil {
		t.Fatal("expected render error")
	}
	if len(f.applies) != 0 {
		t.Errorf("runner called despite render error")
	}
}

// TestApplier_RunnerErrorDoesNotPoisonCache — a failed apply must not
// be remembered, otherwise the next retry would silently skip.
func TestApplier_RunnerErrorDoesNotPoisonCache(t *testing.T) {
	f := &fakeNft{failNext: errors.New("kernel said no")}
	a := NewApplier(f)
	plan := Plan{HostRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept}}}

	if _, err := a.Apply(context.Background(), plan); err == nil {
		t.Fatal("expected runner error to bubble up")
	}
	// Retry must reach the runner again because the first call failed.
	if changed, err := a.Apply(context.Background(), plan); err != nil || !changed {
		t.Fatalf("retry: changed=%v err=%v", changed, err)
	}
	if len(f.applies) != 1 {
		t.Errorf("expected exactly 1 successful apply after retry, got %d", len(f.applies))
	}
}

// TestApplier_ConcurrentApply two goroutines hitting Apply at once
// must serialise — the runner sees a strictly increasing number of
// applies as plans flip back and forth, capped at 20 in the worst
// case (strict alternation).
//
// Note: the two plans must be distinguishable in the rendered output.
// At tier-chain level (no nicDev) Direction alone collapses to
// "accept" for both — choosing different ports forces distinct bytes.
func TestApplier_ConcurrentApply(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	planA := Plan{HostRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept}}}
	planB := Plan{HostRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "80", Action: Accept}}}

	var wg sync.WaitGroup
	wg.Add(20)
	for i := 0; i < 20; i++ {
		i := i
		go func() {
			defer wg.Done()
			plan := planA
			if i%2 == 0 {
				plan = planB
			}
			_, _ = a.Apply(context.Background(), plan)
		}()
	}
	wg.Wait()
	if len(f.applies) < 2 {
		t.Errorf("expected at least 2 distinct applies (one per plan), got %d", len(f.applies))
	}
}

// TestApplier_LastApplied surfaces the last-sent ruleset for
// `lv firewall show`.
func TestApplier_LastApplied(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	if _, err := a.Apply(context.Background(), Plan{DefaultDeny: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(a.LastApplied(), "policy drop") {
		t.Error("LastApplied should contain the rendered ruleset")
	}
}

// TestApplier_Reset forces the next Apply to send even with identical
// bytes — used after an out-of-band `nft flush`.
func TestApplier_Reset(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	plan := Plan{HostRules: []Rule{{Direction: Ingress, Action: Accept}}}
	_, _ = a.Apply(context.Background(), plan)
	a.Reset()
	if changed, _ := a.Apply(context.Background(), plan); !changed {
		t.Error("Reset should force the next Apply to be 'changed'")
	}
	if len(f.applies) != 2 {
		t.Errorf("expected 2 applies after Reset, got %d", len(f.applies))
	}
}
