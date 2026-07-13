package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestSweepPrunesDeletedVMs_StopsPoisoning: stale per-VM failure counters for VMs that no
// longer exist must be pruned on sweep, so they neither leak nor keep isCorrelatedFailure
// over threshold — which would wrongly suppress auto-restart/migrate of healthy VMs.
func TestSweepPrunesDeletedVMs_StopsPoisoning(t *testing.T) {
	db := testSweepDB(t)
	ctx := context.Background()
	// One live, running VM with no healthcheck spec (sweep skips the actual probe).
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-live", HostName: "node1", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	v := NewVMChecker("node1", db, nil)
	// Simulate three VMs deleted while failing — stale counters at the failing threshold.
	v.mu.Lock()
	for _, n := range []string{"gone-1", "gone-2", "gone-3"} {
		v.failures[n] = 2
		v.actionCount[n] = 1
		v.lastAction[n] = time.Now()
	}
	v.mu.Unlock()
	if !v.isCorrelatedFailure() {
		t.Fatal("precondition: 3 stale failing entries should read as correlated")
	}

	v.sweep(ctx)

	if v.isCorrelatedFailure() {
		t.Fatal("sweep must prune deleted-VM counters so correlated-failure clears")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.failures) != 0 || len(v.lastAction) != 0 || len(v.actionCount) != 0 {
		t.Fatalf("stale entries not pruned: failures=%v lastAction=%v actionCount=%v",
			v.failures, v.lastAction, v.actionCount)
	}
}

// TestPruneVMState_KeepsLiveDropsMissing: prune keeps entries for present VMs, drops missing.
func TestPruneVMState_KeepsLiveDropsMissing(t *testing.T) {
	v := &VMChecker{
		failures:      map[string]int{"live": 2, "gone": 2},
		lastAction:    map[string]time.Time{"live": time.Now(), "gone": time.Now()},
		actionCount:   map[string]int{"live": 1, "gone": 1},
		activeActions: make(map[string]int),
	}
	v.pruneVMState(map[string]bool{"live": true})
	if _, ok := v.failures["live"]; !ok {
		t.Fatal("live VM entry must be kept")
	}
	for _, m := range []string{"gone"} {
		if _, ok := v.failures[m]; ok {
			t.Fatalf("failures[%s] must be pruned", m)
		}
		if _, ok := v.lastAction[m]; ok {
			t.Fatalf("lastAction[%s] must be pruned", m)
		}
		if _, ok := v.actionCount[m]; ok {
			t.Fatalf("actionCount[%s] must be pruned", m)
		}
	}
}
