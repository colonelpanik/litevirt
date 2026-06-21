package rolling

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── MaxUnavailable / MaxSurge batching ──

func TestOrdered_MaxUnavailable_Batching(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	var peak atomic.Int32
	var current atomic.Int32
	ops := &concurrentMockOps{
		mockOps: &mockOps{},
		onRecreate: func() {
			cur := current.Add(1)
			for {
				old := peak.Load()
				if cur <= old {
					break
				}
				if peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond) // hold the slot briefly
			current.Add(-1)
		},
	}

	insertTestVMs(t, db, ctx, "batchstack", "batchstack-web-1", "batchstack-web-2", "batchstack-web-3", "batchstack-web-4", "batchstack-web-5", "batchstack-web-6")

	f := &compose.File{
		Name: "batchstack",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "stop-first", MaxUnavailable: 3},
			},
		},
	}
	ch := Update(ctx, db, ops, "batchstack", f, "")
	collectProgress(ch)

	if len(ops.mockOps.recreated) != 6 {
		t.Errorf("expected 6 VMs recreated, got %d: %v", len(ops.mockOps.recreated), ops.mockOps.recreated)
	}
	if p := peak.Load(); p < 2 {
		t.Errorf("expected peak concurrency >= 2 with max-unavailable=3, got %d", p)
	}
}

func TestOrdered_MaxSurge_StartFirst(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	var peak atomic.Int32
	var current atomic.Int32
	ops := &concurrentMockOps{
		mockOps: &mockOps{},
		onRecreate: func() {
			cur := current.Add(1)
			for {
				old := peak.Load()
				if cur <= old {
					break
				}
				if peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			current.Add(-1)
		},
	}

	insertTestVMs(t, db, ctx, "surgestack", "surgestack-web-1", "surgestack-web-2", "surgestack-web-3", "surgestack-web-4")

	f := &compose.File{
		Name: "surgestack",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "start-first", MaxSurge: 2},
			},
		},
	}
	ch := Update(ctx, db, ops, "surgestack", f, "")
	collectProgress(ch)

	if len(ops.mockOps.recreated) != 4 {
		t.Errorf("expected 4 VMs recreated, got %d", len(ops.mockOps.recreated))
	}
}

func TestOrdered_BatchAbortOnError(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "abortstack-web-2"}

	insertTestVMs(t, db, ctx, "abortstack", "abortstack-web-1", "abortstack-web-2", "abortstack-web-3", "abortstack-web-4", "abortstack-web-5", "abortstack-web-6")

	f := &compose.File{
		Name: "abortstack",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "stop-first", MaxUnavailable: 3},
			},
		},
	}
	ch := Update(ctx, db, ops, "abortstack", f, "")
	collectProgress(ch)

	// The first batch (3 VMs) runs, one fails. The second batch should NOT start.
	// VMs 4, 5, 6 should not be recreated.
	for _, name := range ops.recreated {
		if name == "abortstack-web-4" || name == "abortstack-web-5" || name == "abortstack-web-6" {
			t.Errorf("VM %s should not have been recreated after batch abort", name)
		}
	}
}

// ── Rolling strategy with Order ──

func TestUpdate_RollingStrategy_StopFirst(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "rollstack", "rollstack-web-1")

	f := &compose.File{
		Name: "rollstack",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "rolling", Order: "stop-first"},
			},
		},
	}
	ch := Update(ctx, db, ops, "rollstack", f, "")
	collectProgress(ch)

	if len(ops.recreated) != 1 {
		t.Errorf("expected 1 VM recreated, got %d", len(ops.recreated))
	}
	// stop-first should NOT call StartVM.
	if len(ops.started) != 0 {
		t.Errorf("expected 0 StartVM calls for stop-first, got %d", len(ops.started))
	}
}

func TestUpdate_RollingStrategy_StartFirst(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "rollstack2", "rollstack2-web-1")

	f := &compose.File{
		Name: "rollstack2",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "rolling", Order: "start-first"},
			},
		},
	}
	ch := Update(ctx, db, ops, "rollstack2", f, "")
	collectProgress(ch)

	// start-first should call StartVM before RecreateVM.
	if len(ops.started) != 1 {
		t.Errorf("expected 1 StartVM call, got %d", len(ops.started))
	}
	if len(ops.recreated) != 1 {
		t.Errorf("expected 1 RecreateVM call, got %d", len(ops.recreated))
	}
}

// ── Snapshot-and-replace ──

func TestUpdate_SnapshotAndReplace(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "snapstack", "snapstack-web-1", "snapstack-web-2")

	f := &compose.File{
		Name: "snapstack",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "snapshot-and-replace"},
			},
		},
	}
	ch := Update(ctx, db, ops, "snapstack", f, "")
	progress := collectProgress(ch)

	// Should have created -next VMs.
	if len(ops.created) != 2 {
		t.Errorf("expected 2 -next VMs created, got %d: %v", len(ops.created), ops.created)
	}
	// Original VMs should NOT be recreated.
	if len(ops.recreated) != 0 {
		t.Errorf("expected 0 recreated (cutover is manual), got: %v", ops.recreated)
	}
	// Progress should include cutover instructions.
	foundCutover := false
	for _, p := range progress {
		if p.Phase == "done" && len(p.Detail) > 0 {
			if contains(p.Detail, "lv cutover") {
				foundCutover = true
			}
		}
	}
	if !foundCutover {
		t.Errorf("expected cutover instructions in progress, got: %+v", progress)
	}
}

func TestUpdate_SnapshotAndReplace_FailureContinues(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{createFailOn: "snapstack2-web-1"}

	insertTestVMs(t, db, ctx, "snapstack2", "snapstack2-web-1", "snapstack2-web-2")

	f := &compose.File{
		Name: "snapstack2",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "snapshot-and-replace"},
			},
		},
	}
	ch := Update(ctx, db, ops, "snapstack2", f, "")
	progress := collectProgress(ch)

	// web-1 fails, web-2 should still proceed (no rollback-on-failure).
	if len(ops.created) != 1 {
		t.Errorf("expected 1 -next VM created (web-2 only), got %d: %v", len(ops.created), ops.created)
	}
	foundErr := false
	for _, p := range progress {
		if p.Phase == "error" && p.VMName == "snapstack2-web-1" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected error progress for web-1")
	}
}

// ── Per-VM update overrides ──

func TestPerVMOverrides_MixedStrategies(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Use instance names that match compose keys (single-replica).
	for _, name := range []string{"fast", "slow"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name:      name,
			StackName: "mixstack",
			HostName:  "h1",
			Spec:      "{}",
			State:     "running",
			CPUActual: 2,
			MemActual: 4096,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}

	f := &compose.File{
		Name: "mixstack",
		VMs: map[string]compose.VMDef{
			"fast": {
				Image:  "ubuntu",
				CPU:    4,    // upward from 2 — hot-modifiable
				Memory: 8192, // upward from 4096
				Update: &compose.UpdateDef{Strategy: "in-place"},
			},
			"slow": {
				Image:  "ubuntu",
				CPU:    2,
				Memory: 4096,
				Update: &compose.UpdateDef{Strategy: "stop-first"},
			},
		},
	}

	ops := &mockOps{}
	ch := Update(ctx, db, ops, "mixstack", f, "")
	collectProgress(ch)

	// slow should be recreated (stop-first strategy).
	foundSlow := false
	for _, name := range ops.recreated {
		if name == "slow" {
			foundSlow = true
		}
	}
	if !foundSlow {
		t.Errorf("expected 'slow' to be recreated via stop-first, got: %v", ops.recreated)
	}
}

func TestPerVMOverrides_FallbackToStackDefault(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "defstack2", "defstack2-web-1", "defstack2-db-1")

	f := &compose.File{
		Name: "defstack2",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				CPU:    1,
				Memory: 512,
				Update: &compose.UpdateDef{Strategy: "start-first"},
			},
			"db": {
				Image:  "ubuntu",
				CPU:    2,
				Memory: 2048,
				// No Update — should fall back to web's strategy (start-first).
			},
		},
	}
	ch := Update(ctx, db, ops, "defstack2", f, "")
	collectProgress(ch)

	// Both VMs should have StartVM called (start-first is the stack default).
	if len(ops.started) != 2 {
		t.Errorf("expected 2 StartVM calls (stack default start-first), got %d: %v", len(ops.started), ops.started)
	}
}

func TestResolveUpdateGroups_Mixed(t *testing.T) {
	f := &compose.File{VMs: map[string]compose.VMDef{
		"web": {
			Image:  "ubuntu",
			Update: &compose.UpdateDef{Strategy: "start-first"},
		},
		"db": {
			Image:  "ubuntu",
			Update: &compose.UpdateDef{Strategy: "stop-first"},
		},
		"cache": {
			Image: "ubuntu",
			// No Update — inherits stack default (start-first from web).
		},
	}}

	// Use instance names that FindVMDef can resolve (single-replica = base name).
	groups := resolveUpdateGroups(f, []string{"web", "db", "cache"})
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// Verify we have both strategies represented.
	strategies := map[string]bool{}
	for _, g := range groups {
		strategies[g.ud.Strategy] = true
	}
	if !strategies["start-first"] {
		t.Error("expected a start-first group")
	}
	if !strategies["stop-first"] {
		t.Error("expected a stop-first group")
	}
}

func TestResolveUpdateGroups_AllSameStrategy(t *testing.T) {
	f := &compose.File{VMs: map[string]compose.VMDef{
		"web": {
			Image:  "ubuntu",
			Update: &compose.UpdateDef{Strategy: "all-at-once"},
		},
		"db": {
			Image: "ubuntu",
			// Inherits all-at-once.
		},
	}}

	groups := resolveUpdateGroups(f, []string{"s-web-1", "s-db-1"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group when all same strategy, got %d", len(groups))
	}
	if len(groups[0].targets) != 2 {
		t.Errorf("expected 2 targets in single group, got %d", len(groups[0].targets))
	}
}

// ── Helpers ──

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// concurrentMockOps wraps mockOps with a callback on RecreateVM for concurrency tracking.
type concurrentMockOps struct {
	*mockOps
	onRecreate func()
}

func (c *concurrentMockOps) RecreateVM(ctx context.Context, name string, f *compose.File) error {
	if c.onRecreate != nil {
		c.onRecreate()
	}
	return c.mockOps.RecreateVM(ctx, name, f)
}
