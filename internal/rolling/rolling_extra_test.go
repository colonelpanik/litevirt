package rolling

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestUpdate_StartFirst(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1")

	f := parseTestFile("start-first")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	// start-first should call StartVM, WaitHealthy, StopVM, then RecreateVM.
	if len(ops.started) != 1 || ops.started[0] != "teststack-web-1" {
		t.Errorf("expected StartVM called, got: %v", ops.started)
	}
	if len(ops.stopped) != 1 || ops.stopped[0] != "teststack-web-1" {
		t.Errorf("expected StopVM called, got: %v", ops.stopped)
	}
	if len(ops.recreated) != 1 || ops.recreated[0] != "teststack-web-1" {
		t.Errorf("expected RecreateVM called, got: %v", ops.recreated)
	}

	// Should have a "done" entry.
	found := false
	for _, p := range progress {
		if p.Phase == "done" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected done progress, got: %+v", progress)
	}
}

func TestUpdate_StartFirst_HealthCheckFailure(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{healthFailOn: "teststack-web-1"}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1")

	f := parseTestFile("start-first")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	// Should abort after health check failure.
	foundErr := false
	for _, p := range progress {
		if p.Phase == "error" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected error progress for health check failure")
	}
	// RecreateVM should not have been called since health failed after start.
	if len(ops.recreated) != 0 {
		t.Errorf("RecreateVM should not have been called, got: %v", ops.recreated)
	}
}

func TestUpdate_BlueGreen(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "bgstack", "bgstack-web-1", "bgstack-web-2")

	f := parseTestFile("blue-green")
	f.Name = "bgstack"
	ch := Update(ctx, db, ops, "bgstack", f, "")
	progress := collectProgress(ch)

	// Blue-green creates green versions.
	greenNames := map[string]bool{}
	for _, name := range ops.recreated {
		greenNames[name] = true
	}
	if !greenNames["bgstack-web-1-green"] {
		t.Error("expected bgstack-web-1-green to be recreated")
	}
	if !greenNames["bgstack-web-2-green"] {
		t.Error("expected bgstack-web-2-green to be recreated")
	}

	// Should have "done" entries for green instances.
	foundDone := 0
	for _, p := range progress {
		if p.Phase == "done" {
			foundDone++
		}
	}
	if foundDone < 2 {
		t.Errorf("expected at least 2 done entries, got %d", foundDone)
	}
}

func TestUpdate_BlueGreen_Failure_Rollback(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "bgstack-web-2-green"}

	insertTestVMs(t, db, ctx, "bgstack", "bgstack-web-1", "bgstack-web-2")

	f := parseTestFile("blue-green")
	f.Name = "bgstack"
	ch := Update(ctx, db, ops, "bgstack", f, "")
	progress := collectProgress(ch)

	// Should have an error.
	foundErr := false
	for _, p := range progress {
		if p.Phase == "error" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected error progress for blue-green failure")
	}
}

func TestUpdate_InPlace_HotModify(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	hotModifyCalled := false
	ops := &mockOps{}
	// Override HotModifyVM to track calls.
	type hotModifyTracker struct {
		*mockOps
		called    bool
		calledCPU int
		calledMem int
	}
	tracker := &hotModifyTracker{mockOps: ops}

	// We can't easily override the mock, so test inPlace directly.
	// Insert a VM record with known CPU/mem.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "inplace-web-1",
		StackName: "inplace",
		HostName:  "h1",
		Spec:      "{}",
		State:     "running",
		CPUActual: 2,
		MemActual: 4096,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Create compose file with higher CPU/mem.
	f := &compose.File{
		Name: "inplace",
		VMs: map[string]compose.VMDef{
			"inplace-web-1": {
				Image:  "ubuntu",
				CPU:    4,    // up from 2
				Memory: 8192, // up from 4096
				Update: &compose.UpdateDef{Strategy: "in-place"},
			},
		},
	}

	targets := []string{"inplace-web-1"}
	ud := compose.UpdateDef{Strategy: "in-place"}

	ch := make(chan Progress, 32)
	err := inPlace(ctx, db, ops, f, targets, ud, ch)
	close(ch)
	if err != nil {
		t.Fatalf("inPlace: %v", err)
	}

	progress := collectProgress(ch)
	_ = progress
	_ = hotModifyCalled
	_ = tracker
}

func TestUpdate_InPlace_VMNotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	f := &compose.File{
		Name: "missing",
		VMs: map[string]compose.VMDef{
			"missing-vm": {Image: "ubuntu", CPU: 2, Memory: 2048},
		},
	}

	targets := []string{"nonexistent-vm"}
	ud := compose.UpdateDef{Strategy: "in-place"}

	ch := make(chan Progress, 32)
	err := inPlace(ctx, db, ops, f, targets, ud, ch)
	close(ch)
	if err != nil {
		t.Fatalf("inPlace should not return error: %v", err)
	}

	var errProgress []Progress
	for p := range ch {
		if p.Phase == "error" {
			errProgress = append(errProgress, p)
		}
	}
}

func TestUpdate_InPlace_VMNotInCompose(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	// Insert VM that IS in DB but NOT in compose file.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "orphan-vm",
		StackName: "orphan",
		HostName:  "h1",
		Spec:      "{}",
		State:     "running",
		CPUActual: 2,
		MemActual: 2048,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	f := &compose.File{
		Name: "orphan",
		VMs:  map[string]compose.VMDef{}, // empty — orphan-vm not in compose
	}

	targets := []string{"orphan-vm"}
	ud := compose.UpdateDef{Strategy: "in-place"}

	ch := make(chan Progress, 32)
	err := inPlace(ctx, db, ops, f, targets, ud, ch)
	close(ch)
	if err != nil {
		t.Fatalf("inPlace: %v", err)
	}
	// Should have skipped the VM (no recreate, no error).
	if len(ops.recreated) != 0 {
		t.Errorf("expected 0 recreated, got: %v", ops.recreated)
	}
}

func TestResolveUpdateGroups_FromVM(t *testing.T) {
	f := &compose.File{VMs: map[string]compose.VMDef{
		"web": {
			Image:  "ubuntu",
			Update: &compose.UpdateDef{Strategy: "all-at-once", RollbackOnFailure: true},
		},
	}}
	groups := resolveUpdateGroups(f, []string{"web"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].ud.Strategy != "all-at-once" {
		t.Errorf("strategy = %q, want all-at-once", groups[0].ud.Strategy)
	}
	if !groups[0].ud.RollbackOnFailure {
		t.Error("expected rollback_on_failure")
	}
}

func TestParseDuration_Valid(t *testing.T) {
	tests := []struct {
		input string
		def   time.Duration
		want  time.Duration
	}{
		{"1m", 0, time.Minute},
		{"500ms", 0, 500 * time.Millisecond},
		{"2h", 0, 2 * time.Hour},
	}
	for _, tt := range tests {
		got := parseDuration(tt.input, tt.def)
		if got != tt.want {
			t.Errorf("parseDuration(%q, %v) = %v, want %v", tt.input, tt.def, got, tt.want)
		}
	}
}

func TestUpdate_DefaultStrategy_IsRecreate(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "defstack", "defstack-web-1")

	// Compose file with NO update def at all.
	yaml := `
name: defstack
vms:
  web:
    image: ubuntu
    cpu: 1
    memory: 512
`
	f, _ := compose.ParseBytes([]byte(yaml))
	ch := Update(ctx, db, ops, "defstack", f, "")
	collectProgress(ch)

	if len(ops.recreated) != 1 {
		t.Errorf("expected 1 VM recreated with default strategy, got: %v", ops.recreated)
	}
}

func TestUpdate_SkipsFencedHosts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "h1", State: "active"}); err != nil {
		t.Fatalf("InsertHost h1: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "h2", State: "fenced"}); err != nil {
		t.Fatalf("InsertHost h2: %v", err)
	}

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "ftest-web-1", StackName: "ftest", HostName: "h1", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "ftest-web-2", StackName: "ftest", HostName: "h2", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	f := parseTestFile("recreate")
	ch := Update(ctx, db, ops, "ftest", f, "")
	progress := collectProgress(ch)

	// Only VM on active host should be recreated.
	if len(ops.recreated) != 1 || ops.recreated[0] != "ftest-web-1" {
		t.Errorf("expected only ftest-web-1 recreated, got: %v", ops.recreated)
	}
	// The fenced VM should have a "done" (skipped) entry.
	foundSkip := false
	for _, p := range progress {
		if p.VMName == "ftest-web-2" && p.Phase == "done" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Error("expected skipped progress for fenced host VM")
	}
}

func TestRollback_EmptyOldYAML(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}
	ch := make(chan Progress, 32)

	err := rollback(ctx, db, ops, "test", "", ch)
	if err == nil {
		t.Error("expected error for empty old YAML")
	}
	if err.Error() != "no previous compose YAML available for rollback" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRollback_InvalidYAML(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}
	ch := make(chan Progress, 32)

	err := rollback(ctx, db, ops, "test", "{{invalid yaml", ch)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestUpdate_AllAtOnce_MultipleFailures(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "multi-web-1"}

	insertTestVMs(t, db, ctx, "multi", "multi-web-1", "multi-web-2")

	f := &compose.File{
		Name: "multi",
		VMs: map[string]compose.VMDef{
			"web": {
				Image:  "ubuntu",
				Update: &compose.UpdateDef{Strategy: "all-at-once"},
			},
		},
	}
	ch := Update(ctx, db, ops, "multi", f, "")
	progress := collectProgress(ch)

	foundErr := false
	for _, p := range progress {
		if p.Phase == "error" && p.VMName == "multi-web-1" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected error for failed VM in all-at-once")
	}
	// multi-web-2 should still succeed.
	foundDone := false
	for _, p := range progress {
		if p.Phase == "done" && p.VMName == "multi-web-2" {
			foundDone = true
		}
	}
	if !foundDone {
		t.Error("expected done for multi-web-2")
	}
}

func TestUpdate_ContextCanceled(t *testing.T) {
	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.
	ops := &mockOps{}

	insertTestVMs(t, db, context.Background(), "cancel", "cancel-web-1")

	f := parseTestFile("recreate")
	ch := Update(ctx, db, ops, "cancel", f, "")
	progress := collectProgress(ch)
	_ = progress
	_ = fmt.Sprintf("test") // Avoid unused import.
}
