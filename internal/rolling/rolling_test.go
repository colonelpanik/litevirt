package rolling

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// mockOps records calls for assertion in tests.
type mockOps struct {
	mu           sync.Mutex
	recreated    []string
	stopped      []string
	started      []string
	created      []string // -next VMs created via CreateNextVM
	failOn       string   // VM name that should fail RecreateVM
	healthFailOn string   // VM name that should fail WaitHealthy
	createFailOn string   // VM name that should fail CreateNextVM
}

func (m *mockOps) RecreateVM(_ context.Context, name string, _ *compose.File) error {
	if m.failOn == name {
		return fmt.Errorf("simulated failure for %s", name)
	}
	m.mu.Lock()
	m.recreated = append(m.recreated, name)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) StopVM(_ context.Context, name string) error {
	m.mu.Lock()
	m.stopped = append(m.stopped, name)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) StartVM(_ context.Context, name string) error {
	m.mu.Lock()
	m.started = append(m.started, name)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) HotModifyVM(_ context.Context, _ string, _ int, _ int) error { return nil }
func (m *mockOps) CreateNextVM(_ context.Context, name string, _ *compose.File) error {
	nextName := name + "-next"
	if m.createFailOn == name {
		return fmt.Errorf("simulated failure for %s", nextName)
	}
	m.mu.Lock()
	m.created = append(m.created, nextName)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) WaitHealthy(_ context.Context, name string, _ time.Duration) error {
	if m.healthFailOn == name {
		return fmt.Errorf("health check failed for %s", name)
	}
	return nil
}

func newTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func insertTestVMs(t *testing.T, db *corrosion.Client, ctx context.Context, stack string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name:      name,
			StackName: stack,
			HostName:  "h1",
			Spec:      "{}",
			State:     "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
}

func parseTestFile(strategy string) *compose.File {
	yaml := fmt.Sprintf(`
name: teststack
vms:
  web:
    image: ubuntu
    cpu: 1
    memory: 512
    update:
      strategy: %s
`, strategy)
	f, _ := compose.ParseBytes([]byte(yaml))
	return f
}

func collectProgress(ch <-chan Progress) []Progress {
	var out []Progress
	for p := range ch {
		out = append(out, p)
	}
	return out
}

func TestUpdate_Recreate(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1")

	f := parseTestFile("recreate")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	if len(ops.recreated) != 1 || ops.recreated[0] != "teststack-web-1" {
		t.Errorf("expected web-1 recreated, got: %v", ops.recreated)
	}
	// Should have a done progress entry.
	found := false
	for _, p := range progress {
		if p.Phase == "done" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'done' progress, got: %+v", progress)
	}
}

func TestUpdate_AllAtOnce(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	insertTestVMs(t, db, ctx, "mystack", "mystack-web-1", "mystack-web-2", "mystack-db-1")

	f := parseTestFile("all-at-once")
	f.Name = "mystack"
	ch := Update(ctx, db, ops, "mystack", f, "")
	collectProgress(ch)

	if len(ops.recreated) != 3 {
		t.Errorf("expected 3 VMs recreated, got %d: %v", len(ops.recreated), ops.recreated)
	}
}

func TestUpdate_FailureNoRollback(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "teststack-web-1"}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1")

	f := parseTestFile("recreate")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	found := false
	for _, p := range progress {
		if p.Phase == "error" {
			found = true
		}
	}
	if !found {
		t.Error("expected error progress entry on failure")
	}
}

func TestUpdate_AllAtOnce_RollbackOnFailure(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "mystack-web-1"}

	insertTestVMs(t, db, ctx, "mystack", "mystack-web-1")

	oldYAML := `
name: mystack
vms:
  web:
    image: ubuntu-old
    cpu: 1
    memory: 512
`
	f := parseTestFile("all-at-once")
	// Set rollback flag via a VM update def.
	f.Name = "mystack"
	f.VMs["web"] = compose.VMDef{
		Image:  "ubuntu-new",
		Update: &compose.UpdateDef{Strategy: "all-at-once", RollbackOnFailure: true},
	}

	ch := Update(ctx, db, ops, "mystack", f, oldYAML)
	progress := collectProgress(ch)

	foundRollback := false
	for _, p := range progress {
		if p.Phase == "rollback" {
			foundRollback = true
		}
	}
	if !foundRollback {
		t.Error("expected rollback progress on failure with rollback_on_failure=true")
	}
}

func TestResolveUpdateGroups_Default(t *testing.T) {
	f := &compose.File{VMs: map[string]compose.VMDef{
		"web": {Image: "ubuntu"},
	}}
	groups := resolveUpdateGroups(f, []string{"web"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].ud.Strategy != "recreate" {
		t.Errorf("expected default strategy 'recreate', got %q", groups[0].ud.Strategy)
	}
}

func TestParseDuration(t *testing.T) {
	if got := parseDuration("5s", 0); got != 5*time.Second {
		t.Errorf("expected 5s, got %v", got)
	}
	if got := parseDuration("", 10*time.Second); got != 10*time.Second {
		t.Errorf("expected default 10s, got %v", got)
	}
	if got := parseDuration("invalid", 3*time.Second); got != 3*time.Second {
		t.Errorf("expected default 3s for invalid, got %v", got)
	}
}

func TestUpdate_OrderedAbortOnRecreateFailure(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{failOn: "teststack-web-2"}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1", "teststack-web-2", "teststack-web-3")

	f := parseTestFile("stop-first")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	// Only the 1st VM should have been recreated.
	if len(ops.recreated) != 1 || ops.recreated[0] != "teststack-web-1" {
		t.Errorf("expected only teststack-web-1 recreated, got: %v", ops.recreated)
	}
	// The 3rd VM must NOT have been recreated.
	for _, name := range ops.recreated {
		if name == "teststack-web-3" {
			t.Error("teststack-web-3 should not have been recreated after abort")
		}
	}
	// Progress must contain an error entry.
	found := false
	for _, p := range progress {
		if p.Phase == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'error' progress entry, got: %+v", progress)
	}
}

func TestUpdate_OrderedAbortOnHealthCheckFailure(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{healthFailOn: "teststack-web-1"}

	insertTestVMs(t, db, ctx, "teststack", "teststack-web-1", "teststack-web-2")

	f := parseTestFile("stop-first")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	// The 1st VM should have been recreated (RecreateVM succeeds, WaitHealthy fails).
	found1 := false
	for _, name := range ops.recreated {
		if name == "teststack-web-1" {
			found1 = true
		}
	}
	if !found1 {
		t.Errorf("expected teststack-web-1 to be recreated, got: %v", ops.recreated)
	}
	// The 2nd VM must NOT have been recreated (aborted after health check failure).
	for _, name := range ops.recreated {
		if name == "teststack-web-2" {
			t.Error("teststack-web-2 should not have been recreated after health check abort")
		}
	}
	// Progress must contain an error entry mentioning "health check".
	foundErr := false
	for _, p := range progress {
		if p.Phase == "error" && p.Detail != "" {
			if len(p.Detail) >= len("health check") && p.Detail[:len("health check")] == "health check" {
				foundErr = true
			}
		}
	}
	if !foundErr {
		t.Errorf("expected 'error' progress entry about health check, got: %+v", progress)
	}
}

func TestUpdate_OrderedSkipsDrainingHosts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ops := &mockOps{}

	// Insert host records: h1 active, h2 draining.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "h1", State: "active"}); err != nil {
		t.Fatalf("InsertHost h1: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "h2", State: "draining"}); err != nil {
		t.Fatalf("InsertHost h2: %v", err)
	}

	// Insert one VM on the active host and one on the draining host.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "teststack-web-1",
		StackName: "teststack",
		HostName:  "h1",
		Spec:      "{}",
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM teststack-web-1: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "teststack-web-2",
		StackName: "teststack",
		HostName:  "h2",
		Spec:      "{}",
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM teststack-web-2: %v", err)
	}

	f := parseTestFile("stop-first")
	ch := Update(ctx, db, ops, "teststack", f, "")
	progress := collectProgress(ch)

	// Only the VM on the active host should have been recreated.
	if len(ops.recreated) != 1 || ops.recreated[0] != "teststack-web-1" {
		t.Errorf("expected only teststack-web-1 recreated, got: %v", ops.recreated)
	}
	// The VM on the draining host must NOT appear in recreated.
	for _, name := range ops.recreated {
		if name == "teststack-web-2" {
			t.Error("teststack-web-2 (draining host) should have been skipped")
		}
	}
	// A "done" progress entry with "skipped" detail should be present for the draining VM.
	foundSkip := false
	for _, p := range progress {
		if p.VMName == "teststack-web-2" && p.Phase == "done" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected skipped progress for teststack-web-2, got: %+v", progress)
	}
}
