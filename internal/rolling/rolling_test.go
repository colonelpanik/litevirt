package rolling

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// mockOps records calls for assertion and can inject per-VM failures.
type mockOps struct {
	mu        sync.Mutex
	recreated []string
	stopped   []string
	started   []string
	created   []string // -next VMs via CreateNextVM
	deleted   []string
	resized   []string
	metadata  map[string][]string

	failRecreateOn   string
	failResizeOn     string
	failHealthOn     string
	failCreateNextOn string
	onRecreate       func()
}

func (m *mockOps) RecreateVM(_ context.Context, name string, _ *pb.VMSpec) error {
	if m.onRecreate != nil {
		m.onRecreate()
	}
	if m.failRecreateOn == name {
		return fmt.Errorf("simulated recreate failure for %s", name)
	}
	m.mu.Lock()
	m.recreated = append(m.recreated, name)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) ResizeVMLive(_ context.Context, name string, _ *pb.VMSpec) error {
	if m.failResizeOn == name {
		return fmt.Errorf("simulated resize failure for %s", name)
	}
	m.mu.Lock()
	m.resized = append(m.resized, name)
	m.mu.Unlock()
	return nil
}
func (m *mockOps) ApplyLiveMetadata(_ context.Context, name string, _ *pb.VMSpec, fields []string) error {
	m.mu.Lock()
	if m.metadata == nil {
		m.metadata = map[string][]string{}
	}
	m.metadata[name] = fields
	m.mu.Unlock()
	return nil
}
func (m *mockOps) CreateNextVM(_ context.Context, name string, _ *pb.VMSpec) error {
	if m.failCreateNextOn == name {
		return fmt.Errorf("simulated create-next failure for %s", name)
	}
	m.mu.Lock()
	m.created = append(m.created, name+"-next")
	m.mu.Unlock()
	return nil
}
func (m *mockOps) DeleteVM(_ context.Context, name string) error {
	m.mu.Lock()
	m.deleted = append(m.deleted, name)
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
func (m *mockOps) WaitHealthy(_ context.Context, name string, _ time.Duration) error {
	if m.failHealthOn == name {
		return fmt.Errorf("health check failed for %s", name)
	}
	return nil
}

var _ Ops = (*mockOps)(nil)

// act builds a VMAction with the given strategy + plan.
func act(name, strategy string, plan compose.ChangePlan) VMAction {
	return VMAction{
		Name:     name,
		Strategy: compose.UpdateDef{Strategy: strategy},
		Plan:     plan,
		Desired:  &pb.VMSpec{Name: name},
	}
}

func recreatePlan() compose.ChangePlan {
	return compose.ChangePlan{RecreateReasons: []string{"image change recreates"}}
}
func restartPlan() compose.ChangePlan {
	return compose.ChangePlan{RestartReasons: []string{"max_cpu needs a redefine"}}
}
func livePlan() compose.ChangePlan {
	return compose.ChangePlan{ResourceChanges: []compose.Delta{{Field: "cpu", Old: "2", New: "4"}}}
}
func metaPlan() compose.ChangePlan {
	return compose.ChangePlan{MetadataChanges: []compose.Delta{{Field: "labels"}}}
}

func collect() (func(Progress), *[]Progress) {
	var out []Progress
	var mu sync.Mutex
	return func(p Progress) {
		mu.Lock()
		out = append(out, p)
		mu.Unlock()
	}, &out
}

func hasPhase(ps []Progress, phase string) bool {
	for _, p := range ps {
		if p.Phase == phase {
			return true
		}
	}
	return false
}

// ── in-place: LIVE-OR-FAIL ──

func TestInPlace_LiveResize_NoRecreate(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", livePlan())}, fn); err != nil {
		t.Fatalf("live in-place: %v", err)
	}
	if len(ops.resized) != 1 || ops.resized[0] != "web" {
		t.Errorf("expected web resized live, got %v", ops.resized)
	}
	if len(ops.recreated) != 0 || len(ops.deleted) != 0 {
		t.Errorf("in-place live must not recreate/delete: recreated=%v deleted=%v", ops.recreated, ops.deleted)
	}
}

func TestInPlace_LiveMetadata_Applied(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", metaPlan())}, fn); err != nil {
		t.Fatalf("live metadata: %v", err)
	}
	if got := ops.metadata["web"]; len(got) != 1 || got[0] != "labels" {
		t.Errorf("expected labels metadata applied, got %v", got)
	}
	if len(ops.recreated) != 0 || len(ops.resized) != 0 {
		t.Errorf("metadata-only update should not resize/recreate")
	}
}

func TestInPlace_Restart_FailsWithoutDeleting(t *testing.T) {
	ops := &mockOps{}
	fn, ps := collect()
	err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", restartPlan())}, fn)
	if err == nil {
		t.Fatal("in-place of a restart-class change must fail")
	}
	if len(ops.recreated) != 0 || len(ops.deleted) != 0 || len(ops.resized) != 0 {
		t.Errorf("in-place restart-class must not mutate: recreated=%v deleted=%v resized=%v", ops.recreated, ops.deleted, ops.resized)
	}
	if !hasPhase(*ps, "error") {
		t.Error("expected an error progress entry")
	}
}

func TestInPlace_Recreate_FailsNeverDeletes(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", recreatePlan())}, fn)
	if err == nil {
		t.Fatal("in-place of a recreate-class change must fail")
	}
	if len(ops.deleted) != 0 || len(ops.recreated) != 0 {
		t.Errorf("in-place must NEVER delete/recreate: deleted=%v recreated=%v", ops.deleted, ops.recreated)
	}
}

func TestInPlace_ResizeError_Propagates(t *testing.T) {
	ops := &mockOps{failResizeOn: "web"}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", livePlan())}, fn); err == nil {
		t.Fatal("a live resize error must propagate from Run")
	}
}

// ── recreate-class strategies ──

func TestRecreate_Strategy(t *testing.T) {
	ops := &mockOps{}
	fn, ps := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{act("web", "recreate", recreatePlan())}, fn); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if len(ops.recreated) != 1 || ops.recreated[0] != "web" {
		t.Errorf("expected web recreated, got %v", ops.recreated)
	}
	if !hasPhase(*ps, "done") {
		t.Error("expected a done progress entry")
	}
}

func TestRecreate_FailFast(t *testing.T) {
	ops := &mockOps{failRecreateOn: "web-1"}
	fn, ps := collect()
	err := Run(context.Background(), ops, "s", []VMAction{act("web-1", "recreate", recreatePlan())}, fn)
	if err == nil {
		t.Fatal("recreate failure must return an error")
	}
	if !hasPhase(*ps, "error") {
		t.Error("expected error progress")
	}
}

func TestAllAtOnce_All(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "all-at-once", recreatePlan()),
		act("web-2", "all-at-once", recreatePlan()),
		act("db-1", "all-at-once", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err != nil {
		t.Fatalf("all-at-once: %v", err)
	}
	if len(ops.recreated) != 3 {
		t.Errorf("expected 3 recreated, got %d: %v", len(ops.recreated), ops.recreated)
	}
}

func TestAllAtOnce_FailFast(t *testing.T) {
	ops := &mockOps{failRecreateOn: "web-1"}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "all-at-once", recreatePlan()),
		act("web-2", "all-at-once", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err == nil {
		t.Fatal("all-at-once with a failure must return an error (no rollback)")
	}
}

// ── ordered batching ──

func TestOrdered_AbortOnRecreateFailure(t *testing.T) {
	ops := &mockOps{failRecreateOn: "web-2"}
	fn, ps := collect()
	actions := []VMAction{
		act("web-1", "stop-first", recreatePlan()),
		act("web-2", "stop-first", recreatePlan()),
		act("web-3", "stop-first", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err == nil {
		t.Fatal("expected an error when a VM fails mid-sequence")
	}
	if len(ops.recreated) != 1 || ops.recreated[0] != "web-1" {
		t.Errorf("expected only web-1 recreated before abort, got %v", ops.recreated)
	}
	if !hasPhase(*ps, "error") {
		t.Error("expected error progress")
	}
}

func TestOrdered_AbortOnHealthFailure(t *testing.T) {
	ops := &mockOps{failHealthOn: "web-1"}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "stop-first", recreatePlan()),
		act("web-2", "stop-first", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err == nil {
		t.Fatal("expected an error on health-check failure")
	}
	for _, n := range ops.recreated {
		if n == "web-2" {
			t.Error("web-2 must not be recreated after web-1's health abort")
		}
	}
}

func TestOrdered_MaxUnavailableBatching(t *testing.T) {
	var peak, cur atomic.Int32
	ops := &mockOps{onRecreate: func() {
		c := cur.Add(1)
		for {
			old := peak.Load()
			if c <= old || peak.CompareAndSwap(old, c) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		cur.Add(-1)
	}}
	var actions []VMAction
	for i := 1; i <= 6; i++ {
		a := act(fmt.Sprintf("web-%d", i), "stop-first", recreatePlan())
		a.Strategy.MaxUnavailable = 3
		actions = append(actions, a)
	}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", actions, fn); err != nil {
		t.Fatalf("batched: %v", err)
	}
	if len(ops.recreated) != 6 {
		t.Errorf("expected 6 recreated, got %d", len(ops.recreated))
	}
	if peak.Load() < 2 {
		t.Errorf("expected peak concurrency >= 2 with max-unavailable=3, got %d", peak.Load())
	}
}

func TestOrdered_StartFirst(t *testing.T) {
	ops := &mockOps{}
	a := act("web-1", "start-first", recreatePlan())
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{a}, fn); err != nil {
		t.Fatalf("start-first: %v", err)
	}
	if len(ops.started) != 1 || len(ops.stopped) != 1 || len(ops.recreated) != 1 {
		t.Errorf("start-first should start, stop, then recreate: started=%v stopped=%v recreated=%v", ops.started, ops.stopped, ops.recreated)
	}
}

func TestRolling_StopFirst_NoStart(t *testing.T) {
	ops := &mockOps{}
	a := VMAction{Name: "web-1", Strategy: compose.UpdateDef{Strategy: "rolling", Order: "stop-first"}, Plan: recreatePlan(), Desired: &pb.VMSpec{Name: "web-1"}}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{a}, fn); err != nil {
		t.Fatalf("rolling stop-first: %v", err)
	}
	if len(ops.started) != 0 {
		t.Errorf("stop-first must not StartVM, got %v", ops.started)
	}
	if len(ops.recreated) != 1 {
		t.Errorf("expected 1 recreate, got %v", ops.recreated)
	}
}

// ── snapshot-and-replace ──

func TestSnapshotAndReplace(t *testing.T) {
	ops := &mockOps{}
	fn, ps := collect()
	actions := []VMAction{
		act("web-1", "snapshot-and-replace", recreatePlan()),
		act("web-2", "snapshot-and-replace", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err != nil {
		t.Fatalf("snapshot-and-replace: %v", err)
	}
	if len(ops.created) != 2 {
		t.Errorf("expected 2 -next VMs, got %v", ops.created)
	}
	if len(ops.recreated) != 0 {
		t.Errorf("cutover is manual — nothing recreated, got %v", ops.recreated)
	}
	foundCutover := false
	for _, p := range *ps {
		if p.Phase == "done" && len(p.Detail) > 0 && contains(p.Detail, "lv cutover") {
			foundCutover = true
		}
	}
	if !foundCutover {
		t.Error("expected cutover instructions in progress")
	}
}

func TestSnapshotAndReplace_FailureContinues(t *testing.T) {
	ops := &mockOps{failCreateNextOn: "web-1"}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "snapshot-and-replace", recreatePlan()),
		act("web-2", "snapshot-and-replace", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err != nil {
		t.Fatalf("no rollback-on-failure → continues, got %v", err)
	}
	if len(ops.created) != 1 {
		t.Errorf("expected 1 -next VM (web-2), got %v", ops.created)
	}
}

// ── blue-green ──

func TestBlueGreen(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "blue-green", recreatePlan()),
		act("web-2", "blue-green", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err != nil {
		t.Fatalf("blue-green: %v", err)
	}
	green := map[string]bool{}
	for _, n := range ops.recreated {
		green[n] = true
	}
	if !green["web-1-green"] || !green["web-2-green"] {
		t.Errorf("expected -green instances recreated, got %v", ops.recreated)
	}
	// Cutover deletes the blue instances.
	if len(ops.deleted) != 2 {
		t.Errorf("expected 2 blue deletes, got %v", ops.deleted)
	}
}

func TestBlueGreen_FailureRollsBackGreens(t *testing.T) {
	ops := &mockOps{failRecreateOn: "web-2-green"}
	fn, _ := collect()
	actions := []VMAction{
		act("web-1", "blue-green", recreatePlan()),
		act("web-2", "blue-green", recreatePlan()),
	}
	if err := Run(context.Background(), ops, "s", actions, fn); err == nil {
		t.Fatal("blue-green failure must return an error")
	}
	// The already-created green (web-1-green) is cleaned up; blue instances untouched.
	if len(ops.deleted) != 1 || ops.deleted[0] != "web-1-green" {
		t.Errorf("expected the created green rolled back, got deleted=%v", ops.deleted)
	}
}

// ── grouping + helpers ──

func TestResolveGroups_MixedStrategies(t *testing.T) {
	actions := []VMAction{
		act("web", "start-first", recreatePlan()),
		act("db", "stop-first", recreatePlan()),
		act("cache", "start-first", recreatePlan()),
	}
	groups := resolveGroups(actions)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestParseDuration(t *testing.T) {
	if got := parseDuration("5s", 0); got != 5*time.Second {
		t.Errorf("5s → %v", got)
	}
	if got := parseDuration("", 10*time.Second); got != 10*time.Second {
		t.Errorf("default → %v", got)
	}
	if got := parseDuration("bad", 3*time.Second); got != 3*time.Second {
		t.Errorf("invalid default → %v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return len(sub) == 0
}
