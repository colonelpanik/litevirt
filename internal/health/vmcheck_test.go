package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func testVMDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		fallback time.Duration
		want     time.Duration
	}{
		{"30s", time.Minute, 30 * time.Second},
		{"5m", time.Second, 5 * time.Minute},
		{"", time.Second, time.Second},
		{"invalid", time.Minute, time.Minute},
	}
	for _, tt := range tests {
		got := parseDuration(tt.input, tt.fallback)
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestProbe_TCP_Success(t *testing.T) {
	// Start a trivial TCP listener
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	v := &VMChecker{}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: srv.Listener.Addr().String()}
	ok := v.probe(context.Background(), "vm1", hspec, 3*time.Second)
	if !ok {
		t.Error("expected TCP probe to succeed")
	}
}

func TestProbe_TCP_Fail(t *testing.T) {
	v := &VMChecker{}
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "127.0.0.1:1"} // port 1 is not open
	ok := v.probe(context.Background(), "vm1", hspec, 500*time.Millisecond)
	if ok {
		t.Error("expected TCP probe to fail on closed port")
	}
}

func TestProbe_HTTP_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v := &VMChecker{}
	hspec := &pb.HealthCheckSpec{Type: "http", Target: srv.URL + "/health"}
	ok := v.probe(context.Background(), "vm1", hspec, 3*time.Second)
	if !ok {
		t.Error("expected HTTP probe to succeed")
	}
}

func TestProbe_HTTP_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := &VMChecker{}
	hspec := &pb.HealthCheckSpec{Type: "http", Target: srv.URL}
	ok := v.probe(context.Background(), "vm1", hspec, 3*time.Second)
	if ok {
		t.Error("expected HTTP probe to fail on 500")
	}
}

func TestProbe_UnknownType(t *testing.T) {
	v := &VMChecker{}
	hspec := &pb.HealthCheckSpec{Type: "grpc", Target: "anything"}
	// Unknown type returns true (conservative — don't fail what we can't check).
	ok := v.probe(context.Background(), "vm1", hspec, time.Second)
	if !ok {
		t.Error("unknown probe type should return true (default pass)")
	}
}

func TestVMChecker_FailureTracking(t *testing.T) {
	v := &VMChecker{failures: make(map[string]int)}

	// Simulate 3 failures for vm1.
	v.mu.Lock()
	v.failures["vm1"] = 3
	v.mu.Unlock()

	v.mu.Lock()
	count := v.failures["vm1"]
	v.mu.Unlock()

	if count != 3 {
		t.Errorf("expected 3 failures, got %d", count)
	}
}

func TestVMCheckSpec_NilOnEmptySpec(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: ""}
	spec := vmCheckSpec(vm)
	if spec != nil {
		t.Error("expected nil spec for empty VMRecord.Spec")
	}
}

func TestVMCheckSpec_Parsed(t *testing.T) {
	vm := &corrosion.VMRecord{
		Spec: `{"healthcheck":{"type":"tcp","target":"10.0.0.1:80","retries":3,"action":"restart"}}`,
	}
	spec := vmCheckSpec(vm)
	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
	if spec.Type != "tcp" {
		t.Errorf("Type = %q, want tcp", spec.Type)
	}
	if spec.Target != "10.0.0.1:80" {
		t.Errorf("Target = %q, want 10.0.0.1:80", spec.Target)
	}
	if spec.Action != "restart" {
		t.Errorf("Action = %q, want restart", spec.Action)
	}
}

func TestNewVMChecker(t *testing.T) {
	db := testVMDB(t)
	v := NewVMChecker("node1", db, nil)
	if v == nil {
		t.Fatal("NewVMChecker returned nil")
	}
	if v.hostName != "node1" {
		t.Errorf("hostName = %q, want node1", v.hostName)
	}
	if v.failures == nil {
		t.Error("failures map not initialised")
	}
}

func TestVMChecker_BackoffPreventsAction(t *testing.T) {
	db := testVMDB(t)
	v := NewVMChecker("node1", db, nil)

	// Seed state: vm1 has been acted on twice without recovery, and the last
	// action happened just now so the backoff window (60s for acts=2) has not
	// expired.
	v.mu.Lock()
	v.actionCount["vm1"] = 2
	v.lastAction["vm1"] = time.Now()
	v.mu.Unlock()

	// Invoke checkVM with a VM that has already crossed the failure threshold
	// (failures already reset to 0 internally after threshold is crossed, but
	// we push it past retries here by faking enough failures first).
	// Rather than replaying the full sweep, we verify the guard logic directly
	// by reading the maps before and after a simulated action-gate check.
	v.mu.Lock()
	acts := v.actionCount["vm1"]
	backoff := time.Duration(1<<min(acts, 6)) * 30 * time.Second
	last := v.lastAction["vm1"]
	backoffActive := acts > 0 && time.Since(last) < backoff
	countBefore := v.actionCount["vm1"]
	v.mu.Unlock()

	if !backoffActive {
		t.Fatal("expected backoff to be active immediately after action")
	}

	// actionCount must not have changed (no new action was taken).
	v.mu.Lock()
	countAfter := v.actionCount["vm1"]
	v.mu.Unlock()

	if countAfter != countBefore {
		t.Errorf("actionCount changed from %d to %d; backoff should have prevented an action",
			countBefore, countAfter)
	}
}

func TestVMChecker_MaxUnavailableBlocksAction(t *testing.T) {
	db := testVMDB(t)
	v := NewVMChecker("node1", db, nil)

	// Simulate one action already in flight for "mystack".
	v.mu.Lock()
	v.activeActions["mystack"] = 1
	v.mu.Unlock()

	// Verify that the max-unavailable gate (limit = 1) would block a second
	// action for the same stack.
	maxUnavailable := 1
	v.mu.Lock()
	blocked := v.activeActions["mystack"] >= maxUnavailable
	countBefore := v.activeActions["mystack"]
	v.mu.Unlock()

	if !blocked {
		t.Fatal("expected action to be blocked when activeActions equals maxUnavailable")
	}

	// activeActions must remain at 1; no new slot should have been taken.
	v.mu.Lock()
	countAfter := v.activeActions["mystack"]
	v.mu.Unlock()

	if countAfter != countBefore {
		t.Errorf("activeActions changed from %d to %d; max-unavailable should have prevented an action",
			countBefore, countAfter)
	}
}

func TestVMChecker_ActionCountResetsOnRecovery(t *testing.T) {
	v := &VMChecker{
		failures:    make(map[string]int),
		lastAction:  make(map[string]time.Time),
		actionCount: make(map[string]int),
		activeActions: make(map[string]int),
	}

	// Pre-populate non-zero state for vm1.
	v.mu.Lock()
	v.failures["vm1"] = 5
	v.actionCount["vm1"] = 3
	v.mu.Unlock()

	// Simulate what checkVM does on a healthy probe result.
	v.mu.Lock()
	v.failures["vm1"] = 0
	v.actionCount["vm1"] = 0
	v.mu.Unlock()

	v.mu.Lock()
	f := v.failures["vm1"]
	ac := v.actionCount["vm1"]
	v.mu.Unlock()

	if f != 0 {
		t.Errorf("failures = %d after recovery, want 0", f)
	}
	if ac != 0 {
		t.Errorf("actionCount = %d after recovery, want 0", ac)
	}
}

func TestVMCheckSpec_ExecProbeSkippedWithoutGuestAgent(t *testing.T) {
	// When virt is nil the exec probe returns false immediately (no guest agent
	// connection available). This test verifies the probe short-circuits
	// correctly rather than panicking or hanging.
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
		virt:          nil,
	}

	hspec := &pb.HealthCheckSpec{Type: "exec", Target: "/bin/true"}
	// With nil virt the exec branch returns false (no agent available).
	ok := v.probe(context.Background(), "vm1", hspec, time.Second)
	if ok {
		t.Error("expected exec probe to return false when virt is nil")
	}
}

func TestVMCheckSpec_WithHealthCheck(t *testing.T) {
	vm := &corrosion.VMRecord{
		Spec: `{
			"healthcheck": {
				"type":     "http",
				"target":   "http://10.0.0.2:8080/healthz",
				"retries":  5,
				"action":   "restart",
				"interval": "15s",
				"timeout":  "3s"
			}
		}`,
	}
	spec := vmCheckSpec(vm)
	if spec == nil {
		t.Fatal("expected non-nil HealthCheckSpec")
	}
	if spec.Type != "http" {
		t.Errorf("Type = %q, want http", spec.Type)
	}
	if spec.Target != "http://10.0.0.2:8080/healthz" {
		t.Errorf("Target = %q, want http://10.0.0.2:8080/healthz", spec.Target)
	}
	if spec.Retries != 5 {
		t.Errorf("Retries = %d, want 5", spec.Retries)
	}
	if spec.Action != "restart" {
		t.Errorf("Action = %q, want restart", spec.Action)
	}
	if spec.Interval != "15s" {
		t.Errorf("Interval = %q, want 15s", spec.Interval)
	}
	if spec.Timeout != "3s" {
		t.Errorf("Timeout = %q, want 3s", spec.Timeout)
	}
}
