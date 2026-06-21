package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func testCoverageDB(t *testing.T) *corrosion.Client {
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

// ── NewChecker ──────────────────────────────────────────────────────────────

func TestNewChecker_Fields(t *testing.T) {
	db := testCoverageDB(t)
	c := NewChecker("node-1", "/etc/litevirt/pki", db)
	if c.hostName != "node-1" {
		t.Errorf("hostName = %q", c.hostName)
	}
	if c.pkiDir != "/etc/litevirt/pki" {
		t.Errorf("pkiDir = %q", c.pkiDir)
	}
	if c.db == nil {
		t.Error("db should not be nil")
	}
	if c.tlsCfg != nil {
		t.Error("tlsCfg should be nil before Start")
	}
}

// ── NewVMChecker ────────────────────────────────────────────────────────────

func TestNewVMChecker_Fields(t *testing.T) {
	db := testCoverageDB(t)
	v := NewVMChecker("host-x", db, nil)
	if v.hostName != "host-x" {
		t.Errorf("hostName = %q", v.hostName)
	}
	if v.db == nil {
		t.Error("db should not be nil")
	}
	if v.virt != nil {
		t.Error("virt should be nil")
	}
	if v.failures == nil || v.lastAction == nil || v.actionCount == nil || v.activeActions == nil {
		t.Error("maps should be initialized")
	}
}

// ── parseDuration ───────────────────────────────────────────────────────────

func TestParseDuration_ValidInput(t *testing.T) {
	d := parseDuration("5s", 30*time.Second)
	if d != 5*time.Second {
		t.Errorf("parseDuration('5s') = %v", d)
	}
}

func TestParseDuration_EmptyInput(t *testing.T) {
	d := parseDuration("", 30*time.Second)
	if d != 30*time.Second {
		t.Errorf("parseDuration('') = %v, want 30s", d)
	}
}

func TestParseDuration_InvalidInput(t *testing.T) {
	d := parseDuration("notaduration", 10*time.Second)
	if d != 10*time.Second {
		t.Errorf("parseDuration('notaduration') = %v, want 10s", d)
	}
}

func TestParseDuration_VariousFormats(t *testing.T) {
	tests := []struct {
		input    string
		fallback time.Duration
		want     time.Duration
	}{
		{"1m", time.Second, time.Minute},
		{"500ms", time.Second, 500 * time.Millisecond},
		{"2h", time.Second, 2 * time.Hour},
		{"0s", time.Second, 0},
	}
	for _, tc := range tests {
		got := parseDuration(tc.input, tc.fallback)
		if got != tc.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ── vmCheckSpec ─────────────────────────────────────────────────────────────

func TestVmCheckSpec_EmptySpec(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: ""}
	if vmCheckSpec(vm) != nil {
		t.Error("expected nil for empty spec")
	}
}

func TestVmCheckSpec_InvalidJSON(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: "not json"}
	if vmCheckSpec(vm) != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestVmCheckSpec_NoHealthcheck(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: `{"cpu":1}`}
	if vmCheckSpec(vm) != nil {
		t.Error("expected nil for spec without healthcheck")
	}
}

func TestVmCheckSpec_WithHealthcheck(t *testing.T) {
	spec := &pb.VMSpec{
		Healthcheck: &pb.HealthCheckSpec{
			Type:    "http",
			Target:  "http://10.0.0.1/health",
			Retries: 5,
		},
	}
	data, _ := json.Marshal(spec)
	vm := &corrosion.VMRecord{Spec: string(data)}
	hc := vmCheckSpec(vm)
	if hc == nil {
		t.Fatal("expected non-nil healthcheck")
	}
	if hc.Type != "http" {
		t.Errorf("type = %q", hc.Type)
	}
	if hc.Target != "http://10.0.0.1/health" {
		t.Errorf("target = %q", hc.Target)
	}
	if hc.Retries != 5 {
		t.Errorf("retries = %d", hc.Retries)
	}
}

func TestVmCheckSpec_EmptyHealthcheckType(t *testing.T) {
	spec := &pb.VMSpec{
		Healthcheck: &pb.HealthCheckSpec{Type: ""},
	}
	data, _ := json.Marshal(spec)
	vm := &corrosion.VMRecord{Spec: string(data)}
	hc := vmCheckSpec(vm)
	// Returns the struct, but Type is empty — sweep should skip it.
	if hc == nil {
		t.Fatal("expected non-nil healthcheck struct")
	}
	if hc.Type != "" {
		t.Errorf("type = %q, want empty", hc.Type)
	}
}

// ── vmSpecFromDB ────────────────────────────────────────────────────────────

func TestVmSpecFromDB_InvalidJSON(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-badjson",
		HostName: "node1",
		Spec:     `{invalid json`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	spec := vmSpecFromDB(ctx, db, "vm-badjson")
	if spec != nil {
		t.Error("expected nil for invalid JSON spec")
	}
}

// ── probe: unknown type ─────────────────────────────────────────────────────

func TestProbe_UnknownType_ReturnsTrue(t *testing.T) {
	db := testCoverageDB(t)
	v := NewVMChecker("node1", db, nil)

	hspec := &pb.HealthCheckSpec{
		Type:   "unknown-probe-type",
		Target: "anything",
	}
	result := v.probe(context.Background(), "vm1", hspec, 2*time.Second)
	if !result {
		t.Error("unknown probe type should return true (healthy)")
	}
}

// ── probe: HTTP status codes ────────────────────────────────────────────────

func TestProbe_HTTP_StatusCodes(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{200, true},
		{301, true},
		{404, true},
		{499, true},
		{500, false},
		{502, false},
		{503, false},
	}

	for _, tc := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))

		db := testCoverageDB(t)
		v := NewVMChecker("node1", db, nil)
		hspec := &pb.HealthCheckSpec{Type: "http", Target: srv.URL}
		got := v.probe(context.Background(), "vm1", hspec, 2*time.Second)
		srv.Close()

		if got != tc.want {
			t.Errorf("HTTP %d: probe = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// ── probe: TCP success/failure ──────────────────────────────────────────────

func TestProbe_TCP_Success_Coverage(t *testing.T) {
	// httptest.NewServer creates a TCP listener we can probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	db := testCoverageDB(t)
	v := NewVMChecker("node1", db, nil)
	addr := srv.Listener.Addr().String()
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: addr}
	if !v.probe(context.Background(), "vm1", hspec, 2*time.Second) {
		t.Error("TCP probe to active listener should succeed")
	}
}

func TestProbe_TCP_Failure_Coverage(t *testing.T) {
	db := testCoverageDB(t)
	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Type: "tcp", Target: "127.0.0.1:1"} // Port 1 unlikely open.
	if v.probe(context.Background(), "vm1", hspec, 500*time.Millisecond) {
		t.Error("TCP probe to closed port should fail")
	}
}

// ── probe: exec with nil virt ───────────────────────────────────────────────

func TestProbe_Exec_NilVirt(t *testing.T) {
	db := testCoverageDB(t)
	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Type: "exec", Target: "echo ok"}
	result := v.probe(context.Background(), "vm1", hspec, 2*time.Second)
	if result {
		t.Error("exec probe with nil virt should return false")
	}
}

// ── probe: HTTP invalid URL ─────────────────────────────────────────────────

func TestProbe_HTTP_InvalidURL(t *testing.T) {
	db := testCoverageDB(t)
	v := NewVMChecker("node1", db, nil)
	hspec := &pb.HealthCheckSpec{Type: "http", Target: "://invalid"}
	result := v.probe(context.Background(), "vm1", hspec, 500*time.Millisecond)
	if result {
		t.Error("HTTP probe with invalid URL should fail")
	}
}

// ── checkVM: backoff logic ──────────────────────────────────────────────────

func TestCheckVM_Backoff_PreventsRepeatAction(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 1,
		Action:  "alert",
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-backoff",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-backoff", HostName: "node1", Spec: string(specJSON), State: "running"}

	// First action triggers.
	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	ac1 := v.actionCount["vm-backoff"]
	v.mu.Unlock()
	if ac1 != 1 {
		t.Fatalf("actionCount after first action = %d, want 1", ac1)
	}

	// Second action attempt should be blocked by backoff (30s window).
	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	ac2 := v.actionCount["vm-backoff"]
	v.mu.Unlock()
	if ac2 != 1 {
		t.Errorf("actionCount after backoff = %d, want 1 (should not increment)", ac2)
	}
}

// ── checkVM: max-unavailable per stack ──────────────────────────────────────

func TestCheckVM_MaxUnavailable_BlocksSecondAction(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 1,
		Action:  "alert",
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	// Two VMs in the same stack.
	for _, name := range []string{"vm-stack-1", "vm-stack-2"} {
		err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name:      name,
			HostName:  "node1",
			StackName: "mystack",
			Spec:      string(specJSON),
			State:     "running",
		}, nil, nil)
		if err != nil {
			t.Fatalf("InsertVM(%s): %v", name, err)
		}
	}

	v := NewVMChecker("node1", db, nil)

	// Simulate an active action on the stack.
	v.mu.Lock()
	v.activeActions["mystack"] = 1
	v.mu.Unlock()

	vm2 := corrosion.VMRecord{Name: "vm-stack-2", HostName: "node1", StackName: "mystack", Spec: string(specJSON), State: "running"}

	// Pre-seed failures to threshold so it tries to take action.
	v.mu.Lock()
	v.failures["vm-stack-2"] = 0
	v.mu.Unlock()

	v.checkVM(ctx, vm2, hspec)

	// Should be blocked by max-unavailable — actionCount should remain 0.
	v.mu.Lock()
	ac := v.actionCount["vm-stack-2"]
	v.mu.Unlock()

	if ac != 0 {
		t.Errorf("actionCount = %d, want 0 (blocked by max-unavailable)", ac)
	}
}

// ── checkVM: retries=0 defaults to 3 ───────────────────────────────────────

func TestCheckVM_ZeroRetries_DefaultsToThree(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hspec := &pb.HealthCheckSpec{
		Type:    "http",
		Target:  srv.URL,
		Retries: 0, // Should default to 3.
		Action:  "alert",
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Healthcheck: hspec})

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-retries-default",
		HostName: "node1",
		Spec:     string(specJSON),
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm := corrosion.VMRecord{Name: "vm-retries-default", HostName: "node1", Spec: string(specJSON), State: "running"}

	// Fail twice — should NOT trigger action since default retries is 3.
	v.checkVM(ctx, vm, hspec)
	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	ac := v.actionCount["vm-retries-default"]
	f := v.failures["vm-retries-default"]
	v.mu.Unlock()

	if ac != 0 {
		t.Errorf("actionCount = %d after 2 failures (retries defaults to 3), want 0", ac)
	}
	if f != 2 {
		t.Errorf("failures = %d, want 2", f)
	}

	// Third failure triggers action.
	v.checkVM(ctx, vm, hspec)

	v.mu.Lock()
	ac = v.actionCount["vm-retries-default"]
	v.mu.Unlock()

	if ac != 1 {
		t.Errorf("actionCount = %d after 3 failures, want 1", ac)
	}
}

// ── Checker.probe ───────────────────────────────────────────────────────────

func TestChecker_Probe_ClosedPort(t *testing.T) {
	db := testCoverageDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// Manually set tlsCfg to avoid Start().
	c.tlsCfg = nil

	// probe with nil tlsCfg should fail gracefully.
	result := c.probe("127.0.0.1:1")
	if result {
		t.Error("probe to closed port should return false")
	}
}

// ── Checker.checkClockSkew: boundary ────────────────────────────────────────

func TestCheckClockSkew_ExactlyOneSecond(t *testing.T) {
	db := testCoverageDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	// Exactly 1 second is on the boundary — skew > 1s triggers, so 1s should NOT trigger.
	// However, time.Since introduces slight drift, so use a value slightly under.
	c.checkClockSkew(context.Background(), "host-b", time.Now().Add(-999*time.Millisecond))

	rows, err := db.Query(context.Background(),
		`SELECT target FROM clock_skew WHERE observer = ?`, "host-a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no clock_skew rows for ~1s skew, got %d", len(rows))
	}
}

// ── Reconciler: NewReconciler fields ────────────────────────────────────────

func TestNewReconciler_AllFields(t *testing.T) {
	db := testCoverageDB(t)
	r := NewReconciler("host-x", "/var/lib/litevirt", db, nil)
	if r.hostName != "host-x" {
		t.Errorf("hostName = %q", r.hostName)
	}
	if r.dataDir != "/var/lib/litevirt" {
		t.Errorf("dataDir = %q", r.dataDir)
	}
	if r.db != db {
		t.Error("db mismatch")
	}
	if r.virt != nil {
		t.Error("virt should be nil")
	}
}

// ── Reconciler: pending VM with invalid spec ────────────────────────────────

func TestReconciler_PendingVM_InvalidSpec(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-badspec",
		HostName: "host-a",
		Spec:     `{not valid json`,
		State:    "pending",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", t.TempDir(), db, nil)
	r.reconcile(ctx)

	// VM should transition to error state due to invalid spec.
	vm, err := corrosion.GetVM(ctx, db, "vm-badspec")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Errorf("expected error state for invalid spec, got %q", vm.State)
	}
}

// ── Reconciler: multiple pending VMs with invalid spec ──────────────────────

func TestReconciler_ReconcileMultiplePending_InvalidSpec(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	for _, name := range []string{"vm-p1", "vm-p2", "vm-p3"} {
		err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name:     name,
			HostName: "host-a",
			Spec:     `{not valid json`,
			State:    "pending",
		}, nil, nil)
		if err != nil {
			t.Fatalf("InsertVM(%s): %v", name, err)
		}
	}

	r := NewReconciler("host-a", t.TempDir(), db, nil)
	r.reconcile(ctx)

	// All should transition to error due to invalid JSON spec.
	for _, name := range []string{"vm-p1", "vm-p2", "vm-p3"} {
		vm, _ := corrosion.GetVM(ctx, db, name)
		if vm.State != "error" {
			t.Errorf("%s: state = %q, want error", name, vm.State)
		}
	}
}

// refreshLBForVM was removed — LB refresh is now handled by the full
// MigrateVM RPC path (via migrateVMFunc callback).

// ── pickMigrationTarget: memory accounting ──────────────────────────────────

func TestPickMigrationTarget_AccountsForCreatingVMs(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	for _, h := range []corrosion.HostRecord{
		{Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 8192},
		{Name: "node2", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b", MemTotal: 2048},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}

	// Insert a "creating" VM on node2, using 1500 MiB.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "vm-creating",
		HostName:  "node2",
		Spec:      `{}`,
		State:     "creating",
		MemActual: 1500,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	// node2 has 2048 - 1500 = 548 free. Requesting 1024 should fail.
	_, err = v.pickMigrationTarget(ctx, "node1", 1024)
	if err == nil {
		t.Fatal("expected error: node2 should not have enough memory")
	}
}

// ── checkHost writes to host_health ─────────────────────────────────────────

func TestCheckHost_FailedProbe_WritesHostHealth(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()
	c := NewChecker("observer", "/etc/litevirt/pki", db)
	// nil tlsCfg will cause probe to fail.

	host := corrosion.HostRecord{
		Name:     "target-host",
		Address:  "127.0.0.1",
		GRPCPort: 1, // closed port
	}

	c.checkHost(ctx, host)

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures FROM host_health WHERE observer = ? AND target = ?`,
		"observer", "target-host")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if rows[0].String("status") != "healthy" {
		// First failure: 1 < suspectThreshold (3), so status is "healthy".
		if rows[0].Int("consecutive_failures") != 1 {
			t.Errorf("consecutive_failures = %d, want 1", rows[0].Int("consecutive_failures"))
		}
	}
}

func TestCheckHost_MultipleFailures_BecomesSuspect(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()
	c := NewChecker("observer", "/etc/litevirt/pki", db)

	host := corrosion.HostRecord{
		Name:     "target-host",
		Address:  "127.0.0.1",
		GRPCPort: 1,
	}

	// Fail 3 times (suspectThreshold = 3).
	for i := 0; i < 3; i++ {
		c.checkHost(ctx, host)
	}

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures FROM host_health WHERE observer = ? AND target = ?`,
		"observer", "target-host")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].String("status") != "suspect" {
		t.Errorf("status = %q, want suspect", rows[0].String("status"))
	}
	if rows[0].Int("consecutive_failures") != 3 {
		t.Errorf("consecutive_failures = %d, want 3", rows[0].Int("consecutive_failures"))
	}
}

// ── checkAllPeers: skips self and maintenance ───────────────────────────────

func TestCheckAllPeers_SkipsSelfAndMaintenance(t *testing.T) {
	db := testCoverageDB(t)
	ctx := context.Background()

	for _, h := range []corrosion.HostRecord{
		{Name: "self", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a", MemTotal: 4096},
		{Name: "maint-host", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "maintenance", CertSerial: "b", MemTotal: 4096},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}

	c := NewChecker("self", "/etc/litevirt/pki", db)
	// checkAllPeers should not check self or maintenance hosts.
	// No panics; no host_health rows should be written.
	c.checkAllPeers(ctx)

	rows, _ := db.Query(ctx, `SELECT target FROM host_health WHERE observer = ?`, "self")
	if len(rows) != 0 {
		t.Errorf("expected no host_health rows, got %d", len(rows))
	}
}
