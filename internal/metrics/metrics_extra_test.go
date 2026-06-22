package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// gaugeValue drains ch, returning the value of the first metric whose
// descriptor mentions name (and whether one was found).
func gaugeValue(t *testing.T, ch <-chan prometheus.Metric, name string) (float64, bool) {
	t.Helper()
	for m := range ch {
		if !containsStr(m.Desc().String(), name) {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			t.Fatalf("write metric %s: %v", name, err)
		}
		return dm.GetGauge().GetValue(), true
	}
	return 0, false
}

func insertLogRows(t *testing.T, db *corrosion.Client, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if err := db.Execute(ctx,
			`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES ('0','n','x', datetime('now'))`); err != nil {
			t.Fatalf("insert mutation_log: %v", err)
		}
	}
}

// litevirt_replication_pending_entries = MAX(seq) - MIN(live last_seq).
func TestCollect_ReplicationPending(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	insertLogRows(t, db, 10)
	// seq is AUTOINCREMENT (InitSchema advances it) and db.Execute itself logs a
	// mutation row, so don't hardcode an absolute value: place a live peer a few
	// entries behind MAX(seq), then compare the gauge against the same MAX(seq) -
	// MIN(live last_seq) the collector computes (no writes happen after this, so
	// the two reads agree).
	rows, err := db.Query(ctx, `SELECT COALESCE(MAX(seq),0) AS m FROM mutation_log`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("max seq: %v", err)
	}
	if err := db.Execute(ctx,
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)`,
		"peer-a", rows[0].Int("m")-3, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert watermark: %v", err)
	}

	liveCutoff := time.Now().Add(-corrosion.LiveWatermarkWindow).UTC().Format(time.RFC3339)
	wm, _ := db.Query(ctx, `SELECT COALESCE(MIN(last_seq),0) AS m FROM replication_watermarks WHERE updated_at > ?`, liveCutoff)
	mx, _ := db.Query(ctx, `SELECT COALESCE(MAX(seq),0) AS m FROM mutation_log`)
	want := float64(mx[0].Int("m") - wm[0].Int("m"))
	if want <= 0 {
		t.Fatalf("test setup: expected a positive backlog, got %v", want)
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	got, found := gaugeValue(t, ch, "litevirt_replication_pending_entries")
	if !found {
		t.Fatal("missing litevirt_replication_pending_entries metric")
	}
	if got != want {
		t.Fatalf("pending = %v, want %v (MAX(seq) - MIN(live last_seq))", got, want)
	}
}

// With no LIVE peers the backlog is reported as 0, not the whole log — a single
// or fully-partitioned node has nothing to replicate to.
func TestCollect_ReplicationPending_NoLivePeers(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	insertLogRows(t, db, 5)
	// A watermark exists but is stale (outside LiveWatermarkWindow) → excluded.
	if err := db.Execute(ctx,
		`INSERT INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)`,
		"stale", 1, time.Now().Add(-2*corrosion.LiveWatermarkWindow).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert watermark: %v", err)
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	got, found := gaugeValue(t, ch, "litevirt_replication_pending_entries")
	if !found {
		t.Fatal("missing litevirt_replication_pending_entries metric")
	}
	if got != 0 {
		t.Fatalf("pending = %v, want 0 (no live peers)", got)
	}
}

func initTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCollect_WithVMs(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	// Insert host.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:     "host-a",
		State:    "active",
		CPUTotal: 16,
		MemTotal: 65536,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	// Insert VMs.
	for _, vm := range []corrosion.VMRecord{
		{Name: "vm1", StackName: "stack1", HostName: "host-a", Spec: "{}", State: "running", CPUActual: 2, MemActual: 4096},
		{Name: "vm2", StackName: "stack1", HostName: "host-a", Spec: "{}", State: "stopped", CPUActual: 1, MemActual: 2048},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.Name, err)
		}
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	// Should have: hostCPUTotal, hostMemTotal, hostVMCount, 2x vmState, 2x vmCPU, 2x vmMemory, daemonOpenFDs = 10+
	if len(metrics) < 8 {
		t.Errorf("Collect with VMs emitted %d metrics, expected >= 8", len(metrics))
	}

	// Check for specific metric names in descriptions.
	foundVMCount := false
	foundCPUTotal := false
	foundMemTotal := false
	foundVMState := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if containsStr(desc, "litevirt_host_vm_count") {
			foundVMCount = true
		}
		if containsStr(desc, "litevirt_host_cpu_total") {
			foundCPUTotal = true
		}
		if containsStr(desc, "litevirt_host_memory_total_mib") {
			foundMemTotal = true
		}
		if containsStr(desc, "litevirt_vm_state") {
			foundVMState = true
		}
	}
	if !foundVMCount {
		t.Error("missing litevirt_host_vm_count metric")
	}
	if !foundCPUTotal {
		t.Error("missing litevirt_host_cpu_total metric")
	}
	if !foundMemTotal {
		t.Error("missing litevirt_host_memory_total_mib metric")
	}
	if !foundVMState {
		t.Error("missing litevirt_vm_state metric")
	}
}

func TestCollect_WithPeerHealth(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	// Insert health records.
	if err := db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, updated_at) VALUES (?, ?, ?, datetime('now'))`,
		"host-a", "host-b", "healthy"); err != nil {
		t.Fatalf("insert health: %v", err)
	}
	if err := db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, updated_at) VALUES (?, ?, ?, datetime('now'))`,
		"host-a", "host-c", "unhealthy"); err != nil {
		t.Fatalf("insert health: %v", err)
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	foundPeerHealthy := 0
	for m := range ch {
		if containsStr(m.Desc().String(), "litevirt_peer_healthy") {
			foundPeerHealthy++
		}
	}
	if foundPeerHealthy != 2 {
		t.Errorf("expected 2 peer_healthy metrics, got %d", foundPeerHealthy)
	}
}

func TestCollect_WithClockSkew(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	// updated_at must be RFC3339 (matching internal/health/checker.go) so it
	// passes the collector's freshness cutoff — datetime('now')'s space format
	// mis-sorts against the 'T'-separated cutoff and would read as stale.
	if err := db.Execute(ctx,
		`INSERT INTO clock_skew (observer, target, skew_seconds, updated_at)
		 VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		"host-a", "host-b", 5); err != nil {
		t.Fatalf("insert clock_skew: %v", err)
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	found := false
	for m := range ch {
		if containsStr(m.Desc().String(), "litevirt_cluster_clock_skew_seconds") {
			found = true
		}
	}
	if !found {
		t.Error("missing clock_skew metric")
	}
}

func TestCollect_WithSnapshots(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	// Insert snapshot records.
	for _, snap := range []struct {
		vmName string
		name   string
	}{
		{"vm-snap", "snap1"},
		{"vm-snap", "snap2"},
		{"vm-snap", "snap3"},
	} {
		if err := db.Execute(ctx,
			`INSERT INTO snapshots (id, vm_name, name, host_name, state, created_at, updated_at) VALUES (?, ?, ?, 'host-a', 'created', datetime('now'), datetime('now'))`,
			snap.vmName+"-"+snap.name, snap.vmName, snap.name); err != nil {
			t.Fatalf("insert snapshot: %v", err)
		}
	}

	c := newCollector(db, nil, "host-a")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	found := false
	for m := range ch {
		if containsStr(m.Desc().String(), "litevirt_vm_snapshot_chain_depth") {
			found = true
		}
	}
	if !found {
		t.Error("missing snapshot_chain_depth metric")
	}
}

func TestDescribe_AllDescsExtra(t *testing.T) {
	db := initTestDB(t)
	c := newCollector(db, nil, "host-test")

	ch := make(chan *prometheus.Desc, 64)
	c.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	// Describe should emit at least 10 descriptors.
	if count < 10 {
		t.Errorf("Describe emitted %d descriptors, want >= 10", count)
	}
}

func TestHandleStatus_Method(t *testing.T) {
	db := initTestDB(t)
	s := NewServer(7444, "", db, nil, "host-a")

	// Test with POST — should still work (no method restriction).
	req := httptest.NewRequest("POST", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewServer_Fields(t *testing.T) {
	db := initTestDB(t)
	s := NewServer(9999, "", db, nil, "myhost")
	if s.port != 9999 {
		t.Errorf("port = %d", s.port)
	}
	if s.hostName != "myhost" {
		t.Errorf("hostName = %q", s.hostName)
	}
	if s.virt != nil {
		t.Error("virt should be nil when not provided")
	}
}

func TestStop_NilHttpSrv(t *testing.T) {
	s := &Server{} // httpSrv is nil.
	// Should not panic.
	s.Stop(context.Background())
}

func TestCollect_NoHost(t *testing.T) {
	db := initTestDB(t)
	// Collector with a host name that doesn't exist.
	c := newCollector(db, nil, "nonexistent-host")
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// Should still emit at least VM count (0) and FD metric.
	count := 0
	for range ch {
		count++
	}
	if count < 1 {
		t.Errorf("expected at least 1 metric even with no host, got %d", count)
	}
}
