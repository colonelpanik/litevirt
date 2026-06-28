package metrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Container metrics are emitted by the collector: state (1=running, 0=other),
// declared cpu/mem limits, and a per-host count — none existed before A3.
func TestCollect_ContainerMetrics(t *testing.T) {
	db := testCollectorDB(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "running", CPULimit: 2, MemMiB: 512,
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "dbct", State: "stopped", CPULimit: 1, MemMiB: 256,
	}); err != nil {
		t.Fatal(err)
	}

	c := newCollector(db, nil, nil, "host-a")
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)

	names := map[string]bool{}
	stateByName := map[string]float64{}
	want := []string{"litevirt_container_state", "litevirt_container_cpu_limit", "litevirt_container_memory_limit_mib", "litevirt_host_container_count"}
	for m := range ch {
		d := m.Desc().String()
		for _, n := range want {
			if containsStr(d, n) {
				names[n] = true
			}
		}
		if containsStr(d, "litevirt_container_state") {
			var dm dto.Metric
			if m.Write(&dm) == nil {
				ctName := ""
				for _, l := range dm.GetLabel() {
					if l.GetName() == "container" {
						ctName = l.GetValue()
					}
				}
				stateByName[ctName] = dm.GetGauge().GetValue()
			}
		}
	}
	for _, n := range want {
		if !names[n] {
			t.Errorf("collector did not emit %s", n)
		}
	}
	if stateByName["web"] != 1 || stateByName["dbct"] != 0 {
		t.Errorf("container_state = %+v, want web=1 (running) dbct=0 (stopped)", stateByName)
	}
}

// fakeCtStat scripts container cgroup usage; an unknown name → ErrStatsUnavailable.
type fakeCtStat struct{ m map[string]lxc.ContainerStats }

func (f fakeCtStat) Stats(_ context.Context, name string) (lxc.ContainerStats, error) {
	if st, ok := f.m[name]; ok {
		return st, nil
	}
	return lxc.ContainerStats{}, lxc.ErrStatsUnavailable
}

// TestCollect_ContainerUsageMetrics: with a runtime wired, the collector emits
// live cgroup cpu/mem usage for RUNNING containers it can stat, and skips both
// stopped containers and running ones whose stats are unavailable (no panic).
func TestCollect_ContainerUsageMetrics(t *testing.T) {
	db := testCollectorDB(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// "web" running + statable; "ghost" running but unstatable; "idle" stopped.
	for _, c := range []corrosion.ContainerRecord{
		{HostName: "host-a", Name: "web", State: "running", CPULimit: 2, MemMiB: 512},
		{HostName: "host-a", Name: "ghost", State: "running", CPULimit: 1, MemMiB: 256},
		{HostName: "host-a", Name: "idle", State: "stopped", CPULimit: 1, MemMiB: 256},
	} {
		if err := corrosion.UpsertContainer(ctx, db, c); err != nil {
			t.Fatal(err)
		}
	}
	st := fakeCtStat{m: map[string]lxc.ContainerStats{
		"web":  {CPUUsageUsec: 5_000_000, MemBytes: 1 << 20}, // 5s, 1 MiB
		"idle": {CPUUsageUsec: 9_000_000, MemBytes: 9 << 20}, // stopped → must NOT be sampled
	}}

	c := newCollector(db, nil, st, "host-a")
	ch := make(chan prometheus.Metric, 400)
	c.Collect(ch)
	close(ch)

	cpuByName := map[string]float64{}
	memByName := map[string]float64{}
	for m := range ch {
		d := m.Desc().String()
		var dm dto.Metric
		if m.Write(&dm) != nil {
			continue
		}
		name := ""
		for _, l := range dm.GetLabel() {
			if l.GetName() == "container" {
				name = l.GetValue()
			}
		}
		if containsStr(d, "litevirt_container_cpu_seconds_total") {
			cpuByName[name] = dm.GetCounter().GetValue()
		}
		if containsStr(d, "litevirt_container_memory_bytes") {
			memByName[name] = dm.GetGauge().GetValue()
		}
	}
	if cpuByName["web"] != 5.0 {
		t.Errorf("web cpu_seconds_total = %v, want 5", cpuByName["web"])
	}
	if memByName["web"] != float64(1<<20) {
		t.Errorf("web memory_bytes = %v, want %d", memByName["web"], 1<<20)
	}
	if _, ok := cpuByName["ghost"]; ok {
		t.Error("unstatable running container should be skipped, not emitted")
	}
	if _, ok := cpuByName["idle"]; ok {
		t.Error("stopped container must not have usage sampled")
	}
}

func testCollectorDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDescribe_AllDescs(t *testing.T) {
	db := testCollectorDB(t)
	c := newCollector(db, nil, nil, "host-a")

	// Buffer must be large enough to absorb every Desc emit; keep it
	// loose so adding metrics doesn't deadlock the test.
	ch := make(chan *prometheus.Desc, 64)
	c.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}

	// We expect at least 10 descriptors:
	// hostVMCount, hostCPUTotal, hostMemTotal, vmState, vmCPU, vmMemory,
	// peerHealthy, daemonOpenFDs, clockSkew, snapshotDepth
	if len(descs) < 10 {
		t.Errorf("Describe emitted %d descriptors, want >= 10", len(descs))
	}

	// Verify the new metric descriptors are present by checking their string representations.
	descStrs := make(map[string]bool)
	for _, d := range descs {
		descStrs[d.String()] = true
	}

	wantMetrics := []string{
		"litevirt_daemon_open_fds",
		"litevirt_cluster_clock_skew_seconds",
		"litevirt_vm_snapshot_chain_depth",
	}
	for _, name := range wantMetrics {
		found := false
		for s := range descStrs {
			if containsStr(s, name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Describe missing metric %q", name)
		}
	}
}

func TestCollect_EmitsFDMetric(t *testing.T) {
	db := testCollectorDB(t)
	c := newCollector(db, nil, nil, "host-a")

	ch := make(chan prometheus.Metric, 50)
	c.Collect(ch)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	// At minimum, we should get: hostVMCount + daemonOpenFDs.
	// The FD metric should always be present (we can always read /proc/self/fd).
	if len(metrics) < 1 {
		t.Errorf("Collect emitted %d metrics, expected >= 1", len(metrics))
	}

	// Check that at least one metric description contains "open_fds".
	foundFDs := false
	for _, m := range metrics {
		if containsStr(m.Desc().String(), "litevirt_daemon_open_fds") {
			foundFDs = true
			break
		}
	}
	if !foundFDs {
		t.Error("Collect did not emit daemonOpenFDs metric")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
