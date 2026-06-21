package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/corrosion"
)

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
	c := newCollector(db, nil, "host-a")

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
	c := newCollector(db, nil, "host-a")

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
