package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSRIOVMetrics_DegradedGauge(t *testing.T) {
	m := newSRIOVMetrics(prometheus.NewRegistry())

	// Closed reason set initializes to 0 (healthy, not missing).
	if v := testutil.ToFloat64(m.degraded.WithLabelValues("vfs_over_cap")); v != 0 {
		t.Errorf("initial vfs_over_cap = %v, want 0", v)
	}
	m.SetDegraded("vfs_over_cap", true)
	if v := testutil.ToFloat64(m.degraded.WithLabelValues("vfs_over_cap")); v != 1 {
		t.Errorf("after set: vfs_over_cap = %v, want 1", v)
	}
	m.SetDegraded("vfs_over_cap", false)
	if v := testutil.ToFloat64(m.degraded.WithLabelValues("vfs_over_cap")); v != 0 {
		t.Errorf("after clear: vfs_over_cap = %v, want 0", v)
	}
}

func TestSRIOVMetrics_OvercapCounter(t *testing.T) {
	m := newSRIOVMetrics(prometheus.NewRegistry())
	m.OvercapTripped("0000:41:00.0")
	m.OvercapTripped("0000:41:00.0")
	if v := testutil.ToFloat64(m.overcapTrip.WithLabelValues("0000:41:00.0")); v != 2 {
		t.Errorf("overcap transitions = %v, want 2", v)
	}
}

func TestSRIOVMetrics_NilSafe(t *testing.T) {
	var m *SRIOVMetrics
	m.SetDegraded("vfs_over_cap", true) // must not panic
	m.OvercapTripped("x")
}
