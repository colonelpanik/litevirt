package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestDualRunMetrics_RebuildDropsHealedSeries guards the "rebuild each pass" contract:
// a finding that heals must lose its gauge series, not pin a stale 1 forever (else a
// resolved dual-run pages indefinitely).
func TestDualRunMetrics_RebuildDropsHealedSeries(t *testing.T) {
	m := newDualRunMetrics(prometheus.NewRegistry())

	m.SetDetected([]DualRunLabel{{Kind: "vm", Target: "a"}, {Kind: "vip", Target: "10.0.0.1"}})
	if got := testutil.ToFloat64(m.detected.WithLabelValues("vm", "a")); got != 1 {
		t.Fatalf("detected vm/a = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.detected); got != 2 {
		t.Fatalf("detected series = %d, want 2", got)
	}

	// A pass without vm/a must DROP its series, keeping only the still-present vip.
	m.SetDetected([]DualRunLabel{{Kind: "vip", Target: "10.0.0.1"}})
	if got := testutil.CollectAndCount(m.detected); got != 1 {
		t.Fatalf("detected series = %d, want 1 (vm/a should have cleared)", got)
	}
	if got := testutil.ToFloat64(m.detected.WithLabelValues("vip", "10.0.0.1")); got != 1 {
		t.Fatalf("detected vip = %v, want 1", got)
	}

	// Full heal -> no series.
	m.SetDetected(nil)
	if got := testutil.CollectAndCount(m.detected); got != 0 {
		t.Fatalf("detected series = %d, want 0 after full heal", got)
	}

	// probe_failed rebuilds the same way and reflects the pass IMMEDIATELY.
	m.SetProbeFailed([]string{"h1", "h2"})
	if got := testutil.CollectAndCount(m.probeFailed); got != 2 {
		t.Fatalf("probe_failed series = %d, want 2", got)
	}
	if got := testutil.ToFloat64(m.probeFailed.WithLabelValues("h1")); got != 1 {
		t.Fatalf("probe_failed h1 = %v, want 1", got)
	}
	m.SetProbeFailed(nil)
	if got := testutil.CollectAndCount(m.probeFailed); got != 0 {
		t.Fatalf("probe_failed series = %d, want 0 after clear", got)
	}
}

// TestDualRunMetrics_NilSafe: an unwired detector (metrics nil) must not panic.
func TestDualRunMetrics_NilSafe(t *testing.T) {
	var m *DualRunMetrics
	m.SetDetected([]DualRunLabel{{Kind: "vm", Target: "x"}})
	m.SetProbeFailed([]string{"x"})
}
