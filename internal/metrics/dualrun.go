package metrics

import "github.com/prometheus/client_golang/prometheus"

// DualRunLabel is one confirmed dual-run finding's gauge label set.
type DualRunLabel struct {
	Kind   string // vm | ct | vip | owner_mismatch | lww_unresolved
	Target string // the workload / VIP / host the finding is about
}

// DualRunMetrics exposes the leader-gated dual-run detector's output as two gauge
// vectors. Both are REBUILT every detector pass (Reset + re-Set) so a finding that
// heals drops its series rather than pinning a stale 1 forever — a healed dual-run
// must not page indefinitely.
type DualRunMetrics struct {
	// detected{kind,target} = 1 while a dual-run condition is CONFIRMED (present on
	// >=2 consecutive passes — a real dual-run persists, a migration cutover does not).
	// `target` is an unbounded label carrying workload/VIP/host names; acceptable here
	// because the metrics endpoint is localhost-bound and the confirmed set is tiny (a
	// genuine dual-run is rare).
	detected *prometheus.GaugeVec
	// probeFailed{host} = 1 while the leader could not gather a workload-capable host's
	// runtime THIS pass (e.g. a permanently network-segmented peer). A coverage gap,
	// surfaced immediately — never a silent skip. Distinct from detected: a gap in what
	// the detector can see, not a dual-run it saw.
	probeFailed *prometheus.GaugeVec
}

// NewDualRunMetrics registers the gauges on the default registry.
func NewDualRunMetrics() *DualRunMetrics { return newDualRunMetrics(prometheus.DefaultRegisterer) }

// NewDualRunMetricsWith registers the gauges on the given registry — for callers (tests
// across packages) that need an isolated registry to introspect the emitted series.
func NewDualRunMetricsWith(reg prometheus.Registerer) *DualRunMetrics { return newDualRunMetrics(reg) }

// newDualRunMetrics is the test seam (fresh registry per test).
func newDualRunMetrics(reg prometheus.Registerer) *DualRunMetrics {
	m := &DualRunMetrics{
		detected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_dual_run_detected",
			Help: "A confirmed dual-run condition (1) by kind + target; leader-gated, alert-only, rebuilt each pass.",
		}, []string{"kind", "target"}),
		probeFailed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_dual_run_probe_failed",
			Help: "A workload-capable host the dual-run leader could not probe this pass (1); a coverage gap, not a dual-run.",
		}, []string{"host"}),
	}
	reg.MustRegister(m.detected, m.probeFailed)
	return m
}

// SetDetected rebuilds the confirmed-findings gauge set. Nil-safe.
func (m *DualRunMetrics) SetDetected(labels []DualRunLabel) {
	if m == nil {
		return
	}
	m.detected.Reset()
	for _, l := range labels {
		m.detected.WithLabelValues(l.Kind, l.Target).Set(1)
	}
}

// SetProbeFailed rebuilds the probe-failure gauge set. Nil-safe.
func (m *DualRunMetrics) SetProbeFailed(hosts []string) {
	if m == nil {
		return
	}
	m.probeFailed.Reset()
	for _, h := range hosts {
		m.probeFailed.WithLabelValues(h).Set(1)
	}
}
