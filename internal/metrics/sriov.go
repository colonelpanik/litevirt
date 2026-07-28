package metrics

import "github.com/prometheus/client_golang/prometheus"

// SRIOVMetrics exposes SR-IOV policy-enforcement health: a persistent "degraded"
// gauge keyed by a CLOSED reason vocabulary (aggregated across all PFs — a reason is
// 1 while ANY managed PF has it), plus a transition-only over-cap counter.
//
// Reasons:
//   - pf_not_found  : a configured managed PF BDF is malformed or absent from the host.
//   - pf_not_sriov  : a configured managed PF exists but is not SR-IOV capable.
//   - vfs_over_cap  : a PF already has more VFs than max_vfs_per_pf — litevirt won't
//     resize it; only reuse of existing free VFs is allowed there.
//   - short_create  : a VF-pool creation produced fewer VFs than requested.
type SRIOVMetrics struct {
	degraded    *prometheus.GaugeVec
	overcapTrip *prometheus.CounterVec
}

// NewSRIOVMetrics registers the gauges on the default registry.
func NewSRIOVMetrics() *SRIOVMetrics {
	return newSRIOVMetrics(prometheus.DefaultRegisterer)
}

// newSRIOVMetrics is the test seam (fresh registry per test).
func newSRIOVMetrics(reg prometheus.Registerer) *SRIOVMetrics {
	m := &SRIOVMetrics{
		degraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_sriov_degraded",
			Help: "SR-IOV policy-enforcement degraded status (1 = degraded, 0 = healthy) by reason, aggregated across all managed PFs.",
		}, []string{"reason"}),
		overcapTrip: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_sriov_overcap_transitions_total",
			Help: "Count of times a PF transitioned into the over-cap state (more VFs than max_vfs_per_pf).",
		}, []string{"pf"}),
	}
	reg.MustRegister(m.degraded, m.overcapTrip)
	// Initialize the closed reason set to 0 so absence reads as healthy, not missing.
	for _, r := range []string{"pf_not_found", "pf_not_sriov", "vfs_over_cap", "short_create"} {
		m.degraded.WithLabelValues(r).Set(0)
	}
	return m
}

// SetDegraded marks a reason degraded (on=true) or healthy (on=false). Nil-safe.
func (m *SRIOVMetrics) SetDegraded(reason string, on bool) {
	if m == nil {
		return
	}
	m.degraded.WithLabelValues(reason).Set(b2f(on))
}

// OvercapTripped records a PF entering the over-cap state (transition only). Nil-safe.
func (m *SRIOVMetrics) OvercapTripped(pf string) {
	if m == nil {
		return
	}
	m.overcapTrip.WithLabelValues(pf).Inc()
}
