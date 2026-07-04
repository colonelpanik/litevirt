package metrics

import "github.com/prometheus/client_golang/prometheus"

// HAHealthMetrics exposes PERSISTENT "HA degraded" status as a gauge (1 = degraded,
// 0 = healthy) keyed by a CLOSED reason vocabulary — the plan's requirement that these
// conditions surface as a durable status, not merely a per-refusal counter:
//   - unsupported_member   : an enforcement-relevant member can't be confirmed to support
//     a flipped capability (unreachable / old binary) → enforcement
//     (and thus HA) is held back cluster-wide.
//   - demotion_unfenced    : a minority node's VIP self-demote FAILED and it has no verified
//     self-fence, so the majority holds in the safe gap (no reclaim
//     without proof) → a VIP outage until repaired / a fence is provided.
//   - vip_no_holder        : a configured VIP is served by NOBODY (e.g. the symmetric-
//     partition self-demote-and-refuse outcome) → a full VIP outage.
type HAHealthMetrics struct {
	degraded *prometheus.GaugeVec
}

// NewHAHealthMetrics registers the gauge on the default registry.
func NewHAHealthMetrics() *HAHealthMetrics {
	return newHAHealthMetrics(prometheus.DefaultRegisterer)
}

// newHAHealthMetrics is the test seam (fresh registry per test).
func newHAHealthMetrics(reg prometheus.Registerer) *HAHealthMetrics {
	m := &HAHealthMetrics{
		degraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_ha_degraded",
			Help: "HA-degraded status (1 = degraded, 0 = healthy) by reason; a persistent alertable signal.",
		}, []string{"reason"}),
	}
	reg.MustRegister(m.degraded)
	return m
}

// Set marks a reason degraded (on=true) or healthy (on=false). Nil-safe.
func (m *HAHealthMetrics) Set(reason string, on bool) {
	if m == nil {
		return
	}
	v := 0.0
	if on {
		v = 1
	}
	m.degraded.WithLabelValues(reason).Set(v)
}
