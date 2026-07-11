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
	// configEnabled = local config INTENT (the enforcement kill-switch flag);
	// latched = the durable capability marker is present. Both are needed to debug a
	// rollout: config-on-but-not-latched flags the enable window (or a broken Ping
	// path); latched-but-config-off flags a stale marker on a disabled feature.
	configEnabled *prometheus.GaugeVec
	latched       *prometheus.GaugeVec
}

// NewHAHealthMetrics registers the gauges on the default registry.
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
		configEnabled: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_enforcement_config_enabled",
			Help: "Per-node config intent for a capability kill-switch (1 = flag on). Not proof of enforcement — see litevirt_enforcement_latched.",
		}, []string{"feature"}),
		latched: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_enforcement_latched",
			Help: "Whether a capability token's durable enforcement latch is established on this node (1 = latched).",
		}, []string{"feature"}),
	}
	reg.MustRegister(m.degraded, m.configEnabled, m.latched)
	return m
}

// Set marks a reason degraded (on=true) or healthy (on=false). Nil-safe.
func (m *HAHealthMetrics) Set(reason string, on bool) {
	if m == nil {
		return
	}
	m.degraded.WithLabelValues(reason).Set(b2f(on))
}

// SetEnforcement records config intent (configEnabled) and latch state (latched)
// for one feature. Nil-safe.
func (m *HAHealthMetrics) SetEnforcement(feature string, configEnabled, latched bool) {
	if m == nil {
		return
	}
	m.configEnabled.WithLabelValues(feature).Set(b2f(configEnabled))
	m.latched.WithLabelValues(feature).Set(b2f(latched))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
