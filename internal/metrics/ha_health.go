package metrics

import "github.com/prometheus/client_golang/prometheus"

// HAHealthMetrics exposes PERSISTENT "HA degraded" status as a gauge (1 = degraded,
// 0 = healthy) keyed by a CLOSED reason vocabulary — the plan's requirement that these
// conditions surface as a durable status, not merely a per-refusal counter:
//   - unsupported_member   : an enforcement-relevant member can't be confirmed to support
//     a flipped capability (unreachable / old binary) → enforcement
//     (and thus HA) is held back cluster-wide. Carries operator
//     intent: a flag was turned on and the cluster has not
//     confirmed it. Also covers a MANDATORY token that latched and
//     later regressed.
//   - capability_rollout_pending : a MANDATORY token (no config flag — see
//     capabilities.MandatoryTokens) has not latched YET. The ordinary state of
//     every cluster part-way through an upgrade, and permanent on one
//     deliberately held with a host back, so it is deliberately NOT
//     unsupported_member: there is no operator intent to have been let down and
//     nothing to turn off, the only remedy being to finish the roll. Alert on it
//     differently — a planned rollout is not a fault, a stalled one is worth a
//     look.
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
	// featureDegraded is the per-token breakdown of `degraded{reason=
	// "unsupported_member"}`, which is a single boolean shared by every
	// configured token and so cannot say WHICH one is unconfirmed.
	//
	// It is not derivable from the two gauges above. config-on-and-not-latched
	// covers the enable window, but a token that latched and then REGRESSED — the
	// freshness check finding a peer no longer advertising it — still reads
	// latched=1, and that is exactly the case the durable marker cannot show.
	featureDegraded *prometheus.GaugeVec
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
		featureDegraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_enforcement_degraded",
			Help: "Whether a capability this node is configured to enforce is unconfirmed cluster-wide (1 = degraded). The per-feature breakdown of litevirt_ha_degraded{reason=\"unsupported_member\"}.",
		}, []string{"feature"}),
	}
	reg.MustRegister(m.degraded, m.configEnabled, m.latched, m.featureDegraded)
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

// SetDegraded records whether one feature is degraded — configured to enforce
// here, and not confirmed cluster-wide. Nil-safe.
//
// The CALLER must write every supported token every cycle, including the false
// case and including tokens this node does not enforce. A gauge is only ever as
// current as its last write: skipping the healthy tokens leaves a feature that
// was degraded and has since recovered — or been switched off entirely — reading
// 1 for the life of the process, which is worse than not publishing it at all.
// RunHAHealthMonitor does this in the same loop as SetEnforcement.
func (m *HAHealthMetrics) SetDegraded(feature string, degraded bool) {
	if m == nil {
		return
	}
	m.featureDegraded.WithLabelValues(feature).Set(b2f(degraded))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
