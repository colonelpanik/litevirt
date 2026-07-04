package metrics

import "github.com/prometheus/client_golang/prometheus"

// RuntimeGateMetrics counts split-brain safety-gate refusals (Phase 1). Labels
// are a bounded CLOSED vocabulary — {action} × {reason} from
// internal/health/gate.go — never a host/vm NAME. It structurally satisfies the
// nil-safe `func(action, reason string)` observers on the failover coordinator
// and health reconciler, so those packages never import this one.
type RuntimeGateMetrics struct {
	refused *prometheus.CounterVec
}

// NewRuntimeGateMetrics registers the refusal counter on the default registry.
// Call once at daemon startup.
func NewRuntimeGateMetrics() *RuntimeGateMetrics {
	return newRuntimeGateMetrics(prometheus.DefaultRegisterer)
}

// newRuntimeGateMetrics is the test seam (fresh registry per test).
func newRuntimeGateMetrics(reg prometheus.Registerer) *RuntimeGateMetrics {
	m := &RuntimeGateMetrics{
		refused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_runtime_action_refused_total",
			Help: "Dangerous runtime-ownership actions refused by the split-brain gate, by action and reason.",
		}, []string{"action", "reason"}),
	}
	reg.MustRegister(m.refused)
	return m
}

// Refused records one gate/proof refusal. Safe to pass as the observer func.
func (m *RuntimeGateMetrics) Refused(action, reason string) {
	m.refused.WithLabelValues(action, reason).Inc()
}
