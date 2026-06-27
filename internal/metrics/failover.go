package metrics

import "github.com/prometheus/client_golang/prometheus"

// FailoverMetrics holds Prometheus counters for the failover coordinator's
// decisions, per-VM/container actions, and (previously swallowed) errors — U9.
// Labels are a bounded CLOSED vocabulary (see internal/failover/metrics.go):
// phases × results × error-classes is a few hundred series at most, and never
// includes a host/vm/container NAME (which would be unbounded). It structurally
// satisfies failover.Metrics, so the failover package never imports this one.
type FailoverMetrics struct {
	attempts         *prometheus.CounterVec
	vmActions        *prometheus.CounterVec
	containerActions *prometheus.CounterVec
}

// NewFailoverMetrics registers the failover counters on the default registry
// (which promhttp serves at :7444). Call once at daemon startup.
func NewFailoverMetrics() *FailoverMetrics {
	return newFailoverMetrics(prometheus.DefaultRegisterer)
}

// newFailoverMetrics is the test seam: tests pass a fresh prometheus.NewRegistry()
// so repeated construction across test funcs doesn't panic on duplicate registration.
func newFailoverMetrics(reg prometheus.Registerer) *FailoverMetrics {
	m := &FailoverMetrics{
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_failover_attempts_total",
			Help: "Failover decision points, by phase, result, and error class.",
		}, []string{"phase", "result", "error_class"}),
		vmActions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_failover_vm_actions_total",
			Help: "Per-VM failover actions (promote, reschedule), by result and error class.",
		}, []string{"action", "result", "error_class"}),
		containerActions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_failover_container_actions_total",
			Help: "Per-container failover actions (relocate), by result and error class.",
		}, []string{"action", "result", "error_class"}),
	}
	reg.MustRegister(m.attempts, m.vmActions, m.containerActions)
	return m
}

// Attempt records a failover decision point. (Satisfies failover.Metrics.)
func (m *FailoverMetrics) Attempt(phase, result, errorClass string) {
	m.attempts.WithLabelValues(phase, result, errorClass).Inc()
}

// VMAction records a per-VM failover action outcome.
func (m *FailoverMetrics) VMAction(action, result, errorClass string) {
	m.vmActions.WithLabelValues(action, result, errorClass).Inc()
}

// ContainerAction records a per-container failover action outcome.
func (m *FailoverMetrics) ContainerAction(action, result, errorClass string) {
	m.containerActions.WithLabelValues(action, result, errorClass).Inc()
}
