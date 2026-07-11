package metrics

import "github.com/prometheus/client_golang/prometheus"

// StateWriteMetrics counts authoritative ownership/state writes to Corrosion that
// failed and were previously swallowed. Labels are a bounded CLOSED vocabulary —
// {op} × {error_class} from internal/corrosion (writeobs.go) — never a host/vm
// NAME. It structurally satisfies the nil-safe `func(op, class string)` observers
// wired into the health, failover, and grpcapi subsystems, so those packages never
// import this one.
type StateWriteMetrics struct {
	failures *prometheus.CounterVec
}

// NewStateWriteMetrics registers the counter on the default registry (served by
// promhttp at :7444). Call once at daemon startup.
func NewStateWriteMetrics() *StateWriteMetrics {
	return newStateWriteMetrics(prometheus.DefaultRegisterer)
}

// newStateWriteMetrics is the test seam (fresh registry per test).
func newStateWriteMetrics(reg prometheus.Registerer) *StateWriteMetrics {
	m := &StateWriteMetrics{
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_state_write_failures_total",
			Help: "Authoritative ownership/state writes to Corrosion that failed, by op and error class.",
		}, []string{"op", "error_class"}),
	}
	reg.MustRegister(m.failures)
	return m
}

// Failed records one dropped/failed authoritative write. Safe to pass as the
// `func(op, class string)` observer.
func (m *StateWriteMetrics) Failed(op, class string) {
	m.failures.WithLabelValues(op, class).Inc()
}
