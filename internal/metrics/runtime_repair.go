package metrics

import "github.com/prometheus/client_golang/prometheus"

// RuntimeRepairMetrics counts the outcomes of the runtime ownership repairs — the
// VM owner-assert (Phase 3) and the container re-key (Phase 4). The reconcilers
// stay free of a Prometheus dependency by exposing nil-safe observer callbacks
// the daemon wires to OwnerAssert.
type RuntimeRepairMetrics struct {
	ownerAssert *prometheus.CounterVec
}

// NewRuntimeRepairMetrics registers litevirt_runtime_owner_assert_total on the
// default registry. Call once at daemon startup.
func NewRuntimeRepairMetrics() *RuntimeRepairMetrics {
	return newRuntimeRepairMetrics(prometheus.DefaultRegisterer)
}

func newRuntimeRepairMetrics(reg prometheus.Registerer) *RuntimeRepairMetrics {
	m := &RuntimeRepairMetrics{
		ownerAssert: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_runtime_owner_assert_total",
			Help: "Runtime ownership repair outcomes, by workload kind (vm|ct) and result (asserted|rekeyed|split_brain|inconclusive|error).",
		}, []string{"kind", "result"}),
	}
	reg.MustRegister(m.ownerAssert)
	return m
}

// OwnerAssert records one repair decision. kind ∈ {vm, ct}; result ∈ {asserted,
// rekeyed, split_brain, inconclusive, error}.
func (m *RuntimeRepairMetrics) OwnerAssert(kind, result string) {
	m.ownerAssert.WithLabelValues(kind, result).Inc()
}
