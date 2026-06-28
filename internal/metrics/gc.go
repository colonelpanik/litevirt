package metrics

import "github.com/prometheus/client_golang/prometheus"

// GCMetrics counts rows reclaimed by the superseded-row GC, by table. Push-style
// (mirrors FailoverMetrics): registered against the default registry that
// promhttp serves on :7444.
type GCMetrics struct {
	rowsDeleted *prometheus.CounterVec
}

// NewGCMetrics registers the GC counters against the default registry.
func NewGCMetrics() *GCMetrics { return newGCMetrics(prometheus.DefaultRegisterer) }

// newGCMetrics is the test seam (a private registry avoids duplicate-registration
// panics across runs).
func newGCMetrics(reg prometheus.Registerer) *GCMetrics {
	m := &GCMetrics{
		rowsDeleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_gc_rows_deleted_total",
			Help: "Rows hard-deleted by the superseded-row garbage collector, by table.",
		}, []string{"table"}),
	}
	reg.MustRegister(m.rowsDeleted)
	return m
}

// RowsDeleted records n rows reclaimed from table. Nil-safe; ignores n<=0.
func (m *GCMetrics) RowsDeleted(table string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.rowsDeleted.WithLabelValues(table).Add(float64(n))
}
