package metrics

import "github.com/prometheus/client_golang/prometheus"

// MigrationMetrics holds Prometheus histograms for migration observability.
type MigrationMetrics struct {
	Duration *prometheus.HistogramVec // labels: strategy, result
	Downtime *prometheus.HistogramVec // labels: strategy
	Transfer *prometheus.HistogramVec // labels: strategy
}

// NewMigrationMetrics creates and registers migration metrics.
func NewMigrationMetrics() *MigrationMetrics {
	m := &MigrationMetrics{
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "litevirt_migration_duration_seconds",
			Help:    "Total wall-clock time of VM migrations.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		}, []string{"strategy", "result"}),

		Downtime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "litevirt_migration_downtime_ms",
			Help:    "Guest-visible downtime during migration cutover.",
			Buckets: []float64{10, 50, 100, 500, 1000, 5000, 10000, 30000},
		}, []string{"strategy"}),

		Transfer: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "litevirt_migration_transfer_bytes",
			Help:    "Total bytes transferred during migration.",
			Buckets: []float64{1e6, 10e6, 100e6, 1e9, 10e9, 100e9},
		}, []string{"strategy"}),
	}

	prometheus.MustRegister(m.Duration, m.Downtime, m.Transfer)
	return m
}
